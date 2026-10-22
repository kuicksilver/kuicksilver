// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.WebTransportException
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.http3.acceptWebTransport
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.runtime.RawPeer
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.runtime.peerMayHaveClosed
import io.kuicksilver.http3.useScoped
import io.kuicksilver.http3.webTransport
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicStream
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

private fun capsule(
    type: Long,
    value: ByteArray,
) = VarInt.encode(type) + VarInt.encode(value.size.toLong()) + value

private fun closeValue(
    code: Long,
    reason: ByteArray,
) = byteArrayOf((code ushr 24).toByte(), (code ushr 16).toByte(), (code ushr 8).toByte(), code.toByte()) + reason

/** A raw client with an accepted session: the CONNECT stream (its 200 read) and the server's session. */
private class RawSession(
    val raw: RawPeer,
    val connect: QuicStream,
    val server: WebTransportSession,
    val serverConnection: Http3Connection,
) {
    /** Capsules from the raw client, in DATA frames on the CONNECT stream. */
    suspend fun send(vararg capsules: ByteArray) {
        peerMayHaveClosed {
            connect.output.writeFully(raw.data(capsules.reduce { a, b -> a + b }))
            connect.output.flush()
        }
    }
}

private suspend fun CoroutineScope.rawSession(q: QuicPair): RawSession {
    val (c, s) = q.connect()
    val server = Http3Connection.server(s, wtOn)
    val raw = RawPeer(c)
    raw.openControl(wtClientSettings)
    val accepted = CompletableDeferred<WebTransportSession>()
    launch { accepted.complete(server.acceptRequest().acceptWebTransport()) }
    val st = c.openBidi()
    st.output.writeFully(raw.wtConnect(st))
    st.output.flush()
    assertEquals("200", readHeaders(st)[":status"])
    return RawSession(raw, st, withTimeout(5.seconds) { accepted.await() }, server)
}

class WebTransportCloseTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Section 6: WT_CLOSE_SESSION with a code and a reason, then FIN; both sides see the same close. */
    @Test fun closeSendsCapsuleThenFin() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val (client, server) = sessions(p)
                client.close(42, "bye")
                val seen = withTimeout(5.seconds) { server.closed.await() }
                assertEquals(42L, seen.code)
                assertEquals("bye", seen.reason)
                assertNull(seen.cause)
                assertEquals(42L, client.closed.await().code)
            }
        }

    /** Both directions of the CONNECT end, so the connection's one session slot is free for the next one (section 5.1). */
    @Test fun closeFreesTheSlot() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                repeat(3) { round ->
                    val (client, server) = sessions(p)
                    if (round % 2 == 0) client.close(1, "client") else server.close(2, "server")
                    withTimeout(5.seconds) {
                        client.closed.await()
                        server.closed.await()
                    }
                    withTimeout(5.seconds) {
                        p.client.session.wtIdle
                            .first { it }
                    } // the client's slot
                    withTimeout(5.seconds) {
                        p.server.session.wtIdle
                            .first { it }
                    } // the server's slot
                }
            }
        }

    @Test fun finWithoutCapsuleIsCodeZero() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val r = rawSession(q)
                r.connect.output.flushAndClose()
                val seen = withTimeout(5.seconds) { r.server.closed.await() }
                assertEquals(0L, seen.code)
                assertEquals("", seen.reason)
                assertNull(seen.cause)
                r.connect.input.readAllBytes() // the server ends its side too: a clean FIN, no capsule needed
            }
        }

    /** Section 6: the session's streams are reset and stopped with WT_SESSION_GONE; nothing new opens. */
    @Test fun closeResetsAllStreamsSessionGone() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val r = rawSession(q)
                val wtStream = r.raw.quic.wtBidi(r.connect.id, "hi".encodeToByteArray(), fin = false)
                val accepted = withTimeout(5.seconds) { r.server.acceptBidi() }
                r.server.close(5, "done")
                assertEquals(Http3ErrorCode.WT_SESSION_GONE, resetCode(wtStream))
                assertIs<WebTransportException.SessionClosed>(runCatching { r.server.openUni() }.exceptionOrNull())
                assertIs<WebTransportException.SessionClosed>(runCatching { r.server.acceptBidi() }.exceptionOrNull())
                assertIs<WebTransportException.SessionClosed>(runCatching { r.server.receiveDatagram() }.exceptionOrNull())
                assertTrue(accepted.streamId == wtStream.id)
            }
        }

    @Test fun negative_closeReasonOver1024IsMessageError() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val r = rawSession(q)
                r.send(capsule(0x2843, closeValue(1, ByteArray(1025) { 'a'.code.toByte() })))
                assertEquals(Http3ErrorCode.MESSAGE_ERROR, resetCode(r.connect))
                assertIs<io.kuicksilver.http3.Http3Exception.MessageError>(withTimeout(5.seconds) { r.server.closed.await() }.cause)
            }
        }

    @Test fun negative_closeReasonInvalidUtf8IsMessageError() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val r = rawSession(q)
                r.send(capsule(0x2843, closeValue(1, byteArrayOf(0xc3.toByte(), 0x28))))
                assertEquals(Http3ErrorCode.MESSAGE_ERROR, resetCode(r.connect))
            }
        }

    @Test fun negative_dataAfterCloseCapsuleIsMessageError() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val r = rawSession(q)
                r.send(capsule(0x2843, closeValue(1, "x".encodeToByteArray())), capsule(0x2a, byteArrayOf(1)))
                assertEquals(Http3ErrorCode.MESSAGE_ERROR, resetCode(r.connect))
            }
        }

    @Test fun negative_drainWithValueIsMessageError() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val r = rawSession(q)
                r.send(capsule(0x78ae, byteArrayOf(1)))
                assertEquals(Http3ErrorCode.MESSAGE_ERROR, resetCode(r.connect))
            }
        }

    /** Section 4.7: the peer's WT_DRAIN_SESSION and an HTTP/3 GOAWAY both ask the application to wind the session down. */
    @Test fun drainCapsuleAndGoAwaySetDrainRequested() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val (client, server) = sessions(p)
                assertFalse(server.drainRequested.value)
                client.drain()
                withTimeout(5.seconds) { server.drainRequested.first { it } }
                assertFalse(client.drainRequested.value)
                launch { p.server.goAway() }
                withTimeout(5.seconds) { client.drainRequested.first { it } }
            }
        }

    /** Section 5.1: without negotiated flow control its capsules are ignored. */
    @Test fun flowControlCapsulesIgnoredWhenDisabled() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val r = rawSession(q)
                r.send(capsule(0x190B4D3D, VarInt.encode(1000)), capsule(0x190B4D3F, VarInt.encode(10)))
                r.send(capsule(0x2843, closeValue(5, "x".encodeToByteArray())))
                val seen = withTimeout(5.seconds) { r.server.closed.await() }
                assertEquals(5L to "x", seen.code to seen.reason)
            }
        }

    @Test fun closeInfoOnConnectionLoss() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val (client, _) = sessions(p)
                p.server.close()
                val seen = withTimeout(5.seconds) { client.closed.await() }
                assertTrue(seen.cause != null)
            }
        }
}
