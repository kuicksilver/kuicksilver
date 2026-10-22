// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.copyTo
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.WebTransportException
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.http3.acceptWebTransport
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.useScoped
import io.kuicksilver.http3.webTransport
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.DatagramSendResult
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.time.Duration.Companion.seconds

/** A client and a server session over [p]: the server accepts the first WebTransport request. */
internal suspend fun CoroutineScope.sessions(p: H3Pair): Pair<WebTransportSession, WebTransportSession> {
    val server = CompletableDeferred<WebTransportSession>()
    launch { server.complete(p.server.acceptRequest().acceptWebTransport()) }
    val client = p.client.webTransport(wtReq())
    return client to withTimeout(5.seconds) { server.await() }
}

/** The [T] in the cause chain of what [block] throws (ktor-io may wrap the cause a channel was closed with). */
internal suspend inline fun <reified T : Throwable> causeOf(crossinline block: suspend () -> Unit): T {
    val e = assertFailsWith<Throwable> { block() }
    return generateSequence(e) { it.cause }.filterIsInstance<T>().firstOrNull()
        ?: throw AssertionError("no ${T::class.simpleName} in $e", e)
}

class WebTransportStreamsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun bidiEchoBothDirections() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val (client, server) = sessions(p)
                // each side echoes what the other opens
                val echoes =
                    listOf(server, client).map { s ->
                        launch {
                            val st = s.acceptBidi()
                            st.input.copyTo(st.output)
                            st.output.flushAndClose()
                        }
                    }
                for ((opener, payload) in listOf(client to ByteArray(200_000) { it.toByte() }, server to "pong".encodeToByteArray())) {
                    val st = opener.openBidi()
                    val got = async { st.input.readAllBytes() }
                    st.output.writeFully(payload)
                    st.output.flushAndClose()
                    assertContentEquals(payload, withTimeout(5.seconds) { got.await() })
                }
                echoes.forEach { it.join() }
            }
        }

    @Test fun uniFromServer() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val (client, server) = sessions(p)
                val out = server.openUni()
                out.output.writeFully("hello".encodeToByteArray())
                out.output.flushAndClose()
                val st = withTimeout(5.seconds) { client.acceptUni() }
                assertEquals(out.streamId, st.streamId)
                assertEquals("hello", st.input.readAllBytes().decodeToString())
            }
        }

    @Test fun datagramEcho() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val (client, server) = sessions(p)
                launch { server.sendDatagram(server.receiveDatagram() + byteArrayOf(9)) }
                assertEquals(DatagramSendResult.Sent, client.trySendDatagram(byteArrayOf(1, 2)))
                assertContentEquals(byteArrayOf(1, 2, 9), withTimeout(5.seconds) { client.receiveDatagram() })
            }
        }

    /** The limit reported is the payload's, the quarter stream ID of the session already taken off (section 4.5). */
    @Test fun datagramTooLargeReportsPayloadMax() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val (client, _) = sessions(p)
                val quicMax = assertIs<DatagramSendResult.TooLarge>(p.client.quic.trySendDatagram(ByteArray(100_000))).max
                assertEquals(quicMax - 1, assertIs<DatagramSendResult.TooLarge>(client.trySendDatagram(ByteArray(100_000))).max)
            }
        }

    /** Section 4.4: application codes travel mapped into the HTTP/3 space and come back as they were. */
    @Test fun streamResetCodeMapped() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val (client, server) = sessions(p)
                val st = client.openBidi()
                st.output.writeFully("x".encodeToByteArray())
                st.output.flush()
                val peer = withTimeout(5.seconds) { server.acceptBidi() }
                st.reset(7)
                val e = causeOf<WebTransportException.StreamReset> { withTimeout(5.seconds) { peer.input.readAllBytes() } }
                assertEquals(7L, e.code)
                // STOP_SENDING with a code reaches the writer as that code
                val st2 = client.openBidi()
                st2.output.writeFully("y".encodeToByteArray())
                st2.output.flush()
                withTimeout(5.seconds) { server.acceptBidi() }.stopSending(9)
                val stopped =
                    causeOf<WebTransportException.StreamStopped> {
                        withTimeout(5.seconds) {
                            while (true) {
                                st2.output.writeFully(ByteArray(1024))
                                st2.output.flush()
                            }
                        }
                    }
                assertEquals(9L, stopped.code)
            }
        }

    @Test fun negative_codesAbove32BitsRefused() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val (client, _) = sessions(p)
                val st = client.openBidi()
                assertFailsWith<IllegalArgumentException> { st.reset(0x1_0000_0000L) }
                assertFailsWith<IllegalArgumentException> { client.close(0x1_0000_0000L) }
            }
        }
}
