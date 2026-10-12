// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.FrameHeaders
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

internal fun h3Test(block: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(30.seconds) { block() } }

/** The raw server-side QUIC connection's close as seen by the peer that broke the rules. */
internal suspend fun peerSawClose(q: io.kuicksilver.quic.QuicConnection): Long =
    assertIs<QuicException.ConnectionLost.ApplicationClosed>(q.closed.await()).code

class ConnectionTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun settingsSentImmediately() =
        h3Test {
            H3Pair.open(clientSettings = http3Settings { enableQpackDynamicTable() }).use { p ->
                // no request was made: SETTINGS left at once, in both directions
                val seen =
                    p.server.peerSettings
                        .filterNotNull()
                        .first()
                assertEquals(4096, seen.qpackMaxTableCapacity)
                assertEquals(16, seen.qpackBlockedStreams)
                assertNotNull(
                    p.client.peerSettings
                        .filterNotNull()
                        .first(),
                )
                assertEquals(true, seen.h3Datagram)
            }
        }

    /** A stream that ends cleanly inside a frame is a connection error H3_FRAME_ERROR (RFC 9114 section 7.1). */
    @Test fun truncatedFrameAtFinIsFrameError() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                val hdr = ByteArray(16)
                val n = FrameHeaders.write(FrameType.DATA, 10, hdr, 0)
                st.output.writeFully(raw.headers(st.id, GET) + hdr.copyOf(n) + ByteArray(3))
                st.output.flushAndClose() // DATA announces 10 bytes, FIN after 3
                assertEquals(Http3ErrorCode.FRAME_ERROR, withTimeout(5.seconds) { peerSawClose(c) })
            }
        }

    @Test fun greaseSentByDefault() =
        h3Test {
            for (grease in listOf(true, false)) {
                QuicPair.open().use { q ->
                    val (c, s) = q.connect()
                    val server = async { Http3Connection.server(s, http3Settings { this.grease = grease }) }
                    val types = ArrayList<Long>()
                    withTimeout(3.seconds) { repeat(if (grease) 4 else 3) { types += c.acceptStream().readVarInt() } }
                    assertEquals(grease, types.any { FrameType.isGrease(it) }, "types $types")
                    assertTrue(types.containsAll(listOf(StreamType.CONTROL, StreamType.QPACK_ENCODER, StreamType.QPACK_DECODER)))
                    server.await().close()
                }
            }
        }

    @Test fun greaseSettingSeenByPeer() =
        h3Test {
            H3Pair.open().use { p ->
                assertTrue(
                    p.server.peerSettings
                        .filterNotNull()
                        .first()
                        .unknown.keys
                        .any { FrameType.isGrease(it) },
                )
            }
        }

    private suspend fun violation(block: suspend (RawPeer) -> Unit): Pair<Long, Throwable> =
        QuicPair.open().use { q ->
            val (c, s) = q.connect()
            val server = Http3Connection.server(s)
            val raw = RawPeer(c)
            block(raw)
            val code = peerSawClose(c)
            val local = server.closed.await()
            code to local
        }

    @Test fun missingSettingsFirst() =
        h3Test {
            val (code, local) =
                violation {
                    it.openControl(sendSettings = false)
                    it.control.output.writeFully(it.frame(FrameType.GOAWAY, byteArrayOf(0)))
                    it.control.output.flush()
                }
            assertEquals(Http3ErrorCode.MISSING_SETTINGS, code)
            assertEquals(Http3ErrorCode.MISSING_SETTINGS, assertIs<Http3Exception.Protocol>(local).h3Code)
            assertEquals(Initiator.Local, (local as Http3Exception.Protocol).initiator)
        }

    @Test fun secondControlStreamIsCreationError() =
        h3Test {
            assertEquals(
                Http3ErrorCode.STREAM_CREATION_ERROR,
                violation {
                    it.openControl()
                    it.uni(StreamType.CONTROL)
                }.first,
            )
        }

    @Test fun closingControlStreamIsCriticalError() =
        h3Test {
            assertEquals(Http3ErrorCode.CLOSED_CRITICAL_STREAM, violation { it.openControl().output.flushAndClose() }.first)
        }

    @Test fun closingQpackStreamIsCriticalError() =
        h3Test {
            assertEquals(
                Http3ErrorCode.CLOSED_CRITICAL_STREAM,
                violation {
                    it.openControl()
                    it.uni(StreamType.QPACK_ENCODER, fin = true)
                }.first,
            )
        }

    @Test fun unknownUniStreamStoppedNotFatal() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                // the stream is stopped with H3_STREAM_CREATION_ERROR: writing more fails with Stopped. The stop can arrive
                // before the first flush returns (seen on a Linux runner), so opening the stream is inside the same try.
                val stopped =
                    withTimeout(5.seconds) {
                        try {
                            val u = raw.uni(0x54, ByteArray(100))
                            while (true) {
                                u.output.writeFully(ByteArray(1000))
                                u.output.flush()
                                delay(20)
                            }
                        } catch (
                            e: Throwable,
                        ) {
                            return@withTimeout e
                        }
                        @Suppress("UNREACHABLE_CODE")
                        null
                    }
                assertEquals(
                    Http3ErrorCode.STREAM_CREATION_ERROR,
                    assertIs<QuicException.StreamError.Stopped>(
                        generateSequence(stopped) {
                            it.cause
                        }.first { it is QuicException.StreamError.Stopped },
                    ).code,
                )
                assertTrue(!server.closed.isCompleted)
                server.close()
            }
        }

    @Test fun pushStreamCodesByRole() =
        h3Test {
            // a client opening a push stream to a server: H3_STREAM_CREATION_ERROR
            assertEquals(
                Http3ErrorCode.STREAM_CREATION_ERROR,
                violation {
                    it.openControl()
                    it.uni(StreamType.PUSH, byteArrayOf(0))
                }.first,
            )
            // a server opening a push stream to a client that never sent MAX_PUSH_ID: H3_ID_ERROR
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c)
                val raw = RawPeer(s)
                raw.openControl()
                raw.uni(StreamType.PUSH, byteArrayOf(0))
                assertEquals(Http3ErrorCode.ID_ERROR, peerSawClose(s))
                assertIs<Http3Exception.Protocol>(client.closed.await())
            }
        }

    @Test fun serverInitiatedBidiIsCreationError() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                Http3Connection.client(c)
                val raw = RawPeer(s)
                raw.openControl()
                val b = s.openBidi()
                b.output.writeFully(raw.data(byteArrayOf(1)))
                b.output.flush()
                assertEquals(Http3ErrorCode.STREAM_CREATION_ERROR, peerSawClose(s))
            }
        }
}
