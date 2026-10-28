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
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
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
                peerMayHaveClosed { st.output.flushAndClose() } // DATA announces 10 bytes, FIN after 3
                assertEquals(Http3ErrorCode.FRAME_ERROR, withTimeout(5.seconds) { peerSawClose(c) })
            }
        }

    @Test fun greaseSentByDefault() =
        h3Test {
            for (grease in listOf(true, false)) {
                QuicPair.open().useScoped { q ->
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
            peerMayHaveClosed { block(raw) }
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

    /** RFC 9114 section 7.2.7: a MAX_PUSH_ID smaller than the previous one is a connection error H3_ID_ERROR. */
    @Test fun decreasingMaxPushIdIsIdError() =
        h3Test {
            assertEquals(
                Http3ErrorCode.ID_ERROR,
                violation {
                    it.openControl()
                    it.control.output.writeFully(
                        it.frame(FrameType.MAX_PUSH_ID, VarInt.encode(10)) + it.frame(FrameType.MAX_PUSH_ID, VarInt.encode(5)),
                    )
                    it.control.output.flush()
                }.first,
            )
        }

    /** RFC 9114 section 7.1: a MAX_PUSH_ID payload with bytes after its push ID, or ending inside it, is H3_FRAME_ERROR. */
    @Test fun malformedMaxPushIdIsFrameError() =
        h3Test {
            for (payload in listOf(byteArrayOf(5, 0), byteArrayOf(0x40), ByteArray(0))) {
                assertEquals(
                    Http3ErrorCode.FRAME_ERROR,
                    violation {
                        it.openControl()
                        it.control.output.writeFully(it.frame(FrameType.MAX_PUSH_ID, payload))
                        it.control.output.flush()
                    }.first,
                    payload.contentToString(),
                )
            }
        }

    /**
     * We never push, so a MAX_PUSH_ID does no useful work once the client has told us its limit: after the first valid
     * one, each further one spends a glitch token (RFC 9114 section 10.5: "Implementations SHOULD track the use of these
     * features and set limits on their use"). [count] increasing MAX_PUSH_IDs (0, 1, ...) with the bucket's clock frozen
     * at its 1000 tokens; returns whether the connection stayed open once the server had read the last one.
     */
    private suspend fun maxPushIdsLeaveTheConnectionOpen(count: Int): Boolean =
        QuicPair.open().use { q ->
            val (c, s) = q.connect()
            val server = Http3Connection.server(s)
            server.session.glitchClock = { 0L } // no refill: exactly 1000 tokens
            val raw = RawPeer(c)
            raw.openControl()
            val frames = (0 until count).map { raw.frame(FrameType.MAX_PUSH_ID, VarInt.encode(it.toLong())) }.reduce { a, b -> a + b }
            peerMayHaveClosed {
                raw.control.output.writeFully(frames)
                raw.control.output.flush()
            }
            withTimeout(5.seconds) {
                while (!server.closed.isCompleted &&
                    withContext(server.session.dispatcher) { server.session.peerMaxPushId } < count - 1L
                ) {
                    delay(5)
                }
            }
            if (!server.closed.isCompleted) return@use true
            assertEquals(Http3ErrorCode.EXCESSIVE_LOAD, peerSawClose(c))
            false
        }

    /** The first MAX_PUSH_ID is free and each later one spends one token: 1 + 1000 empty the bucket but fit it. */
    @Test fun firstMaxPushIdIsFreeAndLaterOnesSpendGlitchTokens() =
        h3Test {
            assertTrue(maxPushIdsLeaveTheConnectionOpen(1001), "1 free + 1000 tokens")
        }

    /** A flood of increasing MAX_PUSH_IDs, each valid on its own, closes the connection with H3_EXCESSIVE_LOAD. */
    @Test fun negative_maxPushIdFloodIsExcessiveLoad() =
        h3Test {
            assertFalse(maxPushIdsLeaveTheConnectionOpen(1002), "1 free + 1001 tokens")
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
                peerMayHaveClosed { b.output.flush() }
                assertEquals(Http3ErrorCode.STREAM_CREATION_ERROR, peerSawClose(s))
            }
        }
}
