// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.ControlFrames
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.message.GlitchLimiter
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicStream
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** Reads frames from the peer's control stream (after its type byte). */
internal suspend fun QuicStream.readControlFrame(): Pair<Long, ByteArray> {
    val t = readVarInt()
    val n = readVarInt()
    return t to
        input.readByteArray(n.toInt())
}

class GoAwayTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun twoPhaseIds() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val ctrl =
                    async {
                        while (true) {
                            val st = c.acceptStream()
                            if (st.readVarInt() ==
                                StreamType.CONTROL
                            ) {
                                return@async st
                            }
                        }
                        @Suppress("UNREACHABLE_CODE")
                        null!!
                    }
                val req = c.openBidi()
                req.output.writeFully(raw.headers(req.id, GET))
                req.output.flushAndClose()
                server.acceptRequest().respond(200).finish()
                launch { server.goAway() }
                val control = ctrl.await()
                val goAways = ArrayList<Long>()
                withTimeout(5.seconds) {
                    while (goAways.size <
                        2
                    ) {
                        val (t, p) = control.readControlFrame()
                        if (t == FrameType.GOAWAY) goAways += ControlFrames.parseGoAway(p)
                    }
                }
                assertEquals(listOf((1L shl 62) - 4, 4L), goAways)
            }
        }

    /** A hand-driven server answering 200 on the streams it is told to. */
    private suspend fun respond200(
        raw: RawPeer,
        st: QuicStream,
    ) {
        st.input.readAllBytes()
        st.output.writeFully(
            raw.headers(
                st.id,
                listOf(":status" to "200"),
            ),
        )
        st.output.flushAndClose()
    }

    @Test fun goAwayFailsOnlyHigherStreams() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c)
                val raw = RawPeer(s)
                raw.openControl()
                client.peerSettings.filterNotNull().first()
                val results = (0 until 4).map { async { runCatching { client.request(get("/$it")).status } } }
                val streams = (0 until 4).map { s.acceptBidi() }
                raw.control.output.writeFully(raw.frame(FrameType.GOAWAY, ControlFrames.goAwayPayload(8)))
                raw.control.output.flush()
                client.goAwayReceived.filterNotNull().first()
                for (st in streams.filter { it.id < 8 }) launch { respond200(raw, st) }
                val r = results.awaitAll()
                val byPath = r.map { it.getOrNull() ?: it.exceptionOrNull() }
                assertEquals(2, byPath.count { it == 200 }, "$byPath")
                assertEquals(2, byPath.count { it is Http3Exception.RequestNotProcessed && it.retrySafe }, "$byPath")
            }
        }

    @Test fun requestAfterGoAwayNotProcessed() =
        h3Test {
            H3Pair.open().use { p ->
                launch { runCatching { p.server.goAway() } }
                p.client.goAwayReceived
                    .filterNotNull()
                    .first()
                assertFailsWith<Http3Exception.RequestNotProcessed> { p.client.request(get()) }
            }
        }

    @Test fun increasingGoAwayIdIsIdError() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c)
                val raw = RawPeer(s)
                raw.openControl()
                raw.control.output.writeFully(
                    raw.frame(FrameType.GOAWAY, ControlFrames.goAwayPayload(4)) +
                        raw.frame(FrameType.GOAWAY, ControlFrames.goAwayPayload(8)),
                )
                runCatching { raw.control.output.flush() } // the client may already have closed the connection
                assertEquals(Http3ErrorCode.ID_ERROR, peerSawClose(s))
                assertIs<Http3Exception.Protocol>(client.closed.await())
            }
        }

    @Test fun rejectedResetIsRetrySafe() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c)
                RawPeer(s).openControl()
                val r = async { runCatching { client.request(get()) } }
                val st = s.acceptBidi()
                st.reset(Http3ErrorCode.REQUEST_REJECTED)
                st.stopSending(Http3ErrorCode.REQUEST_REJECTED)
                assertTrue(assertIs<Http3Exception.RequestNotProcessed>(r.await().exceptionOrNull()).retrySafe)
            }
        }

    @Test fun closesWhenIdleAfterGoAway() =
        h3Test {
            H3Pair.open().use { p ->
                p.server.goAway()
                val e = withTimeout(5.seconds) { p.client.closed.await() }
                assertEquals(Http3ErrorCode.NO_ERROR, assertIs<Http3Exception.Protocol>(e).h3Code)
                assertEquals(Initiator.Peer, (e as Http3Exception.Protocol).initiator)
            }
        }

    @Test fun inFlightRequestsCompleteBeforeIdleClose() =
        h3Test {
            H3Pair.open().use { p ->
                val serving =
                    launch {
                        val r = p.server.acceptRequest()
                        delay(300)
                        val w = r.respond(200)
                        w.output.writeFully("late".encodeToByteArray())
                        w.finish()
                    }
                val resp = async { p.client.request(get()) }
                delay(100)
                launch { p.server.goAway() }
                assertEquals(
                    "late",
                    resp
                        .await()
                        .body
                        .readAllBytes()
                        .decodeToString(),
                )
                serving.join()
                withTimeout(5.seconds) { p.client.closed.await() }
            }
        }
}

class GlitchLimiterTest {
    @Test fun exhaustsAt1001() {
        val g = GlitchLimiter()
        repeat(1000) { assertTrue(g.spend(0)) }
        assertFalse(g.spend(0))
    }

    @Test fun refills33PerSecond() {
        val g = GlitchLimiter()
        repeat(1000) { g.spend(0) }
        repeat(33) { assertTrue(g.spend(1_000_000_000)) }
        assertFalse(g.spend(1_000_000_000))
        assertTrue(g.spend(2_000_000_000))
    }

    @Test fun unknownControlFramesFloodClosesExcessiveLoad() =
        h3Test {
            KslLoader.ensureLoaded()
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                raw.control.output.writeFully(
                    ByteArray(0).let {
                        var b = it
                        repeat(100) {
                            b +=
                                raw.frame(FrameType.grease(it.toLong()), ByteArray(0))
                        }
                        b
                    },
                )
                raw.control.output.flush()
                delay(300)
                assertFalse(server.closed.isCompleted)
                raw.control.output.writeFully(
                    ByteArray(0).let {
                        var b = it
                        repeat(1000) { b += raw.frame(0x21, ByteArray(0)) }
                        b
                    },
                )
                raw.control.output.flush()
                assertEquals(Http3ErrorCode.EXCESSIVE_LOAD, peerSawClose(c))
            }
        }
}
