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
import io.kuicksilver.http3.frame.FrameHeaders
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.message.GlitchLimiter
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
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
            QuicPair.open().useScoped { q ->
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
            QuicPair.open().useScoped { q ->
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
            H3Pair.open().useScoped { p ->
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
                peerMayHaveClosed { raw.control.output.flush() }
                assertEquals(Http3ErrorCode.ID_ERROR, peerSawClose(s))
                assertIs<Http3Exception.Protocol>(client.closed.await())
            }
        }

    @Test fun rejectedResetIsRetrySafe() =
        h3Test {
            QuicPair.open().useScoped { q ->
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

    /**
     * The GOAWAY state (phase, sent id, requests in flight) belongs to the session dispatcher: a goAway() from another thread
     * (the Ktor server stops on Dispatchers.IO) runs there, so a request racing it cannot be processed above the announced id.
     */
    @Test fun goAwayRunsOnTheSessionDispatcher() =
        h3Test {
            H3Pair.open().use { p ->
                var seen: kotlin.coroutines.CoroutineContext? = null
                p.server.session.goAwayContextForTest = { seen = it }
                kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) { p.server.goAway() }
                val interceptor = seen!![kotlin.coroutines.ContinuationInterceptor]
                assertTrue(interceptor === p.server.session.dispatcher, "goAway ran on $interceptor")
            }
        }

    /**
     * The server's GOAWAY idle close must not cut a response the client is still receiving (RFC 9114 section 5.2): a
     * response larger than the flow-control windows is handed to QUIC long before the client has it. The client reads
     * late; the whole body still arrives, and then the client, idle after GOAWAY, closes the connection itself.
     */
    @Test fun aResponseStillBeingReceivedSurvivesTheGoAwayIdleClose() =
        h3Test {
            H3Pair.open().use { p ->
                val size = 4 * 1024 * 1024
                launch {
                    val r = p.server.acceptRequest()
                    val w = r.respond(200)
                    w.output.writeFully(ByteArray(size) { it.toByte() })
                    w.finish()
                }
                val resp = p.client.request(get())
                launch { p.server.goAway() }
                // the client does not read yet: the old server closed ~200 ms after handing the last bytes to QUIC
                withTimeoutOrNull(1.seconds) { p.server.closed.await() }
                val body = withTimeout(30.seconds) { resp.body.readAllBytes() }
                assertEquals(size, body.size, "the whole response arrived")
                // idle after GOAWAY: the client closes the connection itself, with H3_NO_ERROR
                val e = withTimeout(10.seconds) { p.client.closed.await() } as Http3Exception.Protocol
                assertEquals(Http3ErrorCode.NO_ERROR, e.h3Code)
            }
        }

    /** An idle client that receives GOAWAY closes the connection itself with H3_NO_ERROR (RFC 9114 section 5.2). */
    @Test fun anIdleClientClosesAfterGoAway() =
        h3Test {
            H3Pair.open().use { p ->
                p.server.goAway()
                val e = withTimeout(5.seconds) { p.client.closed.await() }
                assertEquals(Http3ErrorCode.NO_ERROR, assertIs<Http3Exception.Protocol>(e).h3Code)
                assertEquals(Initiator.Local, e.initiator)
                val s = withTimeout(5.seconds) { p.server.closed.await() } as Http3Exception.Protocol
                assertEquals(Http3ErrorCode.NO_ERROR, s.h3Code)
                assertEquals(Initiator.Peer, s.initiator)
            }
        }

    /**
     * A client that never closes after GOAWAY (a raw QUIC peer here): the server keeps the connection while its response is
     * unacknowledged, however long that takes, and closes it itself with H3_NO_ERROR only [goAwayCloseFallback] after the
     * response stream finished. The residual risk is documented: such a client must read an acknowledged response within the
     * fallback (3 s by default).
     */
    @Test fun aClientThatNeverClosesIsClosedOnlyAfterItsResponseFinished() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                server.session.goAwayCloseFallback = 300.milliseconds
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, GET))
                st.output.flushAndClose()
                val size = 4 * 1024 * 1024
                launch {
                    val w = server.acceptRequest().respond(200)
                    w.output.writeFully(ByteArray(size))
                    w.finish()
                }
                withTimeout(5.seconds) { while (server.session.maxRequestId < st.id) yield() }
                launch { server.goAway() }
                // unread for well past the fallback: flow control holds the response back, the stream is not finished
                assertEquals(null, withTimeoutOrNull(1500.milliseconds) { server.closed.await() }, "closed with the response unread")
                val got = withTimeout(30.seconds) { st.input.readAllBytes() }
                assertTrue(got.size > size, "the whole response (frames included) arrived: ${got.size}")
                // finished now; the raw client never closes, so the server does, after the fallback, with H3_NO_ERROR
                val e = withTimeout(10.seconds) { c.closed.await() } as QuicException.ConnectionLost.ApplicationClosed
                assertEquals(Http3ErrorCode.NO_ERROR, e.code)
                assertEquals(Initiator.Peer, e.initiator)
            }
        }

    /** A request below the GOAWAY id whose HEADERS are still arriving counts as in flight: the idle close waits for it (RFC 9114 section 5.2). */
    @Test fun unreadRequestHeadersKeepConnectionOpenAfterGoAway() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                val frame = raw.headers(st.id, GET)
                val half = frame.size / 2
                st.output.writeFully(frame, 0, half)
                st.output.flush()
                withTimeout(5.seconds) { while (server.session.maxRequestId < st.id) yield() }
                server.goAway()
                assertFalse(server.closed.isCompleted, "the half-received request keeps the connection open")
                st.output.writeFully(frame, half, frame.size)
                st.output.flushAndClose()
                server.acceptRequest().respond(200).finish()
                val resp = withTimeout(5.seconds) { st.input.readAllBytes() }
                val h = FrameHeaders.parse(resp, 0, resp.size)!!
                assertEquals(FrameType.HEADERS, h.type)
                val fields =
                    io.kuicksilver.http3.qpack.QpackDecoder(0, 0, 65_536).decode(
                        st.id,
                        resp.copyOfRange(h.headerSize, h.headerSize + h.length.toInt()),
                    )
                assertEquals(":status" to "200", (fields as io.kuicksilver.http3.qpack.DecodeResult.Decoded).fields.first())
                withTimeout(5.seconds) { server.closed.await() }
            }
        }

    /** HEADERS that never complete after GOAWAY do not hold the connection forever: the stream is rejected after a deadline. */
    @Test fun incompleteRequestHeadersRejectedAfterGoAwayDeadline() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                server.session.headerDeadlineAfterGoAway = 300.milliseconds
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                val frame = raw.headers(st.id, GET)
                st.output.writeFully(frame, 0, frame.size / 2)
                st.output.flush()
                withTimeout(5.seconds) { while (server.session.maxRequestId < st.id) yield() }
                server.goAway()
                withTimeout(5.seconds) { server.closed.await() }
                val e = runCatching { st.input.readAllBytes() }.exceptionOrNull()
                val reset = generateSequence(e) { it.cause }.filterIsInstance<QuicException.StreamError.Reset>().firstOrNull()
                if (reset != null) assertEquals(Http3ErrorCode.REQUEST_REJECTED, reset.code)
            }
        }

    @Test fun inFlightRequestsCompleteBeforeIdleClose() =
        h3Test {
            H3Pair.open().useScoped { p ->
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
                peerMayHaveClosed { raw.control.output.flush() }
                assertEquals(Http3ErrorCode.EXCESSIVE_LOAD, peerSawClose(c))
            }
        }
}
