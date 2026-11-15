// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.http3.runtime

import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.FrameHeaders
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.awaitSendStopped
import io.kuicksilver.quic.inputTakenForTest
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Field sections a peer never finishes, or sends too many of at once (RFC 9114 section 10.5: "memory commitments ...
 * strictly bounded"; RFC 9000 section 21.6, Slowloris), and frames that carry nothing (section 10.5: "Implementations
 * SHOULD track the use of these features and set limits on their use"). Invariants: every field section is read within
 * `maxHeaderBlockTime` (a request head from its stream's first byte) or its stream ends; the HEADERS bytes one connection
 * holds, taken from the transport or buffered, never exceed its [HeaderBudget]; nothing stays reserved once the streams
 * ended; GREASE and empty DATA frames beyond a few per stream spend glitch tokens.
 */
class HeaderLimitsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val fastDeadline = http3Settings { maxHeaderBlockTime = 300.milliseconds }

    /** The reset code a peer ended [st]'s receiving half with; fails when it ended any other way. */
    private suspend fun resetCode(st: QuicStream): Long {
        val e =
            runCatching {
                val b = ByteArray(4096)
                @Suppress("ControlFlowWithEmptyBody")
                while (st.input.readAvailable(b, 0, b.size) >= 0) {
                }
            }.exceptionOrNull()
        val r = generateSequence(e) { it.cause }.filterIsInstance<QuicException.StreamError.Reset>().firstOrNull()
        return r?.code ?: fail("stream ${st.id} did not end with a reset: $e")
    }

    /** A HEADERS frame header declaring [length] bytes. */
    private fun headersHeader(length: Long): ByteArray {
        val h = ByteArray(16)
        return h.copyOf(FrameHeaders.write(FrameType.HEADERS, length, h, 0))
    }

    private suspend fun assertNothingHeld(c: Http3Connection) = assertNoHeaderState(c.session)

    internal companion object {
        /** Nothing of the field-section limits stays with [s]: no reservation, waiter, buffered byte, pending head or timer. */
        suspend fun assertNoHeaderState(s: H3Session) {
            awaitCondition("the request-head deadlines to be disarmed") { s.headDeadlinesArmedForTest.load() == 0 }
            awaitCondition("the unidirectional-stream header deadlines to be disarmed") { s.uniDeadlinesArmed.load() == 0 }
            withContext(s.dispatcher) {
                assertEquals(0L, s.headerBudget.reserved, "bytes still reserved")
                assertEquals(0, s.headerBudget.waiting, "readers still waiting for the budget")
                assertEquals(0L, s.bufferedHeaderBytes, "HEADERS bytes still buffered")
                assertTrue(s.pendingHeaders.isEmpty(), "request heads still pending: ${s.pendingHeaders.keys}")
            }
        }
    }

    /**
     * Request heads that never complete: a HEADERS frame cut short, a frame header cut short, and GREASE before a HEADERS
     * that never comes. Each stream is rejected with H3_REQUEST_REJECTED (RFC 9114 section 4.1.1: nothing reached the
     * application) at `maxHeaderBlockTime`, nothing stays held, and the connection lives on and serves the next request.
     */
    @Test fun negative_requestHeadsThatNeverCompleteAreRejected() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, fastDeadline)
                val raw = RawPeer(c)
                raw.openControl()
                val starts =
                    listOf(
                        headersHeader(4000) + ByteArray(3) + byteArrayOf(0x51, 0x01),
                        byteArrayOf(FrameType.HEADERS.toByte()),
                        raw.frame(FrameType.grease(1), ByteArray(2)) + raw.frame(FrameType.grease(2), ByteArray(0)),
                    )
                val streams =
                    (0 until 30).map { i ->
                        c.openBidi().also {
                            it.output.writeFully(starts[i % starts.size])
                            it.output.flush()
                        }
                    }
                for (st in streams) {
                    assertEquals(
                        Http3ErrorCode.REQUEST_REJECTED,
                        withTimeout(5.seconds) { resetCode(st) },
                        "stream ${st.id}",
                    )
                }
                for (st in streams) assertEquals(Http3ErrorCode.REQUEST_REJECTED, withTimeout(5.seconds) { st.awaitSendStopped() })
                awaitCondition("the readers to end") { withContext(server.session.dispatcher) { server.session.pendingHeaders.isEmpty() } }
                assertEquals(30, withContext(server.session.dispatcher) { server.session.headDeadlinesPassedForTest })
                assertNothingHeld(server)
                assertFalse(server.closed.isCompleted, "a slow head is no connection error")
                launch {
                    val r = server.acceptRequest()
                    r.respond(204).finish()
                }
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, GET))
                st.output.flushAndClose()
                assertTrue(st.input.readAllBytes().isNotEmpty(), "the connection still serves requests")
            }
        }

    private val webTransportFast =
        http3Settings {
            maxHeaderBlockTime = 300.milliseconds
            enableConnectProtocol = true
            h3Datagram = true
            webTransport = true
        }

    /**
     * With WebTransport on, a server reads a request stream's first frame type before it knows it is a request: that read
     * is under the deadline too. Half a varint (the first byte of `WT_STREAM`'s two) is rejected with H3_REQUEST_REJECTED;
     * a WebTransport stream whose Session ID never completes, with WT_BUFFERED_STREAM_REJECTED (it reached no session).
     * Before, both held their stream slot and reader forever.
     */
    @Test fun negative_webTransportHeadsThatNeverCompleteAreRejected() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, webTransportFast)
                val raw = RawPeer(c)
                raw.openControl()
                val halfType = c.openBidi()
                halfType.output.writeFully(byteArrayOf(0x40))
                halfType.output.flush()
                val halfSessionId = c.openBidi()
                halfSessionId.output.writeFully(byteArrayOf(0x40, 0x41, 0x40)) // WT_STREAM, then one byte of a 2-byte ID
                halfSessionId.output.flush()
                assertEquals(Http3ErrorCode.REQUEST_REJECTED, withTimeout(5.seconds) { resetCode(halfType) })
                assertEquals(Http3ErrorCode.WT_BUFFERED_STREAM_REJECTED, withTimeout(5.seconds) { resetCode(halfSessionId) })
                assertNothingHeld(server)
                assertEquals(2, withContext(server.session.dispatcher) { server.session.headDeadlinesPassedForTest })
                assertFalse(server.closed.isCompleted)
            }
        }

    /** The peer's control and QPACK streams, so every later unidirectional stream is known not to be one of them. */
    private suspend fun RawPeer.openCriticalStreams() {
        openControl()
        uni(io.kuicksilver.http3.frame.StreamType.QPACK_ENCODER)
        uni(io.kuicksilver.http3.frame.StreamType.QPACK_DECODER)
    }

    /**
     * A unidirectional stream whose type never completes (half a varint) is stopped with H3_STREAM_CREATION_ERROR at
     * `maxHeaderBlockTime` (RFC 9114 section 6.2: an unknown type, "If reading is aborted, the recipient SHOULD use the
     * H3_STREAM_CREATION_ERROR error code"; "MUST NOT consider unknown stream types to be a connection error"). Before, it
     * held a reader and a stream slot for the connection's life.
     */
    @Test fun negative_unidirectionalStreamWithoutItsTypeIsStopped() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, fastDeadline)
                val raw = RawPeer(c)
                raw.openCriticalStreams()
                awaitCondition("the critical streams to be known") { server.session.criticalStreamsSeen.value == 3 }
                val u = c.openUni()
                u.output.writeFully(byteArrayOf(0x40))
                u.output.flush()
                assertEquals(Http3ErrorCode.STREAM_CREATION_ERROR, withTimeout(5.seconds) { u.awaitSendStopped() })
                assertNothingHeld(server)
                assertEquals(1, withContext(server.session.dispatcher) { server.session.uniDeadlinesPassedForTest })
                assertFalse(server.closed.isCompleted)
            }
        }

    /**
     * A stalled type could belong to one of the peer's critical streams (a type value may be sent longer than its one byte),
     * which must never be stopped this way (RFC 9114 section 6.2.1: closing it is a connection error). While the peer's
     * QPACK encoder stream is missing, a stream that sent `0x40` waits past the deadline; it turns out to be that stream
     * (`0x40 0x02`, a two-byte 2) and works. Once every critical stream is known, the next stalled stream is stopped.
     */
    @Test fun negative_aStalledTypeIsNeverStoppedWhileItMayBeACriticalStream() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, fastDeadline)
                val raw = RawPeer(c)
                raw.openControl()
                raw.uni(io.kuicksilver.http3.frame.StreamType.QPACK_DECODER)
                awaitCondition("two critical streams to be known") { server.session.criticalStreamsSeen.value == 2 }
                val encoder = c.openUni()
                encoder.output.writeFully(byteArrayOf(0x40))
                encoder.output.flush()
                delay(600) // a real wait: past maxHeaderBlockTime, which must not stop a stream that may be critical
                assertEquals(0, withContext(server.session.dispatcher) { server.session.uniDeadlinesPassedForTest })
                encoder.output.writeFully(byteArrayOf(0x02))
                encoder.output.flush()
                awaitCondition("the encoder stream to be known") { server.session.criticalStreamsSeen.value == 3 }
                val stalled = c.openUni()
                stalled.output.writeFully(byteArrayOf(0x40))
                stalled.output.flush()
                assertEquals(Http3ErrorCode.STREAM_CREATION_ERROR, withTimeout(5.seconds) { stalled.awaitSendStopped() })
                assertEquals(1, withContext(server.session.dispatcher) { server.session.uniDeadlinesPassedForTest })
                assertFalse(server.closed.isCompleted, "the late critical stream is a working QPACK encoder stream")
            }
        }

    /** A unidirectional WebTransport stream whose Session ID never completes is stopped with WT_BUFFERED_STREAM_REJECTED. */
    @Test fun negative_webTransportUnidirectionalStreamWithoutItsSessionIdIsStopped() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, webTransportFast)
                val raw = RawPeer(c)
                raw.openCriticalStreams()
                val u = c.openUni()
                u.output.writeFully(byteArrayOf(0x40, 0x54, 0x40)) // WT_UNI, then one byte of a two-byte Session ID
                u.output.flush()
                assertEquals(Http3ErrorCode.WT_BUFFERED_STREAM_REJECTED, withTimeout(5.seconds) { u.awaitSendStopped() })
                assertNothingHeld(server)
                assertFalse(server.closed.isCompleted)
            }
        }

    /**
     * A FIN is no abort: a whole request that waits in the budget's line behind 4 unfinished heads (its bytes all arrived,
     * FIN included) is served once the line moves, not dropped as if its stream had been reset.
     */
    @Test fun aFinishedHeadWaitingInLineIsServed() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val blockers = (0 until 4).map { c.openBidi() }
                for (b in blockers) {
                    b.output.writeFully(headersHeader(131_072) + ByteArray(10))
                    b.output.flush()
                }
                val budget = server.session.headerBudget
                awaitCondition(
                    "the budget to fill",
                ) { withContext(server.session.dispatcher) { budget.capacity - budget.reserved < 131_072 } }
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, GET)) // whole, with its FIN: only its reservation is missing
                st.output.flushAndClose()
                awaitCondition("the request to wait in line") { withContext(server.session.dispatcher) { budget.waiting == 1 } }
                val serverSide =
                    withContext(server.session.dispatcher) {
                        server.session.pendingHeaders
                            .getValue(st.id)
                            .first
                    }
                @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                withTimeout(5.seconds) { serverSide.receivedFinalSize!!.await() } // its FIN arrived
                blockers.forEach { it.reset(Http3ErrorCode.REQUEST_CANCELLED) }
                val r = withTimeout(5.seconds) { server.acceptRequest() }
                assertEquals("GET", r.method)
                r.respond(204).finish()
                assertTrue(st.input.readAllBytes().isNotEmpty())
                assertNothingHeld(server)
            }
        }

    /** Control: a WebTransport stream whose header arrives in time is never cut by the deadline later. */
    @Test fun aWebTransportStreamWithItsHeaderInTimeOutlivesTheDeadline() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, webTransportFast)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(byteArrayOf(0x40, 0x41, 0x00)) // WT_STREAM, session 0 (not established: it waits)
                st.output.flush()
                awaitCondition("the deadline to stand down") { server.session.headDeadlinesArmedForTest.load() == 0 }
                assertEquals(0, withContext(server.session.dispatcher) { server.session.headDeadlinesPassedForTest })
            }
        }

    /**
     * RFC 9114 section 4.1.1: "Servers MUST NOT use the H3_REQUEST_REJECTED error code for requests that were partially or
     * fully processed". A rejection takes the stream from the pending heads and cancels its reader before it aborts the
     * stream, so even an abort that suspended could not let a head completed meanwhile reach the application (the abort does
     * not suspend today: this pins the order).
     */
    @Test fun aRejectedHeadIsCancelledBeforeTheAbortRuns() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(headersHeader(100) + byteArrayOf(0))
                st.output.flush()
                val session = server.session
                awaitCondition("the head to be pending") { withContext(session.dispatcher) { session.pendingHeaders.isNotEmpty() } }
                withContext(session.dispatcher) {
                    val (serverStream, reader) = session.pendingHeaders.values.single()
                    launch(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) {
                        session.rejectUnfinishedHead(serverStream, reader, Http3ErrorCode.REQUEST_REJECTED)
                    }
                    assertTrue(reader.isCancelled, "the reader runs on while the stream is aborted")
                    assertTrue(session.pendingHeaders.isEmpty())
                }
                assertEquals(Http3ErrorCode.REQUEST_REJECTED, withTimeout(5.seconds) { resetCode(st) })
            }
        }

    /**
     * Trailers wait for the budget like heads: with the default static-only QPACK too, a stream reads ahead by a frame header
     * only before its trailers are granted. 12 requests whose trailers (60 000 bytes of a 128 KiB frame each, all within the
     * connection's initial window) arrived before their readers ran: the server takes the 4 granted trailers and, of the
     * others, their frame headers and QPACK prefixes only, never the up to 64 KiB a reader pulls ahead without a limit
     * (before, every stream read on unlimited once its head was read).
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun negative_trailersWaitingForTheBudgetStayInTheWindow() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val session = server.session
                val gate = CompletableDeferred<Unit>()
                session.beforeRequestHeadersForTest = { gate.await() } // the readers wait until the bytes are there
                val raw = RawPeer(c)
                raw.openControl()
                val n = 12
                val bodies =
                    launch {
                        repeat(n) {
                            val r = server.acceptRequest()
                            launch { runCatching { r.body.readAllBytes() } }
                        }
                    }
                val streams = (0 until n).map { c.openBidi() }
                for (st in streams) {
                    st.output.writeFully(raw.headers(st.id, POST) + raw.data(byteArrayOf(1)) + headersHeader(131_072))
                    st.output.flush()
                }
                val writers =
                    launch {
                        for (st in streams) {
                            launch {
                                st.output.writeFully(ByteArray(60_000))
                                st.output.flush()
                            }
                        }
                    }
                awaitCondition("every stream to wait at the hook") { withContext(session.dispatcher) { session.pendingHeaders.size == n } }
                val serverStreams = withContext(session.dispatcher) { session.pendingHeaders.values.map { it.first } }
                awaitCondition("most of the connection window to arrive", 15.seconds) {
                    serverStreams.sumOf { it.receivedOffset!!.value } >= n * 60_000L
                }
                gate.complete(Unit)
                val budget = session.headerBudget
                awaitCondition("every trailer either granted or waiting", 15.seconds) {
                    withContext(session.dispatcher) { budget.waiting == n - 4 }
                }
                val taken = withContext(session.dispatcher) { serverStreams.sumOf { it.inputTakenForTest } }
                assertTrue(taken <= budget.capacity + n * 256L, "the server took $taken bytes for 12 heads and unfinished trailers")
                writers.cancel()
                bodies.cancel()
            }
        }

    /**
     * Control: a head that arrives whole, after its stream was opened earlier than the deadline, is served; the deadline
     * is the head's, never the request's (a body may take longer).
     */
    @Test fun aHeadInTimeWithASlowBodyIsServed() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, fastDeadline)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, POST))
                st.output.flush()
                val r = withTimeout(5.seconds) { server.acceptRequest() }
                // the body's first byte only once the deadline would have passed for a head
                val bodySent = CompletableDeferred<Unit>()
                launch {
                    delay(600) // a real wait: longer than maxHeaderBlockTime, to show the body is not bound by it
                    st.output.writeFully(raw.data(byteArrayOf(1, 2, 3)))
                    st.output.flushAndClose()
                    bodySent.complete(Unit)
                }
                assertEquals(3, r.body.readAllBytes().size)
                bodySent.await()
                r.respond(204).finish()
                assertTrue(st.input.readAllBytes().isNotEmpty())
                assertEquals(0, withContext(server.session.dispatcher) { server.session.headDeadlinesPassedForTest })
            }
        }

    /**
     * 100 request streams (the default stream limit) each park most of a 128 KiB HEADERS frame: the server holds at most its
     * header budget of them (4 frames, 512 KiB), the others' bytes stay in their flow-control windows (not taken from the
     * transport, so they return the client no credit) while their readers wait in line. Before 0.3.0 all of them were read,
     * 12.5 MiB for one connection.
     */
    @Test fun negative_unfinishedRequestHeadsHoldNoMoreThanTheBudget() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val streams = 100
                val opened = mutableListOf<QuicStream>()
                val writers =
                    launch {
                        repeat(streams) {
                            val st = c.openBidi()
                            opened += st
                            launch {
                                st.output.writeFully(headersHeader(131_072) + ByteArray(131_000))
                                st.output.flush()
                            }
                        }
                    }
                val budget = server.session.headerBudget
                // the heads that wait keep the connection's window full, so the client cannot even start the last streams
                awaitCondition("the budget to fill and other heads to wait", 15.seconds) {
                    withContext(server.session.dispatcher) {
                        // four granted, each holding all it got but its QPACK prefix byte (read before the reservation)
                        budget.waiting > 0 && server.session.bufferedHeaderBytes == 4 * (131_000L - 1)
                    }
                }
                withContext(server.session.dispatcher) {
                    val s3 = server.session
                    assertEquals(512L * 1024, budget.capacity)
                    assertTrue(budget.reserved <= budget.capacity)
                    val taken = s3.pendingHeaders.values.sumOf { it.first.inputTakenForTest }
                    assertTrue(taken <= budget.capacity + streams * 16L, "the server took $taken bytes of unfinished heads")
                }
                assertFalse(server.closed.isCompleted)
                writers.cancel()
                // a reader waiting in line notices its stream's reset long before the 10 s deadline
                opened.forEach { runCatching { it.reset(Http3ErrorCode.REQUEST_CANCELLED) } }
                awaitCondition("the readers to end at the resets", 3.seconds) {
                    withContext(server.session.dispatcher) { server.session.pendingHeaders.isEmpty() }
                }
                assertEquals(0, withContext(server.session.dispatcher) { server.session.headDeadlinesPassedForTest })
                assertNothingHeld(server)
                assertFalse(server.closed.isCompleted)
            }
        }

    /**
     * Control for the budget: 24 concurrent requests whose heads (about 35 KiB each, 840 KiB together) exceed the budget
     * and the initial connection window all get their answers: a section is read only with its whole length reserved, so
     * two half-read sections never wait on each other.
     */
    @Test fun headsAboveTheBudgetTogetherAllComplete() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val n = 24
                launch {
                    repeat(n) {
                        val r = p.server.acceptRequest()
                        launch { r.respond(204, Http3Headers.of("x-big" to r.headers["x-big"]!!)).finish() }
                    }
                }
                val big = Http3Headers.of("x-big" to "x".repeat(40_000))
                val answers =
                    (0 until n).map {
                        async { p.client.request(http3Request("GET", "server.test", "/$it") { headers = big }).status }
                    }
                assertEquals(List(n) { 204 }, answers.awaitAll())
                assertNothingHeld(p.server)
                assertNothingHeld(p.client)
            }
        }

    /**
     * Control at a larger scale: 60 parallel requests with heads of nearly `maxFieldSectionSize` that do not compress
     * (about 3.7 MB together, far above the budget plus the connection window) all get their answers.
     */
    @Test fun nearLimitHeadsInParallelAllComplete() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val n = 60
                launch {
                    repeat(n) {
                        val r = p.server.acceptRequest()
                        launch { r.respond(204).finish() }
                    }
                }
                val rnd = kotlin.random.Random(1)
                val answers =
                    (0 until n).map {
                        val v = String(CharArray(62_000) { "~^|`{}<>\\".random(rnd) })
                        async {
                            p.client
                                .request(
                                    http3Request("GET", "server.test", "/$it") { headers = Http3Headers.of("x-big" to v) },
                                ).status
                        }
                    }
                assertEquals(List(n) { 204 }, answers.awaitAll())
                assertNothingHeld(p.server)
                assertNothingHeld(p.client)
            }
        }

    /** A server that trickles a response head: the request fails with H3_REQUEST_CANCELLED at `maxHeaderBlockTime`. */
    @Test fun negative_responseHeadThatNeverCompletesCancelsTheRequest() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c, fastDeadline)
                val raw = RawPeer(s)
                raw.openControl()
                val call = async { runCatching { client.request(http3Request("GET", "server.test", "/")) } }
                val st = s.acceptBidi()
                st.output.writeFully(headersHeader(4000) + byteArrayOf(0, 0))
                st.output.flush()
                val e = call.await().exceptionOrNull()
                val p = assertIs<Http3Exception.Protocol>(e, "$e")
                assertEquals(Http3ErrorCode.REQUEST_CANCELLED, p.h3Code)
                assertEquals(Initiator.Local, p.initiator)
                // the request was sent whole (FIN): the client's STOP_SENDING is what the server sees
                assertEquals(Http3ErrorCode.REQUEST_CANCELLED, withTimeout(5.seconds) { st.awaitSendStopped() })
                assertNothingHeld(client)
                assertFalse(client.closed.isCompleted, "a slow head is no connection error")
            }
        }

    /**
     * Control: the deadline runs from a HEADERS frame's first byte, so a server that takes long before answering (a long
     * poll) is not cut off.
     */
    @Test fun aLateButWholeResponseIsNoSlowHead() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c, fastDeadline)
                val raw = RawPeer(s)
                raw.openControl()
                val call = async { client.request(http3Request("GET", "server.test", "/")) }
                val st = s.acceptBidi()
                delay(600) // a real wait: the answer comes later than maxHeaderBlockTime after the request
                st.output.writeFully(raw.headers(st.id, listOf(":status" to "200")))
                st.output.flushAndClose()
                assertEquals(200, call.await().status)
            }
        }

    /**
     * A hostile server parks most of a 128 KiB response head on each of 10 requests: the client holds at most its budget
     * (4 frames), the rest stays unread in the streams' windows, and losing the connection releases everything.
     */
    @Test fun negative_unfinishedResponseHeadsHoldNoMoreThanTheBudget() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c)
                val raw = RawPeer(s)
                raw.openControl()
                val calls = (0 until 10).map { async { runCatching { client.request(http3Request("GET", "server.test", "/$it")) } } }
                val writers =
                    launch {
                        repeat(10) {
                            val st = s.acceptBidi()
                            launch {
                                st.output.writeFully(headersHeader(131_072) + ByteArray(131_000))
                                st.output.flush()
                            }
                        }
                    }
                val budget = client.session.headerBudget
                awaitCondition("the client's budget to fill", 15.seconds) {
                    withContext(client.session.dispatcher) {
                        budget.waiting > 0 && client.session.bufferedHeaderBytes == 4 * (131_000L - 1)
                    }
                }
                assertTrue(withContext(client.session.dispatcher) { client.session.bufferedHeaderBytes } <= budget.capacity)
                writers.cancel()
                s.close()
                // every request fails with the connection's end, at once: the ones waiting in line too, not at their deadline
                withTimeout(3.seconds) {
                    calls.forEach {
                        val e = it.await().exceptionOrNull()
                        assertTrue(e != null && (e !is Http3Exception.Protocol || e.h3Code != Http3ErrorCode.REQUEST_CANCELLED), "$e")
                    }
                }
                assertNothingHeld(client)
            }
        }

    /**
     * Trailers that never complete: the request was handed to the application, so the server cancels it with
     * H3_REQUEST_CANCELLED (RFC 9114 section 4.1.1: "partially or fully processed"), and the body read fails.
     */
    @Test fun negative_trailersThatNeverCompleteCancelTheRequest() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, fastDeadline)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, POST) + raw.data(byteArrayOf(1, 2)) + headersHeader(100) + byteArrayOf(0))
                st.output.flush()
                val r = withTimeout(5.seconds) { server.acceptRequest() }
                val e = runCatching { r.body.readBuffer() }.exceptionOrNull()
                val p = generateSequence(e) { it.cause }.filterIsInstance<Http3Exception.Protocol>().firstOrNull() ?: fail("$e")
                assertEquals(Http3ErrorCode.REQUEST_CANCELLED, p.h3Code)
                assertEquals(Http3ErrorCode.REQUEST_CANCELLED, withTimeout(5.seconds) { resetCode(st) })
                assertNothingHeld(server)
                assertFalse(server.closed.isCompleted)
            }
        }

    /**
     * [count] copies of [frame] in one request's body (a POST whose body is read whole) against a bucket whose clock stands
     * still (1000 tokens): true when the connection is still open once the request was read.
     */
    private suspend fun bodyFramesLeaveTheConnectionOpen(
        frame: ByteArray,
        count: Int,
    ): Boolean =
        QuicPair.open().useScoped { q ->
            val (c, s) = q.connect()
            val server = Http3Connection.server(s)
            server.session.glitchClock = { 0L }
            val raw = RawPeer(c)
            raw.openControl()
            val st = c.openBidi()
            val flood = ByteArray(frame.size * count).also { for (i in 0 until count) frame.copyInto(it, i * frame.size) }
            launch {
                peerMayHaveClosed {
                    st.output.writeFully(raw.headers(st.id, POST) + flood)
                    st.output.flushAndClose()
                }
            }
            val read = runCatching { withTimeout(10.seconds) { server.acceptRequest() }.body.readAllBytes() }
            if (read.isSuccess && !server.closed.isCompleted) return@useScoped true
            assertEquals(Http3ErrorCode.EXCESSIVE_LOAD, peerSawClose(c))
            false
        }

    private val emptyData = byteArrayOf(FrameType.DATA.toByte(), 0)
    private val emptyGrease = byteArrayOf(FrameType.grease(0).toByte(), 0)

    /** The first [RequestFrames.FREE_USELESS_FRAMES] empty DATA frames of a stream are free, then each spends a token. */
    @Test fun aFewEmptyDataFramesAreFree() =
        h3Test { assertTrue(bodyFramesLeaveTheConnectionOpen(emptyData, RequestFrames.FREE_USELESS_FRAMES + 1000)) }

    /** RFC 9114 section 10.5: a flood of empty DATA frames ends the connection (as HTTP/2's `negative_emptyDataFlood`). */
    @Test fun negative_emptyDataFloodIsExcessiveLoad() =
        h3Test { assertFalse(bodyFramesLeaveTheConnectionOpen(emptyData, RequestFrames.FREE_USELESS_FRAMES + 1001)) }

    @Test fun aFewGreaseFramesInABodyAreFree() =
        h3Test { assertTrue(bodyFramesLeaveTheConnectionOpen(emptyGrease, RequestFrames.FREE_USELESS_FRAMES + 1000)) }

    /** RFC 9114 section 10.5: a flood of reserved frames ends the connection, as one of unknown types does. */
    @Test fun negative_greaseFloodOnARequestStreamIsExcessiveLoad() =
        h3Test { assertFalse(bodyFramesLeaveTheConnectionOpen(emptyGrease, RequestFrames.FREE_USELESS_FRAMES + 1001)) }

    /**
     * Control: the free frames are per stream. 130 requests each with the free share of GREASE and empty DATA frames
     * (1040 frames) leave the connection open with a bucket that never refills.
     */
    @Test fun theFreeShareIsPerStream() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                server.session.glitchClock = { 0L }
                val raw = RawPeer(c)
                raw.openControl()
                val half = RequestFrames.FREE_USELESS_FRAMES / 2
                val share =
                    ByteArray(0).let {
                        var b = it
                        repeat(half) { b += emptyGrease + emptyData }
                        b
                    }
                repeat(130) {
                    val st = c.openBidi()
                    st.output.writeFully(raw.headers(st.id, POST) + share)
                    st.output.flushAndClose()
                    val r = withTimeout(5.seconds) { server.acceptRequest() }
                    r.body.readAllBytes()
                    r.respond(204).finish()
                    st.input.readAllBytes()
                }
                assertFalse(server.closed.isCompleted, "the free share of each stream spent tokens")
            }
        }

    /** The client counts a server's empty DATA frames the same way. */
    @Test fun negative_emptyDataFloodInAResponseIsExcessiveLoad() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c)
                client.session.glitchClock = { 0L }
                val raw = RawPeer(s)
                raw.openControl()
                val call = async { runCatching { client.request(http3Request("GET", "server.test", "/")).body.readAllBytes() } }
                val st = s.acceptBidi()
                val count = RequestFrames.FREE_USELESS_FRAMES + 1001
                val flood = ByteArray(2 * count).also { for (i in 0 until count) emptyData.copyInto(it, 2 * i) }
                peerMayHaveClosed {
                    st.output.writeFully(raw.headers(st.id, listOf(":status" to "200")) + flood)
                    st.output.flushAndClose()
                }
                assertTrue(call.await().isFailure)
                assertEquals(Http3ErrorCode.EXCESSIVE_LOAD, peerSawClose(s))
            }
        }
}
