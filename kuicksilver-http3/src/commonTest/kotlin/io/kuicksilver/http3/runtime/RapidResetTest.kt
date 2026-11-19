// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.http3.runtime

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.awaitAbandoned
import io.kuicksilver.http3.handlerEnded
import io.kuicksilver.http3.holdStreamUntilHandled
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.awaitSendStopped
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.runtime.QuicStreamLimits
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The HTTP/3 form of Rapid Reset (CVE-2023-44487): the client opens a request and resets it at once (STOP_SENDING and
 * RESET_STREAM). The transport is done with such a stream immediately, but the application's handler may still run; the
 * stream's MAX_STREAMS credit must stay taken until the application ended the request, or a client keeps any number of
 * handlers running within a limit of [LIMIT] streams (RFC 9114 section 10.5).
 */
@OptIn(ExperimentalAtomicApi::class)
class RapidResetTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private class Handlers {
        val running = AtomicInt(0)
        val maxRunning = AtomicInt(0)
        val started = AtomicInt(0)

        /** Requests whose handler saw the client's reset (their trailers failed). */
        val sawReset = AtomicInt(0)
        val gate = CompletableDeferred<Unit>()

        fun enter() {
            started.incrementAndFetch()
            val n = running.incrementAndFetch()
            while (true) {
                val m = maxRunning.load()
                if (n <= m || maxRunning.compareAndSet(m, n)) break
            }
        }
    }

    /** A handler that ignores the reset: it waits for the gate, then answers (which fails on a reset stream). */
    private suspend fun handle(
        r: Http3ServerRequest,
        h: Handlers,
    ) {
        h.enter()
        try {
            runCatching { r.trailers.await() }.onFailure { h.sawReset.incrementAndFetch() }
            h.gate.await()
            runCatching { r.respond(200).finish() }
        } finally {
            h.running.decrementAndFetch()
        }
    }

    /**
     * Opens a request and resets it in both directions, as the attack does, once [handlerStarted] says its handler runs (a
     * reset that overtakes the HEADERS ends the stream before it is a request: no handler, nothing to hold).
     */
    private suspend fun RawPeer.rapidReset(
        code: Long = Http3ErrorCode.REQUEST_CANCELLED,
        handlerStarted: suspend () -> Unit,
    ) {
        val st = quic.openBidi()
        st.output.writeFully(headers(st.id, GET))
        peerMayHaveClosed { st.output.flush() }
        handlerStarted()
        st.stopSending(code)
        st.reset(code)
    }

    @Test fun negative_resetRequestKeepsItsStreamCreditWhileTheHandlerRuns() =
        h3Test {
            QuicPair.open(quicConfig { maxBidiStreams = LIMIT }).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val h = Handlers()
                val accept =
                    launch {
                        while (true) {
                            val r = runCatching { server.acceptRequest() }.getOrNull() ?: break
                            launch { handle(r, h) }
                        }
                    }
                val raw = RawPeer(c)
                raw.openControl()
                val client =
                    launch {
                        repeat(3 * LIMIT.toInt()) { i -> raw.rapidReset { awaitCondition("handler ${i + 1}") { h.started.load() > i } } }
                    }
                // every handler of the first LIMIT requests runs and has seen its reset: the transport is done with the streams
                awaitCondition("$LIMIT handlers seeing their reset") { h.sawReset.load() >= LIMIT }
                assertEquals(LIMIT.toInt(), h.maxRunning.load(), "handlers at once with $LIMIT streams allowed")
                assertEquals(
                    LIMIT,
                    QuicStreamLimits.peerBidiStreamsGranted(s),
                    "streams granted while $LIMIT handlers of reset requests run",
                )
                h.gate.complete(Unit)
                client.join()
                awaitCondition("every handler ending") { h.started.load() == 3 * LIMIT.toInt() && h.running.load() == 0 }
                assertTrue(h.maxRunning.load() <= LIMIT, "handlers at once: ${h.maxRunning.load()}")
                accept.cancel()
                server.close()
            }
        }

    /**
     * The flood itself: every reset of a request stream spends a glitch token (RFC 9114 section 10.5), so 1500 of them
     * with the bucket's 1000 tokens frozen end the connection with H3_EXCESSIVE_LOAD, and the handlers that ran meanwhile
     * never outnumbered the streams the client may open.
     */
    @Test fun negative_rapidResetFloodEndsWithExcessiveLoad() =
        h3Test {
            QuicPair.open(quicConfig { maxBidiStreams = LIMIT }).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                server.session.glitchClock = { 0L } // no refill: exactly 1000 tokens
                val h = Handlers().also { it.gate.complete(Unit) }
                val accept =
                    launch {
                        while (true) {
                            val r = runCatching { server.acceptRequest() }.getOrNull() ?: break
                            launch { handle(r, h) }
                        }
                    }
                val raw = RawPeer(c)
                raw.openControl()
                runCatching { repeat(1500) { raw.rapidReset {} } } // fails once the server closed
                assertEquals(Http3ErrorCode.EXCESSIVE_LOAD, peerSawClose(c))
                assertTrue(h.maxRunning.load() <= LIMIT, "handlers at once: ${h.maxRunning.load()}")
                accept.cancel()
            }
        }

    /**
     * The reset budget is its own (as nghttp2's stream_reset_ratelim beside its glitch limit): 700 resets and 700 unknown
     * control frames, each within its 1000 tokens, leave the connection open although together they pass 1000.
     */
    @Test fun resetsAndOtherGlitchesHaveSeparateBudgets() =
        h3Test {
            QuicPair.open(quicConfig { maxBidiStreams = LIMIT }).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                server.session.glitchClock = { 0L }
                val h = Handlers().also { it.gate.complete(Unit) }
                val accept =
                    launch {
                        while (true) {
                            val r = runCatching { server.acceptRequest() }.getOrNull() ?: break
                            launch { handle(r, h) }
                        }
                    }
                val raw = RawPeer(c)
                raw.openControl()
                val unknown = raw.frame(0x2f, ByteArray(0)) // reserved for no extension we know, and no GREASE value
                raw.control.output.writeFully(
                    ByteArray(0).let {
                        var b = it
                        repeat(700) { b += unknown }
                        b
                    },
                )
                raw.control.output.flush()
                repeat(700) { raw.rapidReset {} }
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, GET))
                st.output.flushAndClose()
                val answer = runCatching { withTimeout(10.seconds) { st.input.readAllBytes() } }
                assertTrue(answer.isSuccess && answer.getOrThrow().isNotEmpty(), "the request after the resets: $answer")
                assertTrue(!server.closed.isCompleted)
                accept.cancel()
            }
        }

    /**
     * H3_NO_ERROR is free only after a complete response (RFC 9114 section 4.1): 1500 requests reset with it before any
     * response end the connection with H3_EXCESSIVE_LOAD like any other reset flood.
     */
    @Test fun negative_noErrorResetsBeforeTheResponseAreCounted() =
        h3Test {
            QuicPair.open(quicConfig { maxBidiStreams = LIMIT }).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                server.session.glitchClock = { 0L }
                // each handler reads the body's failure (the reset), which gives its stream back
                val accept =
                    launch {
                        while (true) {
                            val r = runCatching { server.acceptRequest() }.getOrNull() ?: break
                            launch { runCatching { r.body.readAllBytes() } }
                        }
                    }
                val raw = RawPeer(c)
                raw.openControl()
                runCatching { repeat(1500) { raw.rapidReset(Http3ErrorCode.NO_ERROR) {} } } // fails once the server closed
                assertEquals(Http3ErrorCode.EXCESSIVE_LOAD, peerSawClose(c))
                accept.cancel()
            }
        }

    /**
     * A client that ends its request with an H3_NO_ERROR reset once it has the complete response, as section 4.1 allows,
     * spends nothing: 1500 such requests leave the connection open.
     */
    @Test fun noErrorResetsAfterACompleteResponseAreNotCounted() =
        h3Test {
            QuicPair.open(quicConfig { maxBidiStreams = LIMIT }).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                server.session.glitchClock = { 0L }
                val accept =
                    launch {
                        while (true) {
                            val r = runCatching { server.acceptRequest() }.getOrNull() ?: break
                            launch { runCatching { r.respond(200).finish() } }
                        }
                    }
                val raw = RawPeer(c)
                raw.openControl()
                repeat(1500) {
                    val st = c.openBidi()
                    st.output.writeFully(raw.headers(st.id, GET)) // no FIN: the request stays open
                    peerMayHaveClosed { st.output.flush() }
                    assertTrue(withTimeout(10.seconds) { st.input.readAllBytes() }.isNotEmpty(), "a complete response")
                    st.reset(Http3ErrorCode.NO_ERROR)
                }
                assertTrue(!server.closed.isCompleted, "closed: ${server.closed.takeIf { it.isCompleted }?.getCompleted()}")
                accept.cancel()
            }
        }

    /** A client that cancels some requests (a browser leaving a page) stays within the budget, and its next request is served. */
    @Test fun resetsWithinTheBudgetKeepTheConnection() =
        h3Test {
            QuicPair.open(quicConfig { maxBidiStreams = LIMIT }).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                server.session.glitchClock = { 0L }
                val h = Handlers().also { it.gate.complete(Unit) }
                val accept =
                    launch {
                        while (true) {
                            val r = runCatching { server.acceptRequest() }.getOrNull() ?: break
                            launch { handle(r, h) }
                        }
                    }
                val raw = RawPeer(c)
                raw.openControl()
                repeat(200) { raw.rapidReset {} }
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, GET))
                st.output.flushAndClose()
                val answer = runCatching { withTimeout(10.seconds) { st.input.readAllBytes() } }
                assertTrue(answer.isSuccess && answer.getOrThrow().isNotEmpty(), "the request after 200 resets: $answer")
                assertTrue(!server.closed.isCompleted)
                accept.cancel()
            }
        }

    /**
     * The core API's rule for an application that is not an engine: a request is over for it once it read the request's
     * failure, also without answering. Its handlers do only that, and more requests than the limit are each served in turn
     * (the stream's credit came back; a held credit would stop the client at [LIMIT]).
     */
    @Test fun handlerThatReadsTheResetGivesTheStreamBack() =
        h3Test {
            QuicPair.open(quicConfig { maxBidiStreams = LIMIT }).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val started = AtomicInt(0)
                val accept =
                    launch {
                        while (true) {
                            val r = runCatching { server.acceptRequest() }.getOrNull() ?: break
                            launch {
                                started.incrementAndFetch()
                                runCatching { r.body.readAllBytes() } // fails with the reset: the handler returns without an answer
                            }
                        }
                    }
                val raw = RawPeer(c)
                raw.openControl()
                repeat(3 * LIMIT.toInt()) { i -> raw.rapidReset { awaitCondition("handler ${i + 1}") { started.load() > i } } }
                assertEquals(3 * LIMIT.toInt(), started.load())
                accept.cancel()
            }
        }

    /**
     * An engine cancels a handler whose client abandoned the request (`awaitAbandoned`), but not once its response was sent
     * in full: a late STOP_SENDING or the connection's end then leaves a handler that goes on with other work alone. The
     * abandonment is signalled directly here; before the response the same signal ends the wait (the control).
     */
    @Test fun abandonmentAfterTheFullResponseDoesNotEndTheWait() =
        h3Test {
            io.kuicksilver.http3.H3Pair.open().useScoped { p ->
                val response = async { p.client.request(io.kuicksilver.http3.http3Request("GET", "server.test", "/")) }
                val early = p.server.acceptRequest() as ServerRequestImpl
                val earlyWait = launch { early.awaitAbandoned() }
                early.peerAbandoned.complete(Unit)
                withTimeout(5.seconds) { earlyWait.join() } // before the response: the abandonment ends the wait
                early.respond(200).finish()
                assertEquals(200, response.await().status)
                val second = async { p.client.request(io.kuicksilver.http3.http3Request("GET", "server.test", "/2")) }
                val r = p.server.acceptRequest() as ServerRequestImpl
                r.respond(200).finish()
                assertEquals(200, second.await().status)
                val wait = launch { r.awaitAbandoned() }
                r.peerAbandoned.complete(Unit)
                repeat(3) { kotlinx.coroutines.withContext(p.server.session.dispatcher) { kotlinx.coroutines.yield() } }
                kotlinx.coroutines.yield()
                assertTrue(wait.isActive, "the wait ended after a response sent in full")
                wait.cancel()
            }
        }

    /** Accepts every request with an engine's handler: holds its stream, waits until the client abandons it, then ends. */
    private fun kotlinx.coroutines.CoroutineScope.abandonedHandlers(
        server: Http3Connection,
        resetAfter: Boolean = false,
    ) = launch {
        while (true) {
            val r = runCatching { server.acceptRequest() }.getOrNull() ?: break
            r.holdStreamUntilHandled()
            launch {
                try {
                    r.awaitAbandoned()
                    // what the Ktor engine does with a cancelled handler: both directions of the request end
                    if (resetAfter) r.reset(Http3ErrorCode.REQUEST_CANCELLED)
                } finally {
                    r.handlerEnded()
                }
            }
        }
    }

    /**
     * Rapid Reset by STOP_SENDING alone: a complete request (HEADERS and FIN), its response then stopped. The client never
     * resets anything, yet each stop abandons a request whose handler had started (the engine cancels it and its stream comes
     * back), so each spends a token of the request-reset budget (RFC 9114 section 10.5): 1500 of them end the connection
     * with H3_EXCESSIVE_LOAD. Before, a stop cost nothing and such a flood went on at full speed.
     */
    @Test fun negative_stopSendingFloodEndsWithExcessiveLoad() =
        h3Test {
            QuicPair.open(quicConfig { maxBidiStreams = LIMIT }).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                server.session.glitchClock = { 0L } // no refill: exactly 1000 tokens
                val accept = abandonedHandlers(server)
                val raw = RawPeer(c)
                raw.openControl()
                var sent = 0
                runCatching {
                    repeat(1500) {
                        val st = c.openBidi()
                        st.output.writeFully(raw.headers(st.id, GET))
                        peerMayHaveClosed { st.output.flushAndClose() }
                        st.stopSending(Http3ErrorCode.REQUEST_CANCELLED)
                        sent++
                    }
                } // fails once the server closed
                assertEquals(Http3ErrorCode.EXCESSIVE_LOAD, peerSawClose(c))
                assertTrue(sent > 1000, "the connection ended after $sent stops")
                accept.cancel()
            }
        }

    /**
     * STOP_SENDING first, the reset only once the server stopped the request in turn: a reset that follows our own
     * STOP_SENDING is never seen as the client's (the stream fails with our stop), so before, neither half of the pair cost
     * anything. The stop is the abandonment now, counted once: 1500 such requests end the connection with H3_EXCESSIVE_LOAD.
     */
    @Test fun negative_stopSendingThenResetFloodEndsWithExcessiveLoad() =
        h3Test {
            QuicPair.open(quicConfig { maxBidiStreams = LIMIT }).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                server.session.glitchClock = { 0L }
                val accept = abandonedHandlers(server, resetAfter = true)
                val raw = RawPeer(c)
                raw.openControl()
                var sent = 0
                runCatching {
                    repeat(1500) {
                        val st = c.openBidi()
                        st.output.writeFully(raw.headers(st.id, GET)) // no FIN: the request stays open
                        peerMayHaveClosed { st.output.flush() }
                        st.stopSending(Http3ErrorCode.REQUEST_CANCELLED)
                        // the server's STOP_SENDING for the request: the reset below comes after it
                        withTimeout(10.seconds) { st.awaitSendStopped() }
                        st.reset(Http3ErrorCode.REQUEST_CANCELLED)
                        sent++
                    }
                }
                assertEquals(Http3ErrorCode.EXCESSIVE_LOAD, peerSawClose(c))
                // 1000 requests went whole; the 1001st one's stop ended the connection while the client waited for our stop
                assertTrue(sent >= 1000, "the connection ended after $sent stopped and reset requests")
                accept.cancel()
            }
        }

    /**
     * A request the client both stops and resets is abandoned once, and costs one token, whichever of the two the server
     * saw first: 700 such requests (1400 frames) stay within the budget of 1000 and the next request is answered.
     */
    @Test fun stopAndResetOfOneRequestSpendOneToken() =
        h3Test {
            QuicPair.open(quicConfig { maxBidiStreams = LIMIT }).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                server.session.glitchClock = { 0L }
                val started = AtomicInt(0)
                val accept =
                    launch {
                        while (true) {
                            val r = runCatching { server.acceptRequest() }.getOrNull() ?: break
                            r.holdStreamUntilHandled()
                            launch {
                                try {
                                    started.incrementAndFetch()
                                    if (r.path == "/last") r.respond(200).finish() else r.awaitAbandoned()
                                } finally {
                                    r.handlerEnded()
                                }
                            }
                        }
                    }
                val raw = RawPeer(c)
                raw.openControl()
                // the handler runs first, so the request is the application's and both halves of the abandon reach it
                repeat(700) { i -> raw.rapidReset { awaitCondition("handler ${i + 1}") { started.load() > i } } }
                val st = c.openBidi()
                st.output.writeFully(
                    raw.headers(
                        st.id,
                        listOf(
                            ":method" to "GET",
                            ":scheme" to "https",
                            ":authority" to "server.test",
                            ":path" to "/last",
                        ),
                    ),
                )
                st.output.flushAndClose()
                val answer = runCatching { withTimeout(10.seconds) { st.input.readAllBytes() } }
                assertTrue(answer.isSuccess && answer.getOrThrow().isNotEmpty(), "the request after 700 stopped and reset ones: $answer")
                assertTrue(!server.closed.isCompleted, "closed: ${server.closed.takeIf { it.isCompleted }?.getCompleted()}")
                accept.cancel()
            }
        }

    /**
     * The watch for a client's STOP_SENDING ends with the complete response, not with the request stream: a stop after the
     * complete response costs nothing, so the watch has nothing left to do, and waiting on for the stream's end it held the
     * whole request (its body channel, headers and deferreds) as long as the transport kept the stream, an idle connection's
     * last request included (about 1.2-1.9 KiB per connection; IdleFootprintTest, the HTTP/3 ceiling). A stop that comes
     * after the complete response leaves the connection up.
     */
    @Test fun theStopWatchEndsWithTheCompleteResponse() =
        h3Test {
            QuicPair.open(quicConfig { maxBidiStreams = LIMIT }).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                server.session.glitchClock = { 0L }
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, GET))
                st.output.flushAndClose()
                val r = withTimeout(10.seconds) { server.acceptRequest() } as ServerRequestImpl
                // the session starts the watch right after it handed the request over, maybe after acceptRequest returned here
                awaitCondition("the request's stop watch") { r.stopWatch != null }
                val watch = r.stopWatch!!
                assertTrue(watch.isActive, "a request handed to the application is watched for a stop")
                r.respond(200).finish()
                assertTrue(withTimeout(10.seconds) { st.input.readAllBytes() }.isNotEmpty())
                awaitCondition("the watch ending with the complete response") { watch.isCompleted }
                assertTrue(watch.isCancelled, "the complete response ended the watch, not the stream's end")
                // a stop now abandons nothing: the connection stays up and the next request is answered
                runCatching { st.stopSending(Http3ErrorCode.REQUEST_CANCELLED) }
                val next = c.openBidi()
                next.output.writeFully(raw.headers(next.id, GET))
                next.output.flushAndClose()
                withTimeout(10.seconds) { server.acceptRequest() }.respond(204).finish()
                assertTrue(withTimeout(10.seconds) { next.input.readAllBytes() }.isNotEmpty())
                assertTrue(!server.closed.isCompleted)
                server.close()
            }
        }

    /**
     * The response completes while its watch starts (the writer runs on another thread than the session's loop that starts
     * the watch): the watch is cancelled all the same, by its starter, which reads respondedInFull after it stored the watch.
     * The hook completes the response between the start and the store, the order in which responseComplete finds no watch.
     */
    @Test fun aResponseCompleteBeforeItsWatchIsStoredStillEndsTheWatch() =
        h3Test {
            QuicPair.open(quicConfig { maxBidiStreams = LIMIT }).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                var started: kotlinx.coroutines.Job? = null
                server.session.stopWatchStartedForTest = { req, watch ->
                    req.responseComplete() // as the writer's thread would, before the watch is stored
                    started = watch
                }
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, GET))
                st.output.flushAndClose()
                val r = withTimeout(10.seconds) { server.acceptRequest() } as ServerRequestImpl
                awaitCondition("the watch's start") { started != null }
                assertTrue(r.respondedInFull)
                awaitCondition("the watch ending") { started!!.isCompleted }
                assertTrue(started!!.isCancelled, "the starter cancelled the watch of a response complete before it was stored")
                assertEquals(null, r.stopWatch)
                server.close()
            }
        }

    /**
     * A stop that empties the reset budget while the response's FIN is being handed over: the watch closes the connection
     * with H3_EXCESSIVE_LOAD, and the response completing meanwhile cancels the watch. That cancel must not cut the close
     * short: fail had completed `closed` and was inside the transport's close, and the CONNECTION_CLOSE was never sent (the
     * client learnt of the end only from its idle timeout). The hooks hold the writer before its FIN until the stop spent
     * the last token, and fail before the transport's close until the response is complete.
     */
    @Test fun negative_aStopThatEmptiesTheBudgetAsTheResponseCompletesStillClosesTheConnection() =
        h3Test {
            QuicPair.open(quicConfig { maxBidiStreams = LIMIT }).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val session = server.session
                session.glitchClock = { 0L }
                kotlinx.coroutines.withContext(session.dispatcher) { session.spendResetBudgetForTest(1000) } // nothing left
                val atFin = CompletableDeferred<Unit>()
                val releaseFin = CompletableDeferred<Unit>()
                session.beforeResponseFinForTest = {
                    atFin.complete(Unit)
                    releaseFin.await()
                }
                var request: ServerRequestImpl? = null
                session.beforeFailTransportCloseForTest = {
                    releaseFin.complete(Unit) // the writer hands its FIN over and completes the response, which cancels the watch
                    awaitCondition("the complete response") { request!!.respondedInFull }
                }
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, GET))
                st.output.flushAndClose()
                val r = withTimeout(10.seconds) { server.acceptRequest() } as ServerRequestImpl
                request = r
                launch { runCatching { r.respond(200).finish() } }
                withTimeout(10.seconds) { atFin.await() }
                st.stopSending(Http3ErrorCode.REQUEST_CANCELLED)
                val code = withTimeoutOrNull(10.seconds) { peerSawClose(c) }
                assertEquals(Http3ErrorCode.EXCESSIVE_LOAD, code, "the client got the CONNECTION_CLOSE")
            }
        }

    /**
     * Resets the client makes us send (MadeYouReset, CVE-2025-8671; RFC 9114 section 10.5), as HTTP/2 counts them: a
     * malformed request head (no :path, RFC 9114 section 4.3.1) is reset with H3_MESSAGE_ERROR before it reaches the
     * application, and each is a glitch, so 1500 of them end the connection with H3_EXCESSIVE_LOAD. Before, a client that
     * read our resets sent them forever.
     */
    @Test fun negative_malformedRequestFloodEndsWithExcessiveLoad() =
        h3Test {
            QuicPair.open(quicConfig { maxBidiStreams = LIMIT }).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                server.session.glitchClock = { 0L }
                val raw = RawPeer(c)
                raw.openControl()
                val noPath = listOf(":method" to "GET", ":scheme" to "https", ":authority" to "server.test")
                runCatching {
                    repeat(1500) {
                        val st = c.openBidi()
                        st.output.writeFully(raw.headers(st.id, noPath))
                        peerMayHaveClosed { st.output.flushAndClose() }
                    }
                } // fails once the server closed
                assertEquals(Http3ErrorCode.EXCESSIVE_LOAD, peerSawClose(c))
            }
        }

    /**
     * The same after the request reached the application: a content-length the content does not match (RFC 9114 section
     * 4.1.2) resets the stream with H3_MESSAGE_ERROR once the request's handler holds it; each is a glitch, and 1500 end
     * the connection.
     */
    @Test fun negative_contentLengthMismatchFloodEndsWithExcessiveLoad() =
        h3Test {
            QuicPair.open(quicConfig { maxBidiStreams = LIMIT }).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                server.session.glitchClock = { 0L }
                // each handler reads the body's failure, which gives its stream back
                val accept =
                    launch {
                        while (true) {
                            val r = runCatching { server.acceptRequest() }.getOrNull() ?: break
                            launch { runCatching { r.body.readAllBytes() } }
                        }
                    }
                val raw = RawPeer(c)
                raw.openControl()
                val promised = GET + ("content-length" to "5")
                runCatching {
                    repeat(1500) {
                        val st = c.openBidi()
                        st.output.writeFully(raw.headers(st.id, promised)) // and no content
                        peerMayHaveClosed { st.output.flushAndClose() }
                    }
                }
                assertEquals(Http3ErrorCode.EXCESSIVE_LOAD, peerSawClose(c))
                accept.cancel()
            }
        }

    private companion object {
        const val LIMIT = 8L
    }
}
