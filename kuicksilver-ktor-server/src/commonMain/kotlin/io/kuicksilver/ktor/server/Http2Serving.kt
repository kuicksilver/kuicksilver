// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class, io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.http.HttpProtocolVersion
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.engine.handleFailure
import io.ktor.util.pipeline.execute
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.runtime.H2ServerConnection
import io.kuicksilver.http2.runtime.H2ServerStream
import io.kuicksilver.ktor.network.abort
import io.kuicksilver.ktor.network.bytesSent
import io.kuicksilver.ktor.network.openDeliveringReadChannel
import io.kuicksilver.ktor.server.h1.httpDateNow
import io.kuicksilver.ktor.server.h2.H2Call
import io.kuicksilver.tls.Certificate
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** How long a connection that ended in an error may go without sending anything while it closes, at most. */
internal val ERROR_CLOSE_STALL: Duration = 3.seconds

/** The engine's live HTTP/2 connections (for [KuicksilverServerProbe] and tests). */
internal class H2LiveSet {
    private val lock = Mutex()
    private val set = HashSet<H2ServerConnection>()

    /** How many there are (tests wait on it: a connection is added only after its runtime started). */
    val count = kotlinx.coroutines.flow.MutableStateFlow(0)

    suspend fun add(c: H2ServerConnection) =
        lock.withLock {
            set += c
            count.value = set.size
        }

    suspend fun remove(c: H2ServerConnection) =
        lock.withLock {
            set -= c
            count.value = set.size
        }

    suspend fun live(): List<H2ServerConnection> = lock.withLock { set.toList() }
}

/** [settings] with its field-block deadline bounded by the engine's request-head deadline [headerTimeout]. */
internal fun h2SettingsWithin(
    settings: Http2Settings,
    headerTimeout: Duration,
): Http2Settings {
    if (settings.maxHeaderBlockTime <= headerTimeout) return settings
    return with(settings) {
        Http2Settings(
            headerTableSize,
            maxConcurrentStreams,
            initialStreamWindow,
            maxStreamWindow,
            initialConnectionWindow,
            maxConnectionWindow,
            maxFrameSize,
            maxHeaderListSize,
            settingsAckTimeout,
            maxContinuationFrames,
            maxControlFramesQueued,
            maxEmptyFrames,
            resetBurst,
            resetsPerSecond,
            headerTimeout,
            glitchBurst,
            glitchesPerSecond,
        )
    }
}

/**
 * Serves one TLS connection that negotiated ALPN `h2` (RFC 9113 section 3.2) until it is over, then closes [sock] within
 * [sendTimeout] of no progress. Deadlines on the client: its connection preface by [prefaceWithin] (what is left of the
 * request-head deadline after the TLS handshake), each field block by `requestHeaderTimeout` (the core's
 * `maxHeaderBlockTime`), each wait for request content by [idle], each wait for window by [sendTimeout]; a connection
 * without requests for [idle] gets GOAWAY and closes. When the server stops ([draining]) the connection gets the two-step
 * GOAWAY (section 6.8): the requests it took finish, new ones are refused.
 */
internal suspend fun KuicksilverApplicationEngine.serveH2(
    sock: Socket,
    remote: InetSocketAddress?,
    peer: List<Certificate>,
    altSvc: () -> String?,
    prefaceWithin: Duration,
    idle: Duration,
    headerTimeout: Duration,
    sendTimeout: Duration,
    draining: Job,
) {
    val local = sock.localAddress as? InetSocketAddress
    var conn: H2ServerConnection? = null
    try {
        coroutineScope {
            val c =
                H2ServerConnection.start(
                    sock.openDeliveringReadChannel(),
                    sock.openWriteChannel(),
                    h2SettingsWithin(configuration.http2Settings, headerTimeout),
                    this,
                    closeTransport = { sock.close() },
                    clock =
                        configuration.h2ClockForTest
                            ?: kotlin.time.TimeSource.Monotonic
                                .markNow()
                                .let { m -> { m.elapsedNow().inWholeNanoseconds } },
                    ownResponseFields = { listOf("date" to httpDateNow()) }, // RFC 9110 section 6.6.1, on the 431
                )
            conn = c
            h2Live.add(c)
            events.emit("connectionOpened") { connectionOpened(HttpProtocolVersion.HTTP_2_0, remote) }
            // RFC 9113 section 3.4: the client preface, within the request-head deadline (as the first request head on HTTP/1.1)
            val preface = withTimeoutOrNull(prefaceWithin) { runCatching { c.awaitPreface() }.isSuccess }
            if (preface != true) {
                // section 9.1: GOAWAY before the close (no stream was taken: its last stream is 0); a client that does not
                // even read it is cut off after the send-stall deadline
                c.goAway(Http2ErrorCode.NO_ERROR)
                if (withTimeoutOrNull(sendTimeout) { c.awaitClosed() } == null) {
                    c.abort(IOException("no HTTP/2 connection preface within the request header timeout ($headerTimeout)"))
                    sock.abort()
                }
                return@coroutineScope
            }
            val watchers =
                listOf(
                    launch {
                        draining.join()
                        c.shutdown() // the server stops: two-step GOAWAY, the requests taken finish
                    },
                    launch { closeWhenIdle(c, sock, idle, sendTimeout) },
                    launch {
                        // the protocol is over (a flood limit, any connection error, the last stream after GOAWAY): what is
                        // left to write goes out for as long as the client takes it, and once it takes nothing for the
                        // send-stall deadline the socket is aborted, so a client that floods without reading our answers
                        // does not hold the connection until the idle timeout
                        c.awaitEnded()
                        if (!drainsWhileMoving(c, sock, sendTimeout)) {
                            c.abort(IOException("the client took none of the connection's last frames for $sendTimeout"))
                            sock.abort()
                        }
                    },
                )
            launch {
                // a request's failure is its own (handleH2 catches it; the supervisor is the second line)
                supervisorScope {
                    for (r in c.requests) {
                        launch { handleH2(r, local, remote, peer, altSvc, idle, sendTimeout) }
                    }
                }
            }
            c.awaitClosed()
            watchers.forEach { it.cancel() }
        }
    } finally {
        conn?.let { c ->
            h2BytesRead.update { it + c.bytesReceived }
            if (c.endedByFloodDefence) strikeOffender(remote)
        }
        // closeWithin handles a cancelled caller itself (it aborts); the probe's set is left last and without cancellation,
        // so a forced stop neither skips the close nor leaves the entry behind
        // a connection that ended in an error (a flood limit, a protocol error) has only its GOAWAY left to deliver: a short
        // stall bound, since a client that keeps sending after it (a flood that does not stop) fills the buffers in front of
        // the socket, which then cannot finish closing by itself and would hold the descriptor for the whole send-stall time
        val stall =
            when {
                conn?.isClosed != true -> Duration.ZERO
                conn.endedInError -> minOf(sendTimeout, ERROR_CLOSE_STALL)
                else -> sendTimeout
            }
        closeWithin(sock, { sock.abort() }, stall)
        if (conn != null) events.emit("connectionClosed") { connectionClosed(HttpProtocolVersion.HTTP_2_0, remote) }
        conn?.let { withContext(NonCancellable) { h2Live.remove(it) } }
    }
}

/**
 * Waits until [c] wrote what it had left and closed; false once the socket took no byte for [stall] (the bytes the kernel
 * took, `bytesSent`, looked at every second, as [closeWithin] does; where they are not known, [stall] bounds the whole
 * wait).
 */
private suspend fun drainsWhileMoving(
    c: H2ServerConnection,
    sock: Socket,
    stall: Duration,
): Boolean {
    val poll = minOf(1.seconds, stall)
    var last = sock.bytesSent
    var quiet = Duration.ZERO
    while (withTimeoutOrNull(poll) { c.awaitClosed() } == null) {
        val now = sock.bytesSent
        if (now == null || now == last) {
            quiet += poll
            if (quiet >= stall) return false
        } else {
            last = now
            quiet = Duration.ZERO
        }
    }
    return true
}

/**
 * A connection from [remote] ended in a flood defence (we sent GOAWAY ENHANCE_YOUR_CALM for a flood limit): with
 * `http2RepeatOffenderPenalty`, one strike for its address. The
 * strike that starts a penalty is logged at debug level (many addresses may start one at once); the refusals that follow
 * are the warning, rate-limited per connector ([RefusalReporter]).
 */
private suspend fun KuicksilverApplicationEngine.strikeOffender(remote: InetSocketAddress?) {
    // counted after the strike is recorded: a test that waits for the count then sees the strike's effect at accept
    try {
        val offenders = h2Offenders ?: return // http2RepeatOffenderPenalty off (the default)
        if (withContext(NonCancellable) { offenders.strike(remote) }) {
            environment.log.debug(
                "HTTP/2: connections from ${RepeatOffenders.describe(remote)} keep ending in ENHANCE_YOUR_CALM (flood limits); " +
                    "refusing its connections for a while",
            )
        }
    } finally {
        h2FloodEnds.update { it + 1 }
    }
}

/**
 * GOAWAY for a connection without requests for [idle] (`connectionIdleTimeoutSeconds`); a request that arrives meanwhile
 * restarts the count. A connection that then cannot even write its GOAWAY within [sendTimeout] once its last request is
 * done (the client reads nothing) is aborted.
 */
private suspend fun closeWhenIdle(
    c: H2ServerConnection,
    sock: Socket,
    idle: Duration,
    sendTimeout: Duration,
) {
    while (true) {
        c.openRequests.first { it == 0 }
        // a monotonic count: a request that starts and ends within the wait restarts it too (openRequests alone would
        // conflate 0, 1, 0 into no change)
        val seen = c.requestsTaken.value
        if (withTimeoutOrNull(idle) { c.requestsTaken.first { it != seen } } == null && c.openRequests.value == 0) break
    }
    c.shutdown()
    // a request that crossed the first GOAWAY runs to its end on its own deadlines; then the close is bounded
    c.openRequests.first { it == 0 }
    if (withTimeoutOrNull(sendTimeout) { c.awaitClosed() } == null) sock.abort()
}

/**
 * One request stream as a Ktor call, after HTTP/3's handleHttp3: a CONNECT is answered 501 (the engine has no tunnels), a
 * request a gateway forwarded from early data and not replayable 425 (RFC 8470 section 5.1). The handler is cancelled
 * when the stream fails under it (the client's RST_STREAM, the connection), and then nothing is sent on the stream (RFC
 * 9113 section 5.4.2: no RST_STREAM in answer to one). A call that ends without a response on a live stream resets it
 * (INTERNAL_ERROR), never leaving it unanswered. Whatever the call throws ends this stream only (section 5.4.2: a stream
 * error affects the stream alone): it is logged, never passed to the connection. The stream is released at the end.
 */
private suspend fun KuicksilverApplicationEngine.handleH2(
    r: H2ServerStream,
    local: InetSocketAddress?,
    remote: InetSocketAddress?,
    peer: List<Certificate>,
    altSvc: () -> String?,
    bodyIdle: Duration,
    sendTimeout: Duration,
) {
    val job = currentCoroutineContext().job
    r.invokeOnFailure { job.cancel(CancellationException("HTTP/2 stream ${r.id} ended: ${it.message}", it)) }
    var answered = false
    try {
        if (r.method == "CONNECT") {
            answered = runCatching { r.respond(501, listOf("date" to httpDateNow()), endStream = true) }.isSuccess
            return
        }
        if (r.fields.any { it.first == EARLY_DATA_FIELD.lowercase() } &&
            r.method !in io.kuicksilver.http3.Http3EarlyDataPolicy.SAFE_METHODS
        ) {
            answered = runCatching { r.respond(425, listOf("date" to httpDateNow()), endStream = true) }.isSuccess
            return
        }
        withContext(userDispatcher) requestContext@{
            val call =
                H2Call(
                    applicationProvider(),
                    r,
                    local,
                    remote,
                    peer,
                    this@requestContext.coroutineContext,
                    bodyIdle,
                    sendTimeout.inWholeMilliseconds,
                    altSvc,
                )
            events.emit("requestStarted") { requestStarted(HttpProtocolVersion.HTTP_2_0, call) }
            var failure: Throwable? = null
            try {
                pipeline.execute(call)
            } catch (error: Throwable) {
                failure = error
                // a stream that failed (reset by the client, the connection gone) takes no answer: Ktor's error response
                // would only fail in turn
                if (!r.failed) {
                    try {
                        handleFailure(call, error)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Throwable) {
                        environment.log.debug("HTTP/2 stream ${r.id}: the error response failed too: $e")
                    }
                }
            } finally {
                runCatching { call.finish() }
                answered = call.response.answered
                events.emit("requestEnded") { requestEnded(HttpProtocolVersion.HTTP_2_0, call, failure) }
            }
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Throwable) {
        // the call's set-up (the application provider, the call itself) or its error handling failed: this stream only
        environment.log.debug("HTTP/2 stream ${r.id} failed: $e")
    } finally {
        // a call that failed after its response was committed cannot get the 500 any more: the stream is reset, unless it
        // already ended (section 5.4.2)
        if (!answered && !r.failed) runCatching { r.reset(Http2ErrorCode.INTERNAL_ERROR) }
        r.release()
    }
}
