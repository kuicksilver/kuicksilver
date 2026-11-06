// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    io.kuicksilver.annotations.InternalKuicksilverApi::class,
    kotlin.concurrent.atomics.ExperimentalAtomicApi::class,
    kotlinx.coroutines.ExperimentalCoroutinesApi::class,
)

package io.kuicksilver.http3.runtime

import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.frame.ControlFrames
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.runtime.H3Session.Companion.DRAINERS_PRUNE_MIN
import io.kuicksilver.http3.runtime.H3Session.Companion.DRAIN_GRACE
import io.kuicksilver.http3.runtime.H3Session.Companion.beforeIdleCloseForTest
import io.kuicksilver.http3.runtime.H3Session.Companion.transportCause
import io.kuicksilver.http3.runtime.H3Session.Drainer
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.receivedAll
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withContext
import kotlin.time.Duration.Companion.milliseconds

// How a session ends: GOAWAY, idle close, fail, close and the draining of what is still being written (RFC 9114 section 5.2).

/**
 * Graceful shutdown (RFC 9114 section 5.2). A server sends GOAWAY(2^62-4), waits about two round trips for requests in
 * flight, then GOAWAY with the first id it will not process, and closes with H3_NO_ERROR once its accepted requests
 * are answered. A client sends GOAWAY(0) (no push) and stops issuing requests.
 */
internal suspend fun H3Session.goAway(): Unit = withContext(dispatcher) { goAwayConfined() }

internal suspend fun H3Session.goAwayConfined() {
    goAwayContextForTest?.invoke(currentCoroutineContext())
    if (goAwayPhase != 0 || closed.isCompleted) return
    if (!isServer) {
        goAwayPhase = 2
        goAwaySentId = 0
        sendGoAway(0)
        return
    }
    goAwayPhase = 1
    if (!sendGoAway((1L shl 62) - 4)) return
    delay(maxOf(quic.stats.smoothedRtt * 2, 50.milliseconds))
    val id = if (maxRequestId < 0) 0 else maxRequestId + 4
    goAwayPhase = 2
    goAwaySentId = id
    if (!sendGoAway(id)) return
    // a request below the GOAWAY id whose HEADERS never complete must not hold the connection open forever
    scope.launch {
        delay(headerDeadlineAfterGoAway)
        headerDeadlinePassed = true
        for ((st, reader) in pendingHeaders.values.toList()) {
            abort(st, Http3ErrorCode.REQUEST_REJECTED)
            reader.cancel()
        }
    }
    scope.launch { closeIfIdle() }
}

/**
 * GOAWAY([id]) on our control stream; false when the connection closed meanwhile, which ends the graceful shutdown
 * (a client idle after our first GOAWAY closes at once, RFC 9114 section 5.2).
 */
internal suspend fun H3Session.sendGoAway(id: Long): Boolean =
    try {
        sendControl(FrameType.GOAWAY, ControlFrames.goAwayPayload(id))
        true
    } catch (e: CancellationException) {
        throw e
    } catch (e: Throwable) {
        // the connection ended under the write (an idle client closes as soon as GOAWAY arrives): the transport's loss can
        // reach this write before the session's own close has run, so it counts as closed too
        if (closed.isCompleted || transportCause(e) is QuicException.ConnectionLost) false else throw e
    }

/**
 * After the final GOAWAY with nothing in flight and every response acknowledged (RFC 9114 section 5.2): the client
 * closes the connection once it read its responses (quic-go's server waits for exactly that); one that does not is
 * closed after [goAwayCloseFallback], so a slow reader of an acknowledged response still has that long.
 */
internal suspend fun H3Session.closeIfIdle() {
    if (activeRequests > 0 || settling > 0 || closed.isCompleted) return
    delay(maxOf(quic.stats.smoothedRtt * 4, goAwayCloseFallback))
    if (activeRequests == 0 && settling == 0) close(Http3ErrorCode.NO_ERROR, "")
}

/**
 * Client: a GOAWAY was received and no exchange is left, so this connection carries nothing more (no new request may
 * use it): close it with H3_NO_ERROR (RFC 9114 section 5.2), which is what lets the server finish its graceful stop
 * without guessing whether our responses were read.
 */
internal fun H3Session.closeIfIdleAfterGoAway() {
    if (isServer || goAwayReceived.value == null || openExchanges > 0 || closed.isCompleted) return
    scope.launch {
        beforeIdleCloseForTest?.invoke(this@closeIfIdleAfterGoAway)
        close(Http3ErrorCode.NO_ERROR, "")
    }
}

/** Connection error (RFC 9114 section 8): close with [code], fail everything waiting. */
internal suspend fun H3Session.fail(
    code: Long,
    reason: String,
) {
    if (!closed.complete(Http3Exception.Protocol(code, Initiator.Local, null, "${Http3ErrorCode.name(code)}: $reason"))) return
    requests.close(closed.getCompleted())
    try {
        quic.close(code, reason.take(200))
    } catch (e: CancellationException) {
        throw e
    } catch (_: Throwable) {
    }
}

internal suspend fun H3Session.close(
    code: Long,
    reason: String,
) {
    if (closed.complete(
            Http3Exception.Protocol(code, Initiator.Local, null, "closed locally with ${Http3ErrorCode.name(code)}"),
        )
    ) {
        requests.close(closed.getCompleted())
    }
    try {
        quic.close(code, reason)
    } catch (e: CancellationException) {
        throw e
    } catch (_: Throwable) {
    }
}

/**
 * [job] reads a peer's stream (a message body, a unidirectional stream): when the connection is lost it goes on until
 * its input ends, which it does once it has read what the peer sent before the loss (`QuicStream.input`), so a
 * response whose last bytes came with the peer's CONNECTION_CLOSE is still read whole. [stream] is the stream of the
 * message it reads: one that came whole is never cut ([onTransportClosed]). Any thread (a capsule reader starts on the
 * application's).
 */
internal fun H3Session.drains(
    job: Job,
    stream: QuicStream? = null,
): Job {
    while (true) {
        val now = drainers.load()
        val kept = if (now.size >= DRAINERS_PRUNE_MIN) now.filter { !it.job.isCompleted } else now
        if (drainers.compareAndSet(now, kept + Drainer(job, stream))) return job
    }
}

/**
 * The connection is gone: every coroutine of the session ends, but the [drains] readers only once their inputs ended.
 * Cancelling them at once lost what the peer sent last, Firefox's WT_CLOSE_SESSION right before its close. A reader of
 * a stream that came whole (its FIN and every byte before it, RFC 9000 section 3.2 "Data Recvd") goes on until it has
 * handed all of it over: that is the peer's complete message (it ends with its stream, RFC 9114 section 4.1), and
 * the close does not take back what had arrived. Reading it needs nothing more from the network, and the reader does
 * not wait for the application either ([handOver]): it moves the rest into the body and ends, so the session ends
 * whether or not the application reads, and the bytes live only as long as the application keeps the body. Every
 * other reader gets at most [DRAIN_GRACE] (one the application does not keep up with is cut there, never holding the
 * session for a message that cannot complete).
 */
internal fun H3Session.onTransportClosed(e: QuicException.ConnectionLost) {
    if (closed.complete(Http3Exception.fromQuic(e))) requests.close(closed.getCompleted())
    val draining = drainers.exchange(emptyList()).filter { it.job.isActive }
    if (draining.isEmpty()) {
        job.cancel()
        return
    }
    val readers = draining.map { it.job }.toSet()
    for (c in job.children.toList()) if (c !in readers) c.cancel()
    // read once the transport reported the end, which it does after it settled which streams came whole
    val partial = draining.filter { it.stream?.receivedAll != true }.map { it.job }
    scope.launch {
        if (partial.isNotEmpty()) {
            launch(start = CoroutineStart.UNDISPATCHED) {
                drainTimer(DRAIN_GRACE)
                for (r in partial) r.cancel()
            }
        }
        for (r in readers) r.join()
        job.cancel()
    }
}

/**
 * Launches a reader of a peer's stream that may finish it when the connection is lost, like a [drains] one, from any
 * thread. It runs outside [scope]: a launch into the scope once the connection ended never runs, and a response whose
 * headers were read after the session processed the peer's CONNECTION_CLOSE lost its body that way (seen on slow
 * Windows and macOS runners). Once the session's coroutines are gone it gets at most [DRAIN_GRACE] more, then it is
 * cut, unless [stream], the stream it reads, came whole: then it goes on until it has handed all of it over (without
 * waiting for the application, [handOver]), however late it runs (a reader the scheduler paused past the grace cut a whole response with H3_NO_ERROR, seen on a loaded
 * Android 7 emulator).
 */
internal fun H3Session.launchDrainer(
    stream: QuicStream? = null,
    block: suspend CoroutineScope.() -> Unit,
): Job =
    afterEnd.launch {
        val reader =
            launch {
                beforeDrainerForTest?.invoke()
                block()
            }
        select {
            reader.onJoin {}
            job.onJoin {}
        }
        if (reader.isCompleted) return@launch
        val drainer = coroutineContext.job
        if (stream?.receivedAll != true) {
            // cut: this coroutine ends cancelled, the reader with it
            launch(start = CoroutineStart.UNDISPATCHED) {
                drainTimer(DRAIN_GRACE)
                drainer.cancel()
            }
        }
        reader.join()
        drainer.children.forEach { it.cancel() }
    }

/**
 * Runs [cleanup] when [job] ends cancelled, with the connection's reason once it is gone. Unlike a catch or finally in
 * the job's body this also runs for a job cancelled before it started: a launch into the scope of a connection that
 * already ended runs none of its body, and a channel only it would have closed left its reader or writer waiting
 * forever (a response body whose pump was launched just after the connection closed). [cleanup] runs on whatever
 * thread cancels the job: it may only close channels and complete deferreds.
 */
internal fun H3Session.onCancelled(
    job: Job,
    cleanup: (Throwable) -> Unit,
) {
    job.invokeOnCompletion { e -> if (e != null) cleanup(if (closed.isCompleted) closed.getCompleted() else e) }
}
