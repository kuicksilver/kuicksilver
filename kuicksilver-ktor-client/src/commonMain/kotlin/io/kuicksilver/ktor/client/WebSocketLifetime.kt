// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.HttpRequestData
import io.ktor.util.AttributeKey
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketSession
import io.kuicksilver.ktor.client.h1.SpinLock
import io.kuicksilver.quic.LogLevel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.ChannelResult
import kotlinx.coroutines.channels.SendChannel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicReference
import kotlin.coroutines.CoroutineContext
import kotlin.time.TimeMark
import kotlin.time.TimeSource

/**
 * The close wait of a client WebSocket, counted from the session's own Close: how long the session may still take to write
 * that Close once its call ended, and over HTTP/2 to see the server's END_STREAM after it (RFC 6455 section 7.1.1: the
 * client "MAY close the connection at any time after sending and receiving a Close message, e.g., if it has not received a
 * TCP Close from the server in a reasonable time period"). One deadline for all of it.
 */
internal const val WEBSOCKET_CLOSE_WAIT_MILLIS: Long = 5_000

/**
 * What the engine gives each call for a WebSocket session that may outlive it: [hold] is the engine's in-flight job of the
 * call (the engine's cleanup after `close()` waits for it), [events] the engine's listener.
 */
internal class WebSocketCallTrack(
    val hold: Job,
    val events: EngineEvents,
)

/** The [WebSocketCallTrack] of a request, put by the engine before the call is routed. */
internal val WebSocketCallTrackKey: AttributeKey<WebSocketCallTrack> = AttributeKey("io.kuicksilver.ktor.client.WebSocketCallTrack")

/** The [WebSocketLifetime] of the request's WebSocket session, put when the session's handshake is in hand. */
internal val WebSocketLifetimeKey: AttributeKey<WebSocketLifetime> = AttributeKey("io.kuicksilver.ktor.client.WebSocketLifetime")

/**
 * The coroutines of one client WebSocket session (Ktor's `RawWebSocket` reader and writer, the engine's frame guards) run
 * in [context], under a job of their own rather than the call's, so that a Close the session queued is written even when
 * the call ends with a cancellation right after; and everything the session holds (its connection or stream, the pool
 * entry, the engine's in-flight count) is given back once, when the session ends ([invokeOnEnd]), not when the call does.
 *
 * Ktor's `HttpClient.webSocketSession()` ends its call that way every time: once the session sent its Close, its
 * outgoing channel is cancelled, the builder takes that cancellation for a failure and cancels the call. Under the call's
 * job the writer was cancelled with it, often before it wrote the Close the session had just queued, and the server saw
 * the connection end without one ("closed without close frame"): RFC 6455 section 7.1.2, an endpoint that starts the
 * closing handshake "MUST send a Close control frame". Here:
 *
 * - a call that ends in order waits for the session's coroutines as before (a child of the call joins [context]'s job),
 *   so `webSocket { }` still returns once the closing handshake is over;
 * - a call that ends with a cause after the session queued its own Close ([watch] sees it) leaves the session running
 *   until its coroutines end, within the close wait counted from that Close ([remainingCloseWaitMillis]): the Close goes
 *   out, behind the frames queued before it;
 * - a call that ends with a cause before that cancels the session at once, as before;
 * - the engine's cleanup after `client.close()` waits for the session's end (the engine's in-flight job of the call is
 *   held until every [invokeOnEnd] handler has run), so a lingering session is not cut by the pools closing under it.
 *
 * A lifetime made before code that can still fail or go again (a handshake answer that is refused, a request the server
 * did not process) is [abandon]ed there: nothing of it is left waiting.
 */
@OptIn(DelicateCoroutinesApi::class)
internal class WebSocketLifetime(
    private val data: HttpRequestData,
    callContext: CoroutineContext,
    private val closeWaitMillis: Long = WEBSOCKET_CLOSE_WAIT_MILLIS,
) {
    private val callJob: Job = callContext[Job] ?: throw IllegalStateException("a call without a Job")
    private val track: WebSocketCallTrack? = data.attributes.getOrNull(WebSocketCallTrackKey)
    private val events: EngineEvents? = track?.events

    /** The engine's in-flight job of the call stays incomplete until this completes, after the end handlers. */
    private val hold: CompletableJob? = track?.hold?.let { Job(it) }
    private val job = Job()
    private val ownClose = AtomicBoolean(false)
    private val ownCloseAt = AtomicReference<TimeMark?>(null)
    private val ended = AtomicBoolean(false)
    private val endHandlers = ArrayList<suspend (Throwable?) -> Unit>()
    private var endCause: Throwable? = null
    private val lock = SpinLock()

    /**
     * The session's context: the call's, with the session's own job. A coroutine of the session that fails ends the
     * session (the transport learns it through [invokeOnEnd], the application through the session's channels); the failure
     * itself goes to the engine's listener ([KuicksilverEventListener.webSocketFailed]) and its logger, not to the uncaught
     * exception handler (the session's job has no parent that would take it; on Kotlin/Native that ends the process).
     */
    val context: CoroutineContext =
        callContext.minusKey(Job) + job +
            CoroutineExceptionHandler { _, e ->
                val ev = events ?: return@CoroutineExceptionHandler
                ev.emit("webSocketFailed") { webSocketFailed(data, e) }
                runCatching {
                    if (ev.logger.isEnabled(LogLevel.Debug)) {
                        ev.logger.log(LogLevel.Debug, "a WebSocket session's coroutine failed", e)
                    }
                }
            }

    /** The session's own Close went to its outgoing channel (queued, maybe not written yet). */
    val ownCloseQueued: Boolean get() = ownClose.load()

    /**
     * What is left of the close wait: counted from the session's own Close, the whole wait while there is none yet. The
     * transports bound what they still wait for after the session (HTTP/2: the server's END_STREAM) by it, so the whole
     * close takes at most [closeWaitMillis] after the own Close.
     */
    fun remainingCloseWaitMillis(): Long {
        val at = ownCloseAt.load() ?: return closeWaitMillis
        return (closeWaitMillis - at.elapsedNow().inWholeMilliseconds).coerceAtLeast(0)
    }

    init {
        data.attributes.put(WebSocketLifetimeKey, this)
        // the call waits for the session as it did while the session ran under it: a call that ends in order ends once
        // the session's coroutines did; cancelled with the call, this child lets it end at once
        CoroutineScope(callContext + CoroutineName("kuicksilver-websocket-session")).launch(start = CoroutineStart.UNDISPATCHED) {
            job.join()
        }
        callJob.invokeOnCompletion { cause ->
            when {
                cause == null -> {}

                !ownClose.load() -> {
                    job.cancel(CancellationException("the call ended before the session's Close", cause))
                }

                // the call failed after the session's Close was queued: the Close goes out, within the close wait
                else -> {
                    GlobalScope.launch(
                        Dispatchers.Unconfined + CoroutineName("kuicksilver-websocket-close"),
                        start = CoroutineStart.ATOMIC,
                    ) {
                        var done = false
                        try {
                            done = withTimeoutOrNull(remainingCloseWaitMillis()) { job.join() } != null
                        } finally {
                            if (!done) job.cancel(CancellationException("the session's Close was not written within the close wait"))
                        }
                    }
                }
            }
            job.invokeOnCompletion { sessionCause ->
                end(
                    when {
                        sessionCause != null -> cause ?: sessionCause
                        cause == null || ownClose.load() -> null
                        else -> cause
                    },
                )
            }
        }
    }

    /**
     * [session] with its outgoing frames watched for the session's own Close (Ktor's session sends it through `outgoing`,
     * its `close()` through `send`), before the Close is queued behind the frames ahead of it; [onClose] runs then too.
     * Every send path of the channel is watched but `onSend`, a select clause, which cannot be wrapped without
     * kotlinx.coroutines' internal API (Ktor's sessions never select on it). Called once [session] was made in [context]:
     * from then on the session's job ends with the coroutines it started.
     */
    fun watch(
        session: WebSocketSession,
        onClose: () -> Unit = {},
    ): WebSocketSession {
        job.complete()
        return OwnCloseWatch(session) {
            if (ownClose.compareAndSet(false, true)) ownCloseAt.store(TimeSource.Monotonic.markNow())
            onClose()
        }
    }

    /**
     * Gives the lifetime up before a session was made in it ([watch] not called): the request failed or goes again. Its
     * coroutines are cancelled, the call no longer waits for it, and the end handlers run with [cause].
     */
    fun abandon(cause: Throwable) {
        if (data.attributes.getOrNull(WebSocketLifetimeKey) === this) data.attributes.remove(WebSocketLifetimeKey)
        job.cancel(CancellationException("the WebSocket was not opened", cause))
    }

    /**
     * Runs [handler] once, after both the call and the session's coroutines are over: with null when the session ended in
     * order (the call ended in order, or after the session's own Close, and the session's coroutines finished within the
     * close wait), else with the cause. The handlers run in order, each may suspend (bounded by its own waits); the
     * engine's in-flight job of the call completes after the last. One added after the end runs at once.
     */
    fun invokeOnEnd(handler: suspend (Throwable?) -> Unit) {
        val late =
            lock.withLock {
                if (ended.load()) {
                    true
                } else {
                    endHandlers += handler
                    false
                }
            }
        if (late) runHandlers(listOf(handler), endCause, completeHold = false)
    }

    private fun end(cause: Throwable?) {
        val handlers =
            lock.withLock {
                endCause = cause
                ended.store(true)
                endHandlers.toList().also { endHandlers.clear() }
            }
        runHandlers(handlers, cause, completeHold = true)
    }

    private fun runHandlers(
        handlers: List<suspend (Throwable?) -> Unit>,
        cause: Throwable?,
        completeHold: Boolean,
    ) {
        // at once on the completing thread up to a handler's first suspension; ATOMIC: the hold is released whatever happens.
        // Every handler runs, whatever an earlier one did (a cancellation included: the HTTP/3 pool entry is released
        // after the stream's end); all of them within one close wait, so none can keep the engine's cleanup waiting
        GlobalScope.launch(Dispatchers.Unconfined + CoroutineName("kuicksilver-websocket-end"), start = CoroutineStart.ATOMIC) {
            try {
                var left = handlers
                withTimeoutOrNull(closeWaitMillis) {
                    while (left.isNotEmpty()) {
                        val h = left.first()
                        left = left.drop(1)
                        try {
                            h(cause)
                        } catch (e: Throwable) {
                            reportEndFailure(e)
                        }
                    }
                }
                // the handlers the bound cut off still run up to their first suspension (a release, a reset), then are
                // cancelled there (their finally blocks run)
                for (h in left) {
                    GlobalScope
                        .launch(
                            Dispatchers.Unconfined +
                                CoroutineExceptionHandler {
                                    _,
                                    e,
                                    ->
                                    reportEndFailure(e)
                                },
                            start = CoroutineStart.UNDISPATCHED,
                        ) {
                            h(cause)
                        }.cancel()
                }
            } finally {
                if (completeHold) hold?.complete()
            }
        }
    }

    private fun reportEndFailure(e: Throwable) {
        runCatching {
            val ev = events
            if (ev != null && ev.logger.isEnabled(LogLevel.Warn)) ev.logger.log(LogLevel.Warn, "a WebSocket session's end failed", e)
        }
    }
}

/** [raw] with [onClose] run when the session sends its own Close (see [WebSocketLifetime.watch]). */
private class OwnCloseWatch(
    private val raw: WebSocketSession,
    private val onClose: () -> Unit,
) : WebSocketSession by raw {
    override val outgoing: SendChannel<Frame> =
        object : SendChannel<Frame> by raw.outgoing {
            override suspend fun send(element: Frame) {
                if (element is Frame.Close) onClose()
                raw.outgoing.send(element)
            }

            override fun trySend(element: Frame): ChannelResult<Unit> {
                if (element is Frame.Close) onClose()
                return raw.outgoing.trySend(element)
            }

            @Deprecated("Use trySend", level = DeprecationLevel.ERROR)
            @Suppress("DEPRECATION_ERROR", "OVERRIDE_DEPRECATION")
            override fun offer(element: Frame): Boolean {
                if (element is Frame.Close) onClose()
                return raw.outgoing.offer(element)
            }
        }

    override suspend fun send(frame: Frame) {
        outgoing.send(frame)
    }
}
