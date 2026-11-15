// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.client

import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketSession
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.ChannelResult
import kotlinx.coroutines.channels.SendChannel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.coroutines.CoroutineContext

/**
 * How long a client WebSocket whose call ended after the session sent its own Close keeps the session going for that
 * Close to be written, and over HTTP/2 how long a session that ended in order waits for its last frames and the server's
 * END_STREAM (RFC 6455 section 7.1.1: the client "MAY close the connection at any time after sending and receiving a
 * Close message, e.g., if it has not received a TCP Close from the server in a reasonable time period").
 */
internal const val WEBSOCKET_CLOSE_WAIT_MILLIS: Long = 5_000

/**
 * The coroutines of one client WebSocket session (Ktor's `RawWebSocket` reader and writer, the engine's frame guards) run
 * in [context], under a job of their own rather than the call's, so that a Close the session queued is written even when
 * the call ends with a cancellation right after.
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
 *   until its coroutines end, at most [closeWaitMillis] more: the Close goes out, behind the frames queued before it;
 * - a call that ends with a cause before that cancels the session at once, as before.
 *
 * [invokeOnEnd] tells the transport when the session is over and how: in order or not.
 */
@OptIn(DelicateCoroutinesApi::class)
internal class WebSocketLifetime(
    callContext: CoroutineContext,
    private val closeWaitMillis: Long = WEBSOCKET_CLOSE_WAIT_MILLIS,
) {
    private val callJob: Job = callContext[Job] ?: throw IllegalStateException("a call without a Job")
    private val job = Job()
    private val ownClose = AtomicBoolean(false)

    /**
     * The session's context: the call's, with the session's own job. A coroutine of the session that fails cancels the
     * session, and the transport learns it through [invokeOnEnd] (the application through the session's channels); with
     * no handler of the call's to take the failure, it is taken here rather than reported as uncaught, since the session's
     * job has no parent that would.
     */
    val context: CoroutineContext =
        callContext.minusKey(Job) + job + (callContext[CoroutineExceptionHandler] ?: CoroutineExceptionHandler { _, _ -> })

    /** The session's own Close went to its outgoing channel (queued, maybe not written yet). */
    val ownCloseQueued: Boolean get() = ownClose.load()

    init {
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
                        context.minusKey(Job) + CoroutineName("kuicksilver-websocket-close"),
                        start = CoroutineStart.ATOMIC,
                    ) {
                        var ended = false
                        try {
                            ended = withTimeoutOrNull(closeWaitMillis) { job.join() } != null
                        } finally {
                            if (!ended) job.cancel(CancellationException("the session's Close was not written within the close wait"))
                        }
                    }
                }
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
            ownClose.store(true)
            onClose()
        }
    }

    /**
     * Runs [handler] once, when both the call and the session's coroutines are over: with null when the session ended in
     * order (the call ended in order, or after the session's own Close, and the session's coroutines finished within the
     * close wait), else with the cause. Must not block.
     */
    fun invokeOnEnd(handler: (Throwable?) -> Unit) {
        callJob.invokeOnCompletion { callCause ->
            job.invokeOnCompletion { sessionCause ->
                handler(
                    when {
                        sessionCause != null -> callCause ?: sessionCause
                        callCause == null || ownClose.load() -> null
                        else -> callCause
                    },
                )
            }
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
