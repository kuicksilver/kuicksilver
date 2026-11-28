// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.HttpRequestData
import io.ktor.util.AttributeKey
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketSession
import io.ktor.websocket.readReason
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
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicReference
import kotlin.coroutines.CoroutineContext
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.TimeMark
import kotlin.time.TimeSource

/**
 * The close wait of a client WebSocket (`webSocketCloseWaitMillis`), used for both timers of the closing handshake
 * ([WebSocketLifetime]): T1, from the session's own Close, for the server's Close (and for the session to write its own);
 * T2, from the end of the session (both Closes sent and received), for the server's close of the transport: its TCP FIN
 * (with close_notify over TLS), its END_STREAM over HTTP/2, its FIN over HTTP/3. RFC 6455 section 5.5.1: "the client
 * SHOULD wait for the server to close the connection but MAY close the connection at any time after sending and receiving
 * a Close message, e.g., if it has not received a TCP Close from the server in a reasonable time period".
 *
 * While the client is open a session whose server stays silent waits out these bounds: three close waits (15 s) after
 * its own Close at most. T1 for the server's Close; T2 for its close of the transport; over HTTP/2 and HTTP/3 one more for
 * its END_STREAM or FIN after the client's own, before the stream is reset. The end handlers are cut off two close waits
 * after the session ended, whatever they still wait for.
 *
 * The engine's `close()` (`client.close()`) ends every wait for the server at once, in the sessions closing then and in
 * those that close later ([WebSocketLifetime.hurry]): the client "MAY close the connection at any time after sending and
 * receiving a Close message" (RFC 6455 section 5.5.1), and before the server's Close the client's own close of the
 * connection is the abnormal case section 7.1.1 lets a client "initiate". What the client still sends is not cut: its own
 * Close goes out first (section 7.1.2: the endpoint that starts the closing handshake "MUST send a Close control frame"),
 * then its side of the transport ends cleanly (close_notify and a FIN, END_STREAM, a FIN), no reset before that clean end.
 * The server's own end is still waited for, [WEBSOCKET_HURRY_GRACE_MILLIS] (1 s) at most: until it ends its side, our
 * Close may be unread, and the reset or the connection's close that follows would discard it; over HTTP/2 and HTTP/3 a
 * Close the server never answered keeps the rest of its close wait instead ([WebSocketLifetime.serverWithin]). A session
 * whose Close cannot be written (a server that reads slowly or not at all) keeps its close wait: the engine's close does
 * not cut a writer short.
 */
internal const val WEBSOCKET_CLOSE_WAIT_MILLIS: Long = 5_000

/**
 * How long, once the engine was closed ([WebSocketLifetime.hurry]), a session still waits for the server's end of the
 * transport (its FIN, END_STREAM or FIN) after its own Close went out: until the server ends its side, nothing says it read
 * that Close (a Close it never answered, our reply to its Close, or two Closes that crossed), and what follows (over
 * HTTP/2 a reset of the stream, over HTTP/3 the connection's close, over HTTP/1.1 a reset the closed socket answers the
 * server's next bytes with) would discard it unread. A server that reads ends within it, and the order stays the
 * server's first; a silent one costs this, not the close waits.
 */
internal const val WEBSOCKET_HURRY_GRACE_MILLIS: Long = 1_000

/**
 * What the engine gives each call for a WebSocket session that may outlive it: [hold] is the engine's in-flight job of the
 * call (the engine's cleanup after `close()` waits for it), [events] the engine's listener.
 */
internal class WebSocketCallTrack(
    val hold: Job,
    val events: EngineEvents,
    /** The engine's sessions, which its `close()` hurries ([WebSocketSessions.hurryAll]); null outside an engine (tests). */
    val sessions: WebSocketSessions? = null,
)

/**
 * The engine's WebSocket sessions that have not ended yet: its `close()` ends their waits for the server at once
 * ([WebSocketLifetime.hurry]), and a session that starts after that is hurried as it starts.
 */
internal class WebSocketSessions {
    private val lock = SpinLock()
    private val live = LinkedHashSet<WebSocketLifetime>()
    private var closed = false

    /** Adds [lifetime]; false once the engine was closed (it is not added, and its waits are to be cut at once). */
    fun add(lifetime: WebSocketLifetime): Boolean =
        lock.withLock {
            if (!closed) live += lifetime
            !closed
        }

    fun remove(lifetime: WebSocketLifetime) {
        lock.withLock { live -= lifetime }
    }

    /** The engine was closed: every live session's waits for the server end now, and so do those of sessions added later. */
    fun hurryAll() {
        val all =
            lock.withLock {
                closed = true
                live.toList().also { live.clear() }
            }
        for (l in all) l.hurry()
    }

    /** The grace each session gives the server after its own end once the engine was closed (tests shorten it). */
    @kotlin.concurrent.Volatile var hurryGraceMillis: Long = WEBSOCKET_HURRY_GRACE_MILLIS

    /** The sessions not ended yet (tests). */
    val size: Int get() = lock.withLock { live.size }
}

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
 *   until its coroutines end: the Close goes out, behind the frames queued before it;
 * - once the session queued its own Close, its coroutines have the close wait (T1, counted from that Close,
 *   [remainingCloseWaitMillis]) to write it and to see the server's Close; a session still running then (a server that
 *   never answers, or never takes the Close) is cancelled, whichever way its call ended (RFC 6455 section 7.1.1: the
 *   client may close "in abnormal cases"), and its transport is ended at once (reset when its writer had not finished:
 *   what it had queued never leaves after the close wait);
 * - a call that ends with a cause before that closes the session the same way (RFC 6455 sections 7.1.7 and 7.3: an
 *   established connection ends with the closing handshake): one Close, 1001 Going Away, or the application's own code
 *   when it sends one meanwhile (Ktor's own answer to the cancellation, a Close 1000 without a reason, goes out as 1001),
 *   never a second Close; a call that ends before the session was made (the handshake) cancels it at once;
 * - the engine's cleanup after `client.close()` waits for the session's end (the engine's in-flight job of the call is
 *   held until every [invokeOnEnd] handler has run), so a lingering session is not cut by the pools closing under it;
 *   the engine's `close()` ends every wait for the server at once ([hurry]), so that end comes as soon as the session's
 *   own Close and the clean end of its transport went out, never after the close waits.
 *
 * The transport's own close comes after the session ([invokeOnEnd]): Ktor's writer ends its channel right after its Close
 * (a TCP half-close, close_notify, END_STREAM or FIN at once), so the engines hand it a channel whose end only flushes
 * ([HeldTransportEnd]), and end the transport themselves in the order RFC 6455 section 7.1.1 wants of a client: the
 * server closes first ("The underlying TCP connection, in most normal cases, SHOULD be closed first by the server"), and
 * the client "SHOULD wait for a TCP Close from the server", here at most the close wait counted from the session's end (T2,
 * [remainingTransportWaitMillis]), then closes its side cleanly. The end handlers have two close waits in all: T2, and as
 * much again for what a transport still waits for after its own close (HTTP/2 and HTTP/3: the server's end of the stream
 * before the stream is reset).
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

    /** The call's context without its job: its dispatcher's clock runs T1. */
    private val callTimers: CoroutineContext = callContext.minusKey(Job)
    private val track: WebSocketCallTrack? = data.attributes.getOrNull(WebSocketCallTrackKey)
    private val events: EngineEvents? = track?.events

    /** The engine's in-flight job of the call stays incomplete until this completes, after the end handlers. */
    private val hold: CompletableJob? = track?.hold?.let { Job(it) }
    private val job = Job()
    private val ownClose = AtomicBoolean(false)
    private val ownCloseAt = AtomicReference<TimeMark?>(null)
    private val endedAt = AtomicReference<TimeMark?>(null)
    private val ended = AtomicBoolean(false)
    private val endHandlers = ArrayList<suspend (Throwable?) -> Unit>()

    /** Completed by [hurry]: the engine was closed, the waits for the server end at once. */
    private val hurried: CompletableJob = Job()

    /**
     * Completed once the session's writer ended its channel in order ([writerEnded]): its own Close, if any, went to the
     * transport whole. A writer that failed or was cancelled never completes it.
     */
    private val writerEnd: CompletableJob = Job()

    /** The grace after this side's own end once the engine was closed: the engine's (a test may shorten it), or the default. */
    private val hurryGraceMillis: Long get() = track?.sessions?.hurryGraceMillis ?: WEBSOCKET_HURRY_GRACE_MILLIS

    /** T1 ended because the engine was closed, after the session's own Close was written ([hurry]). */
    private val hurriedOut = AtomicBoolean(false)

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

    /**
     * The session was cut at the end of the close wait (T1): what it still had queued must not leave after it, so the
     * transport is reset rather than closed in order behind it.
     */
    val cutByCloseWait: Boolean get() = cut.load()
    private val cut = AtomicBoolean(false)

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

    /**
     * What is left of T2, the wait for the server's close of the transport (its TCP FIN, END_STREAM or FIN): the close
     * wait counted from the session's end, which in an orderly session is when both Closes were sent and received; the
     * whole wait before the session ended. The transports close their own side when it is over, or as soon as the server
     * closed its side first. Once the engine was closed ([hurry]) the waits are bounded by the grace instead
     * ([serverWithin]).
     */
    fun remainingTransportWaitMillis(): Long {
        val at = endedAt.load() ?: return closeWaitMillis
        return (closeWaitMillis - at.elapsedNow().inWholeMilliseconds).coerceAtLeast(0)
    }

    /**
     * How long the transports wait for what this side still sends after the session (HTTP/2: its last DATA and
     * END_STREAM): the close wait; once the engine was closed ([hurry]), what is left of T1 (from the session's own Close),
     * at least the grace, so the engine's close never holds a session past its T1 for its own sending.
     */
    fun ownEndBoundMillis(): Long = if (hurried.isCompleted) maxOf(remainingCloseWaitMillis(), hurryGraceMillis) else closeWaitMillis

    /** The close wait itself (both T1 and T2). */
    val closeWait: Long get() = closeWaitMillis

    /** Whether the engine was closed ([hurry]). */
    val isHurried: Boolean get() = hurried.isCompleted

    /**
     * The engine was closed (`client.close()`): every wait for the server ends now, and those that come later are not
     * waited at all. In T1 the session still writes its own Close (RFC 6455 section 7.1.2: "MUST send a Close control
     * frame"), within what is left of the close wait, and is ended once it did, without the server's Close (section 7.1.1:
     * the abnormal case a client may close the connection in); its transport then ends as after an orderly session. T2,
     * which section 5.5.1 lets a client cut "at any time after sending and receiving a Close message", and the wait after
     * this side's own end become [WEBSOCKET_HURRY_GRACE_MILLIS] at most, for the server to read the Close and end its side.
     * A session that has not sent its own Close yet goes on (a call in flight outlives `close()`), and once it sends one
     * it is not waited for either.
     */
    fun hurry() {
        hurried.complete()
    }

    /** The session's writer ended its channel to the transport in order ([HeldTransportEnd]): its last frame was handed on. */
    fun writerEnded() {
        writerEnd.complete()
    }

    /** Whether the session's writer ended its channel in order ([writerEnded]; tests, in a failure's message). */
    val writerEndedForTest: Boolean get() = writerEnd.isCompleted

    /** The state a test reports when a session did not end as it should: what the lifetime knows of its end. */
    fun stateForTest(): String =
        "cut=$cutByCloseWait hurried=$isHurried writerEnded=${writerEnd.isCompleted} ownCloseQueued=$ownCloseQueued " +
            "ended=${ended.load()} endCause=$endCause"

    /**
     * [block]'s result within [deadline] (as [io.kuicksilver.tls.completedWithin]: a result that came is never dropped),
     * or null when the deadline passed first. For the waits for the server's end of the transport: before this side's own
     * end ([afterOwnEnd] false: HTTP/2 and HTTP/3 hold their END_STREAM or FIN until the server's, T2) and after it (and
     * HTTP/1.1's wait for the server's close, which comes before this side's). Once the engine was closed ([hurry]) a
     * wait before this side's end stops, so that end goes at once. A wait after it is bounded by
     * [WEBSOCKET_HURRY_GRACE_MILLIS], counted from the engine's close or from now when that came first: as long as the
     * server has not ended its side, the session's Close may still be unread there. Over a transport whose end
     * [discardsUnread] (HTTP/2: the stream's reset; HTTP/3: the connection's close), a session ended before the server
     * answered its Close keeps what is left of its close wait (T1, from its own Close) instead, at least the grace: the
     * server may still be reading what was sent, that Close among it, and nothing but its own end says it read it.
     */
    suspend fun <T : Any> serverWithin(
        deadline: kotlin.time.Duration,
        afterOwnEnd: Boolean,
        discardsUnread: Boolean = false,
        block: suspend () -> T,
    ): T? {
        if (!afterOwnEnd) return io.kuicksilver.tls.completedWithinUnless(hurried, deadline, block)
        if (discardsUnread && hurriedOut.load()) {
            val left = maxOf(remainingCloseWaitMillis(), hurryGraceMillis).milliseconds
            return io.kuicksilver.tls.completedWithin(minOf(deadline, left), block)
        }
        return kotlinx.coroutines.coroutineScope {
            val graceOver =
                launch {
                    hurried.join()
                    kotlinx.coroutines.delay(hurryGraceMillis)
                }
            try {
                io.kuicksilver.tls.completedWithinUnless(graceOver, deadline, block)
            } finally {
                graceOver.cancel()
            }
        }
    }

    init {
        data.attributes.put(WebSocketLifetimeKey, this)
        // a session that starts after the engine's close() waits for no server either
        if (track?.sessions?.add(this) == false) hurried.complete()
        // the call waits for the session as it did while the session ran under it: a call that ends in order ends once
        // the session's coroutines did; cancelled with the call, this child lets it end at once
        CoroutineScope(callContext + CoroutineName("kuicksilver-websocket-session")).launch(start = CoroutineStart.UNDISPATCHED) {
            job.join()
        }
        callJob.invokeOnCompletion { cause ->
            // the call failed after the session's Close was queued: the Close goes out, within the close wait (T1, [watch]).
            // One that failed before: an established session still closes with a Close frame (RFC 6455 sections 7.1.7 and
            // 7.3), 1001 Going Away, within the close wait; one not established yet (no [watch]) is cancelled at once
            if (cause != null && !ownClose.load()) closeForEndedCall(cause)
            job.invokeOnCompletion { sessionCause ->
                end(
                    when {
                        // ended at the engine's close once its own Close was written: the transport ends as in order
                        sessionCause != null && hurriedOut.load() -> null

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
        ownCloseHook = onClose
        watched.store(session)
        job.complete()
        return OwnCloseWatch(session, ::claimClose)
    }

    /** The session as [watch] got it (its own outgoing channel, under the watch); null before. */
    private val watched = AtomicReference<WebSocketSession?>(null)

    @kotlin.concurrent.Volatile private var ownCloseHook: () -> Unit = {}

    /**
     * The session's one Close (RFC 6455 section 5.5.1: after it nothing more is sent), as [close] goes out: null for a
     * Close after the first, which is not sent. A Close sent once the call is cancelled whose code is 1000 without a reason
     * is Ktor's own answer to that cancellation (its session closes its outgoing channel, and its processor sends a normal
     * Close): it goes out as 1001 Going Away, as the session's end through a cancelled call is (section 7.4.1); any other
     * code, the application's own (a `close()` in a `finally`), is sent as it is.
     */
    private fun claimClose(close: Frame.Close): Frame.Close? {
        if (!ownClose.compareAndSet(false, true)) return null
        ownCloseAt.store(TimeSource.Monotonic.markNow())
        boundByCloseWait()
        ownCloseHook()
        val reason = close.readReason()
        val normalWithoutReason = reason != null && reason.code == CloseReason.Codes.NORMAL.code && reason.message.isEmpty()
        return if (callJob.isCancelled && normalWithoutReason) Frame.Close(CloseReason(CloseReason.Codes.GOING_AWAY, "")) else close
    }

    /**
     * The call ended with [cause] before the session queued its own Close. An established session ([watch]) sends one,
     * 1001 Going Away, and has the close wait (T1) for it and the server's, as after any own Close; the transport then
     * ends in order. A Close the session (Ktor's, or the application's) sent meanwhile is that one. A session not
     * established yet, or whose outgoing channel no longer takes the Close, is cancelled at once.
     */
    private fun closeForEndedCall(cause: Throwable) {
        val session = watched.load()
        if (session != null) {
            val close = claimClose(Frame.Close(CloseReason(CloseReason.Codes.GOING_AWAY, ""))) ?: return // one is queued
            if (session.outgoing.trySend(close).isSuccess) return
        }
        job.cancel(CancellationException("the call ended before the session's Close", cause))
    }

    /**
     * T1: the session's coroutines end within the close wait from its own Close (its Close written, the server's read),
     * or are cancelled then, whichever way the call ends; the end handlers then get that cancellation and end the
     * transport at once. Once the engine was closed ([hurry]) the server's Close is not waited for: the session is ended
     * as soon as its writer ended in order (its Close written), and its transport ends as after an orderly session. A
     * writer that has not written its Close yet (a server that reads slowly, or not at all: flow control, a full send
     * buffer) keeps the close wait it has: the engine's close does not cut it short.
     */
    private fun boundByCloseWait() {
        // on the call's dispatcher (its clock), outside its job: the call may have ended already
        GlobalScope.launch(callTimers + CoroutineName("kuicksilver-websocket-close"), start = CoroutineStart.ATOMIC) {
            // true: the session ended; false: the engine was closed and the session's writer ended; null: the close wait passed
            var outcome: Boolean? = null
            try {
                outcome =
                    withTimeoutOrNull(remainingCloseWaitMillis()) {
                        val ended =
                            select {
                                job.onJoin { true }
                                hurried.onJoin { false }
                            }
                        ended ||
                            select {
                                job.onJoin { true }
                                writerEnd.onJoin { false }
                            }
                    }
            } finally {
                when (outcome) {
                    true -> {}

                    false -> {
                        hurriedOut.store(true)
                        job.cancel(CancellationException("the engine was closed: the server's Close is not waited for"))
                    }

                    null -> {
                        cut.store(true)
                        job.cancel(
                            CancellationException("no Close from the server (or the own Close not written) within the close wait"),
                        )
                    }
                }
            }
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
     * close wait), else with the cause. The handlers run in order, each may suspend: all of them within two close waits
     * (T2 and what a transport waits for after its own close), cancelled past that; the engine's in-flight job of the
     * call completes after the last. One added after the end runs at once.
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
        endedAt.store(TimeSource.Monotonic.markNow())
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
        // after the stream's end); all of them within two close waits (T2, then a transport's wait after its own close),
        // so none can keep the engine's cleanup waiting
        GlobalScope.launch(Dispatchers.Unconfined + CoroutineName("kuicksilver-websocket-end"), start = CoroutineStart.ATOMIC) {
            try {
                var left = handlers
                withTimeoutOrNull(2 * closeWaitMillis) {
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
                if (completeHold) {
                    track?.sessions?.remove(this@WebSocketLifetime)
                    hold?.complete()
                }
            }
        }
    }

    private fun reportEndFailure(e: Throwable) {
        runCatching {
            val ev = events
            if (ev != null && ev.logger.isEnabled(LogLevel.Warn)) ev.logger.log(LogLevel.Warn, "a WebSocket session's end failed", e)
            // the whole stack at Debug only: an end handler that failed left its transport's end undone, and the stack says
            // where. It is not built at Warn: the end handlers' bound (two close waits) ends a handler with a cancellation
            // that lands here too, and on Kotlin/Native formatting a stack symbolizes it, which under load took long
            // enough to delay the engine's cleanup past the leak sentinel's 1.5 s (ClientH2WebSocketTest)
            if (ev != null && ev.logger.isEnabled(LogLevel.Debug)) {
                // the stack is in the message: no cause, which a logger that prints stacks would print a second time
                ev.logger.log(LogLevel.Debug, "a WebSocket session's end failed: ${e.stackTraceToString()}", null)
            }
        }
    }
}

/**
 * [raw] with every Close the session sends passed through [onClose] (see [WebSocketLifetime.watch]): what it gives is sent
 * in its place, and a Close it refuses (null) is dropped, as if sent.
 */
private class OwnCloseWatch(
    private val raw: WebSocketSession,
    private val onClose: (Frame.Close) -> Frame.Close?,
) : WebSocketSession by raw {
    override val outgoing: SendChannel<Frame> =
        object : SendChannel<Frame> by raw.outgoing {
            override suspend fun send(element: Frame) {
                raw.outgoing.send(if (element is Frame.Close) onClose(element) ?: return else element)
            }

            override fun trySend(element: Frame): ChannelResult<Unit> {
                // dropped: the success a channel that takes everything gives (ChannelResult's constructors are internal)
                val frame =
                    if (element is Frame.Close) {
                        onClose(element) ?: return kotlinx.coroutines.channels
                            .Channel<Frame>(1)
                            .trySend(element)
                    } else {
                        element
                    }
                return raw.outgoing.trySend(frame)
            }

            @Deprecated("Use trySend", level = DeprecationLevel.ERROR)
            @Suppress("DEPRECATION_ERROR", "OVERRIDE_DEPRECATION")
            override fun offer(element: Frame): Boolean {
                val frame = if (element is Frame.Close) onClose(element) ?: return true else element
                return raw.outgoing.offer(frame)
            }
        }

    override suspend fun send(frame: Frame) {
        outgoing.send(frame)
    }
}

/**
 * The transport channel under a client session's output guard, whose [flushAndClose] only flushes: Ktor's WebSocket writer
 * always ends its channel right after its Close, which on the transport would close the client's side at once (a TCP
 * half-close, close_notify, END_STREAM, a FIN), before the server closed its side. RFC 6455 section 7.1.1: the server
 * "SHOULD initiate a TCP Close immediately, and when a client is instructed to do the same, it SHOULD wait for a TCP Close
 * from the server". The engine ends [out] itself once the session ended ([WebSocketLifetime.invokeOnEnd]). [endRequested]
 * says the writer ended in order (its last frames flushed); [cancel] still reaches [out] at once.
 */
@OptIn(io.ktor.utils.io.InternalAPI::class)
internal class HeldTransportEnd(
    private val out: io.ktor.utils.io.ByteWriteChannel,
    /** Told when the writer ended this channel in order ([WebSocketLifetime.writerEnded]). */
    private val lifetime: WebSocketLifetime? = null,
    /**
     * Waits, at the writer's end, until what was handed to [out] ([handed] bytes) is out of reach of the end that follows
     * the session: [out]'s flush may return with bytes still queued in front of the transport, and the writer has not
     * written its Close until they went. Over HTTP/2 that is the stream's lead after the session's own Close (the stream
     * took them). Over HTTP/1.1 it is the socket's channel, whose flush returns once it holds less than its capacity (the
     * kernel took them). Over HTTP/3 it is the stream's channel and QUIC's send buffer, which takes data beyond the
     * server's credit and which the connection's close discards (the server acknowledged them). Null: [out]'s flush says
     * it (tests).
     */
    private val delivered: (suspend (handed: Long) -> Unit)? = null,
) : io.ktor.utils.io.ByteWriteChannel {
    @kotlin.concurrent.Volatile var endRequested: Boolean = false
        private set

    /**
     * The bytes handed to [out] so far: every write reaches [out]'s write buffer through this channel's [writeBuffer] and
     * leaves it with a [flush] of this channel (ktor-io's writes flush through their receiver), counted there. An engine
     * compares it with what its transport took to tell whether anything still waits in front of the transport.
     */
    @kotlin.concurrent.Volatile var handed: Long = 0
        private set

    override val isClosedForWrite: Boolean get() = out.isClosedForWrite

    override val closedCause: Throwable? get() = out.closedCause

    @io.ktor.utils.io.InternalAPI
    override val writeBuffer: kotlinx.io.Sink get() = out.writeBuffer

    override suspend fun flush() {
        count()
        out.flush()
    }

    override suspend fun flushAndClose() {
        count()
        out.flush()
        delivered?.invoke(handed)
        endRequested = true
        // in order only: a transport that failed under the writer did not take its Close
        if (out.closedCause == null) lifetime?.writerEnded()
    }

    private fun count() {
        // a closed [out] has no write buffer: its flush below fails as it would have
        handed += runCatching { (out.writeBuffer as? kotlinx.io.Buffer)?.size }.getOrNull() ?: 0
    }

    override fun cancel(cause: Throwable?) {
        // the frame guard's reset of a stream its writer cut inside a frame: the engine ends the transport after the session
        // (a reset, from webSocketTransportEnd), not the output under it now (over TLS a failed output would send an alert
        // and a FIN before that reset)
        @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
        if (cause is io.kuicksilver.ktor.network.WebSocketFrameCutException) return
        out.cancel(cause)
    }
}
