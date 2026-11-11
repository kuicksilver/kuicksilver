// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class, ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.http2.runtime

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.core.H2ConnectionCore
import io.kuicksilver.http2.core.H2ConnectionUnusable
import io.kuicksilver.http2.core.H2Event
import io.kuicksilver.http2.core.H2HeaderListTooLarge
import io.kuicksilver.http2.core.H2StreamLimit
import io.kuicksilver.http2.core.Role
import io.kuicksilver.http2.message.H2Messages
import io.kuicksilver.http2.message.MalformedMessage
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.time.Duration.Companion.seconds

/** A lock for the short, non-suspending sections around the core: it is also taken from completion handlers. */
internal class SpinLock {
    @PublishedApi internal val held: AtomicInt = AtomicInt(0)

    inline fun <T> withLock(block: () -> T): T {
        while (!held.compareAndSet(0, 1)) {
            // the holder runs one core call and leaves; nothing in a section suspends or blocks
        }
        try {
            return block()
        } finally {
            held.store(0)
        }
    }
}

/** One stream as the runtime sees it; its mutable state is guarded by the connection's lock. */
internal class StreamRt(
    val conn: H2Runtime,
    val id: Int,
    /** A response to a HEAD request, which has no content whatever its content-length says (RFC 9110 section 6.4.1). */
    private val headRequest: Boolean,
    /**
     * A client stream opened before the server's preface (its SETTINGS, RFC 9113 section 3.4) arrived, under the initial
     * values of section 6.5.2: SETTINGS_MAX_CONCURRENT_STREAMS was not known yet.
     */
    val beforePeerSettings: Boolean = false,
) {
    /** Content delivered by the core and not yet pulled by [body]. */
    val chunks = ArrayDeque<ByteArray>()

    /** The peer's END_STREAM arrived and the message passed its checks: [chunks] hold the rest of the content. */
    var remoteEnded = false

    /** Our END_STREAM is queued (or our side ended otherwise: the peer stopped it after a complete response). */
    var localEnded = false

    /** Why the stream failed; the body and the sender throw it. */
    var failure: Throwable? = null

    /** The final field section arrived (on a client: the response head; on a server: the request head). */
    var headReceived = false

    var contentLength = -1L
    var received = 0L
    var noContent = false
    var released = false
    var trailers: List<Pair<String, String>>? = null

    /** Completed with [failure] when the stream fails (a server's engine cancels the request's handler on it). */
    val failed = CompletableDeferred<Throwable>()

    /** Wakes the body's reader. */
    val readable = Channel<Unit>(Channel.CONFLATED)

    /** Wakes the request body's sender: window available, or the stream failed. */
    val writable = Channel<Unit>(Channel.CONFLATED)

    /** The final response (client). */
    val head = CompletableDeferred<H2ResponseHead>()

    /** An interim (1xx) or the final response arrived: an `Expect: 100-continue` body may go (RFC 9110 section 10.1.1). */
    val answered = CompletableDeferred<Unit>()

    val body = H2BodyChannel(this)

    fun responseHasNoContent(status: Int): Boolean = headRequest || status == 204 || status == 304
}

/**
 * The coroutine driver of one [H2ConnectionCore] over a byte stream (ADR-0017, ADR-0004): one coroutine reads the
 * transport into the core, one writes what the core polls, one runs its timers and the optional PING interval. Every core
 * call runs under [lock] and never suspends; the core's events are dispatched in order, one dispatcher at a time, outside
 * the lock. The driver's contract with the core holds here: [H2ConnectionCore.consumed] as the application pulls the
 * content, [H2ConnectionCore.release] for every stream, `poll` and `onTimeout` on [clock].
 */
internal class H2Runtime(
    role: Role,
    val settings: Http2Settings,
    private val input: ByteReadChannel,
    private val output: ByteWriteChannel,
    parent: CoroutineScope,
    /** Monotonic nanoseconds. */
    val clock: () -> Long,
    /** PING period, nanoseconds; [Long.MAX_VALUE] for none. A PING unanswered when the next is due ends the connection. */
    private val pingIntervalNanos: Long,
    private val closeTransport: () -> Unit,
    /** Capacity or usability changed: a stream was released, the peer's limits or a GOAWAY arrived, the connection ended. */
    private val onChange: () -> Unit,
    /** A server's new request stream, its request already validated. */
    private val onRequest: ((StreamRt, io.kuicksilver.http2.message.H2Request) -> Unit)? = null,
    /** A server's fields for the responses the runtime makes itself (the 431): the engine's `date`, say. */
    private val ownResponseFields: () -> List<Pair<String, String>> = { emptyList() },
    /**
     * The code of the connection error (RFC 9113 section 5.4.1) a failure of [input] stands for, when the transport reports
     * something the protocol makes one (a TLS 1.2 renegotiation, section 9.2.1: PROTOCOL_ERROR); null: the connection was lost.
     */
    private val connectionErrorOf: (Throwable) -> Http2ErrorCode? = { null },
    /**
     * Ends the transport in order once the protocol is over and everything was written (the last GOAWAY flushed into
     * [output]): the transport's own close (TLS close_notify) goes after those bytes, bounded by its owner. Null:
     * [closeTransport]. A transport that failed or was lost is always closed with [closeTransport].
     */
    private val closeTransportGracefully: (() -> Unit)? = null,
) {
    private val client = role == Role.CLIENT
    val lock = SpinLock()
    val core = H2ConnectionCore(role, settings, clock())
    private val streams = HashMap<Int, StreamRt>()
    private val pending = ArrayDeque<H2Event>()
    private var dispatching = false
    private val kick = Channel<Unit>(Channel.CONFLATED)
    private val timerKick = Channel<Unit>(Channel.CONFLATED)

    /**
     * Counts what the writer handed to the transport, and failed streams: an `endStream` that waits for its frame's
     * predecessor wakes on either (a stream reset meanwhile would leave the writer nothing to write).
     */
    private val written = MutableStateFlow(0L)

    private val job = SupervisorJob(parent.coroutineContext[Job])
    private val scope = CoroutineScope(parent.coroutineContext + job)

    /** Completed by the peer's first SETTINGS (its preface, RFC 9113 section 3.4); failed when the connection ends first. */
    val prefaceReceived = CompletableDeferred<Unit>()

    /** The peer's preface (its first SETTINGS) arrived. */
    val peerPrefaceReceived: Boolean get() = lock.withLock { core.peerPrefaceReceived }

    /** The connection ended because the peer's preface did not arrive by the deadline of [expectPeerPrefaceWithin]. */
    val peerPrefaceMissed: Boolean get() = lock.withLock { core.peerPrefaceMissed }

    /** Ends the connection with SETTINGS_TIMEOUT unless the peer's preface arrives within [nanos] from now (the core's timer). */
    fun expectPeerPrefaceWithin(nanos: Long) {
        if (nanos == Long.MAX_VALUE) return
        val now = clock()
        withCore { expectPeerPrefaceBy(if (now > Long.MAX_VALUE - nanos) Long.MAX_VALUE else now + nanos) }
    }

    /** Completed when the connection is over, with nothing left to write. */
    val closed = CompletableDeferred<Unit>()

    /** Completed when the protocol ended ([closeCause] is set), possibly with frames still to write ([closed] follows). */
    val ended = CompletableDeferred<Unit>()

    /** The connection ended because the peer broke a flood limit (we sent ENHANCE_YOUR_CALM; not for a slow field block). */
    @Volatile var endedByFlood: Boolean = false
        private set

    @Volatile var closeCause: Throwable? = null
        private set

    @Volatile var goAwayReceived: Boolean = false
        private set

    /** The error code of the peer's GOAWAY, once one arrived. */
    @Volatile var goAwayCode: Http2ErrorCode? = null
        private set

    @Volatile private var transportLost: Throwable? = null

    @Volatile private var shuttingDown = false
    private val transportClosed = AtomicBoolean(false)
    private var awaitingPong = -1L // under lock

    /** Bytes read from the peer and fed to the core (the reader stops when the connection ends). */
    @Volatile var bytesRead: Long = 0
        private set

    /** When bytes last arrived from the peer, on [clock]. */
    @Volatile var lastReceived: Long = clock()
        private set

    /** PINGs of [checkHealth] waiting for their acknowledgement, by payload (under lock). */
    private val healthPings = HashMap<Long, CompletableDeferred<Unit>>()

    /** Streams reserved by the pool and not released (under lock). */
    private var reserved = 0

    /** When [reserved] last fell to 0, on [clock]. */
    @Volatile var idleSince: Long = clock()
        private set

    fun start() {
        scope.launch(CoroutineName("kuicksilver-h2-reader")) { readLoop() }
        scope.launch(CoroutineName("kuicksilver-h2-writer")) { writeLoop() }
        scope.launch(CoroutineName("kuicksilver-h2-timer")) { timerLoop() }
    }

    // ---- the core under the lock, events after it ----

    private inline fun <T> withCore(block: H2ConnectionCore.() -> T): T {
        var wantsWrite = false
        try {
            return lock.withLock {
                try {
                    core.block()
                } finally {
                    takeEventsLocked()
                    wantsWrite = core.wantsWrite || core.isClosed
                }
            }
        } finally {
            afterCore(wantsWrite)
        }
    }

    /**
     * [withCore] for a call the core may refuse because the stream ended under us (IllegalStateException from
     * `sendHeaders`, `sendData`, `endStream`): null then. Only the core's own call is guarded: an exception out of the
     * event dispatch that follows (a callback of the engine) is not a refusal and passes through.
     */
    private inline fun <T : Any> withCoreUnlessRefused(crossinline block: H2ConnectionCore.() -> T): T? =
        withCore {
            try {
                block()
            } catch (_: IllegalStateException) {
                null
            }
        }

    /** Runs right before a body's END_STREAM is queued (tests: the peer's reset arrives in that gap). */
    internal var beforeEndStreamForTest: (() -> Unit)? = null

    /** Tests: another thread is dispatching events, so this thread's events wait for it ([releaseDispatchForTest]). */
    internal fun holdDispatchForTest() {
        lock.withLock { dispatching = true }
    }

    internal fun releaseDispatchForTest() {
        lock.withLock { dispatching = false }
        afterCore(false)
    }

    /** Tests: feeds peer bytes into the core without dispatching their events (they stay pending). */
    internal fun receiveWithoutDispatchForTest(bytes: ByteArray) {
        lock.withLock {
            core.receive(bytes, 0, bytes.size, clock())
            takeEventsLocked()
        }
    }

    /**
     * Queues the core's events for dispatch (under the lock). A peer's GOAWAY and the connection's end are noted here, not at
     * their dispatch: the core has already closed or refuses streams for them, and whoever finds that out meanwhile must
     * also find why: the GOAWAY's code (HTTP_1_1_REQUIRED, RFC 9113 section 7) and the connection's end ([closeCause],
     * which [guarded] reports). An HTTP_1_1_REQUIRED stays: a later GOAWAY (section 6.8 allows several) does not take it back.
     */
    private fun takeEventsLocked() {
        while (true) {
            val e = core.nextEvent() ?: break
            if (e is H2Event.GoAway) {
                if (goAwayCode != Http2ErrorCode.HTTP_1_1_REQUIRED) goAwayCode = e.code
                goAwayReceived = true
            }
            if (e is H2Event.Closed && closeCause == null) closeCause = closedCause(e)
            pending.addLast(e)
        }
    }

    /** Why the connection ended with [e]: the transport's loss when that came first, else the core's end. */
    private fun closedCause(e: H2Event.Closed): Http2Exception.ConnectionClosed =
        transportLost?.let {
            Http2Exception.ConnectionClosed(
                goAwayCode,
                byPeer = true,
                notProcessed = false,
                "the connection was lost: ${it.message}",
                it,
            )
        }
            ?: Http2Exception.ConnectionClosed(e.code, e.byPeer, notProcessed = false, "the connection ended (${e.code}): ${e.reason}")

    /**
     * Wakes the writer when the core has something to write (only then: the writer's own poll would wake it forever) and
     * the timer (a deadline may have moved), then dispatches the events in order, one dispatcher at a time.
     */
    private fun afterCore(wantsWrite: Boolean) {
        if (wantsWrite) kick.trySend(Unit)
        timerKick.trySend(Unit)
        while (true) {
            val e =
                lock.withLock {
                    if (dispatching) return
                    pending.removeFirstOrNull()?.also { dispatching = true } ?: return
                }
            try {
                dispatch(e)
            } finally {
                lock.withLock { dispatching = false }
            }
        }
    }

    private fun dispatch(e: H2Event) {
        when (e) {
            is H2Event.HeadersReceived -> {
                onHeaders(e)
            }

            is H2Event.Data -> {
                onData(e)
            }

            is H2Event.StreamReset -> {
                onReset(e)
            }

            is H2Event.GoAway -> {
                onGoAway(e)
            }

            is H2Event.SettingsChanged -> {
                prefaceReceived.complete(Unit)
                onChange()
            }

            is H2Event.WindowAvailable -> {
                lock.withLock { streams[e.streamId] }?.writable?.trySend(Unit)
            }

            is H2Event.PingAck -> {
                val health =
                    lock.withLock {
                        if (e.payload == awaitingPong) awaitingPong = -1
                        healthPings.remove(e.payload)
                    }
                health?.complete(Unit)
            }

            is H2Event.Closed -> {
                onClosed(e)
            }
        }
    }

    // ---- events ----

    private fun onHeaders(e: H2Event.HeadersReceived) {
        val s = lock.withLock { streams[e.streamId] }
        if (s == null) {
            if (!client) newRequest(e)
            return
        }
        if (e.tooLarge) {
            // RFC 9113 section 8.2 and the core's contract: a client fails the request; the stream is no longer wanted
            fail(
                s,
                Http2Exception.FieldSectionTooLarge(
                    "the field section of stream ${e.streamId} is above ${settings.maxHeaderListSize} bytes",
                ),
            )
            withCore { reset(s.id, Http2ErrorCode.CANCEL, clock()) }
            return
        }
        val first = lock.withLock { !s.headReceived }
        if (first) {
            val r =
                try {
                    H2Messages.parseResponse(e.fields)
                } catch (m: MalformedMessage) {
                    return malformed(s, m.reason)
                }
            if (r.status in 100..199) {
                s.answered.complete(Unit) // 100 Continue, 103 Early Hints...: the core refused 101 and 1xx with END_STREAM
                return
            }
            lock.withLock {
                s.headReceived = true
                s.contentLength = r.contentLength
                s.noContent = s.responseHasNoContent(r.status)
            }
            s.answered.complete(Unit)
            s.head.complete(H2ResponseHead(r.status, r.fields))
            if (e.endStream) endOfMessage(s)
        } else {
            // trailers (RFC 9113 section 8.1): the core made sure they carry END_STREAM
            val t =
                try {
                    H2Messages.parseTrailers(e.fields)
                } catch (m: MalformedMessage) {
                    return malformed(s, m.reason)
                }
            lock.withLock { s.trailers = t }
            endOfMessage(s)
        }
    }

    private fun newRequest(e: H2Event.HeadersReceived) {
        val handler = onRequest ?: return
        val s = StreamRt(this, e.streamId, headRequest = false)
        lock.withLock { streams[e.streamId] = s }
        if (e.tooLarge) {
            // RFC 9113 section 8.2 and the core's contract: a server answers 431. The stream may no longer be sendable by now
            // (the peer's RST_STREAM, a stream or connection error later in the same read): nothing goes then, and a 431 head
            // above the peer's own SETTINGS_MAX_HEADER_LIST_SIZE (section 6.5.2) cannot go either, so the stream is reset;
            // either way the stream is released, and this event never fails the dispatcher (another stream's caller)
            try {
                withCore {
                    try {
                        sendHeaders(s.id, listOf(":status" to "431") + ownResponseFields(), endStream = true)
                    } catch (_: IllegalStateException) {
                        // ended under us: nothing to answer
                    } catch (_: H2HeaderListTooLarge) {
                        reset(s.id, Http2ErrorCode.CANCEL, clock())
                    }
                    release(s.id)
                }
            } finally {
                lock.withLock { streams.remove(s.id) }
            }
            return
        }
        val r =
            try {
                H2Messages.parseRequest(e.fields, connectProtocolEnabled = false)
            } catch (m: MalformedMessage) {
                malformed(s, m.reason)
                withCore { release(s.id) }
                lock.withLock { streams.remove(s.id) }
                return
            }
        if (e.endStream && r.contentLength > 0) {
            // RFC 9113 section 8.1.1: no DATA can follow, so the content cannot match its content-length; never delivered
            malformed(s, "content-length ${r.contentLength} on a request without content")
            withCore { release(s.id) }
            lock.withLock { streams.remove(s.id) }
            return
        }
        lock.withLock {
            s.headReceived = true
            s.contentLength = r.contentLength
        }
        handler(s, r)
        if (e.endStream) endOfMessage(s)
    }

    private fun onData(e: H2Event.Data) {
        val s = lock.withLock { streams[e.streamId] }
        if (s == null) {
            // released already: nobody reads it, so it goes back to the window at once
            withCore { consumed(e.streamId, e.data.size.toLong(), clock()) }
            return
        }
        var bad: String? = null
        var dropped = false
        lock.withLock {
            when {
                s.failure != null -> {
                    dropped = true
                }

                // RFC 9113 section 8.1.1: a response with no content (HEAD, 204, 304) carrying content is malformed, and so is
                // content beyond its content-length
                s.noContent && e.data.isNotEmpty() -> {
                    bad = "content in a response that has none"
                }

                s.contentLength >= 0 && s.received + e.data.size > s.contentLength -> {
                    bad = "more content than content-length ${s.contentLength}"
                }

                else -> {
                    s.received += e.data.size
                    if (e.data.isNotEmpty()) s.chunks.addLast(e.data)
                }
            }
        }
        if (dropped) {
            withCore { consumed(s.id, e.data.size.toLong(), clock()) }
            return
        }
        bad?.let {
            withCore { consumed(s.id, e.data.size.toLong(), clock()) }
            return malformed(s, it)
        }
        s.readable.trySend(Unit)
        if (e.endStream) endOfMessage(s)
    }

    /** END_STREAM: RFC 9113 section 8.1.1, the content must match a content-length (not for a response without content). */
    private fun endOfMessage(s: StreamRt) {
        val bad =
            lock.withLock {
                if (!s.noContent && s.contentLength >= 0 && s.received != s.contentLength) {
                    "content of ${s.received} bytes, content-length ${s.contentLength}"
                } else {
                    s.remoteEnded = true
                    null
                }
            }
        if (bad != null) return malformed(s, bad)
        s.readable.trySend(Unit)
        s.writable.trySend(Unit)
    }

    /** RFC 9113 section 8.1.1: a malformed message is a stream error of type PROTOCOL_ERROR. */
    private fun malformed(
        s: StreamRt,
        reason: String,
    ) {
        fail(s, Http2Exception.MalformedMessage("malformed message on stream ${s.id}: $reason"))
        withCore { reset(s.id, Http2ErrorCode.PROTOCOL_ERROR, clock()) }
    }

    private fun onReset(e: H2Event.StreamReset) {
        val s = lock.withLock { streams[e.streamId] } ?: return
        val lost = transportLost
        val ended = lock.withLock { core.isClosed }
        // RFC 9113 section 8.1: a server may answer before the whole request and then reset with NO_ERROR: the client stops
        // sending and keeps the response
        // (a client's NO_ERROR reset has no such meaning: on a server it fails the stream like any reset)
        if (client && e.byPeer && e.code == Http2ErrorCode.NO_ERROR && lock.withLock { s.remoteEnded }) {
            lock.withLock { s.localEnded = true }
            s.writable.trySend(Unit)
            return
        }
        val cause =
            when {
                lost != null -> {
                    Http2Exception.ConnectionClosed(
                        goAwayCode,
                        byPeer = true,
                        notProcessed = e.notProcessed,
                        "the connection was lost" + (goAwayCode?.let { " after GOAWAY $it" } ?: "") + ": ${lost.message}",
                        lost,
                    )
                }

                !e.byPeer && ended -> {
                    val local = localError
                    Http2Exception.ConnectionClosed(
                        e.code,
                        byPeer = false,
                        e.notProcessed,
                        "the connection ended with ${e.code}" + (local?.let { ": ${it.second}" } ?: ""),
                        local?.first,
                    )
                }

                else -> {
                    Http2Exception.StreamReset(
                        e.streamId,
                        e.code,
                        e.byPeer,
                        e.notProcessed,
                        "stream ${e.streamId} reset with ${e.code}" + (if (e.byPeer) " by the peer" else "") +
                            (if (e.notProcessed) " (not processed)" else ""),
                    )
                }
            }
        fail(s, cause)
    }

    private fun onGoAway(e: H2Event.GoAway) {
        // goAwayReceived and goAwayCode were set as the event was queued ([takeEventsLocked])
        onChange()
    }

    private fun onClosed(e: H2Event.Closed) {
        // set as the event was queued ([takeEventsLocked])
        val cause = closeCause ?: closedCause(e).also { closeCause = it }
        endedByFlood =
            transportLost == null && e.code == Http2ErrorCode.ENHANCE_YOUR_CALM && !e.byPeer && !lock.withLock { core.slowFieldBlock }
        ended.complete(Unit)
        prefaceReceived.completeExceptionally(cause)
        val left = lock.withLock { streams.values.toList() }
        for (s in left) fail(s, cause) // a complete response stays complete (fail keeps it)
        onChange()
        kick.trySend(Unit) // the writer drains what is left, then closes the transport
        if (client) {
            // a server that stopped reading would hold the writer, and with it the transport and the pool's slot, for good:
            // the drain is bounded as for [lost] in order (a server bounds it by the engine's send-stall deadline instead)
            scope.launch(CoroutineName("kuicksilver-h2-close")) {
                if (withTimeoutOrNull(IN_ORDER_CLOSE_BOUND) { closed.await() } == null) closeTransportOnce(graceful = false)
            }
        }
    }

    /** Fails [s] with [cause] unless it already failed; a response read to its end stays complete. */
    fun fail(
        s: StreamRt,
        cause: Throwable,
    ) {
        val set =
            lock.withLock {
                if (s.failure != null || (s.remoteEnded && s.localEnded)) {
                    false
                } else {
                    s.failure = cause
                    true
                }
            }
        if (!set) return
        s.failed.complete(cause)
        s.head.completeExceptionally(cause)
        s.answered.completeExceptionally(cause)
        s.readable.trySend(Unit)
        s.writable.trySend(Unit)
        written.update { it + 1 } // a sender waiting to end its body looks again (and finds the failure)
    }

    // ---- loops ----

    private suspend fun readLoop() {
        val buf = ByteArray(READ_BUFFER)
        try {
            while (true) {
                val n = input.readAvailable(buf, 0, buf.size)
                if (n < 0) {
                    // a channel closed with a cause answers -1 too: the cause says it failed, not ended
                    transportFailed(input.closedCause ?: IOException("the peer closed the connection"))
                    return
                }
                if (n == 0) continue
                bytesRead += n // one reader coroutine writes it
                lastReceived = clock()
                withCore { receive(buf, 0, n, clock()) }
                if (lock.withLock { core.isClosed }) return
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            transportFailed(e)
        }
    }

    /**
     * The input failed with [cause]: a connection error when [connectionErrorOf] says the transport reported one (GOAWAY with
     * its code on the output, which still works; RFC 9113 section 5.4.1), else the connection was lost.
     */
    private fun transportFailed(cause: Throwable) {
        val code = connectionErrorOf(cause)
        if (code == null) {
            lost(cause)
            return
        }
        // the transport's own reason, not a channel's wrapper of it
        val reason = generateSequence(cause) { it.cause }.mapNotNull { it.message }.lastOrNull() ?: "the transport failed"
        lock.withLock { if (localError == null) localError = cause to reason }
        withCore { goAway(code, reason.encodeToByteArray(), graceful = false, now = clock()) }
        onChange()
    }

    /** Why this side ended the connection with a connection error the transport reported ([transportFailed]), and its reason. */
    @Volatile private var localError: Pair<Throwable, String>? = null

    private suspend fun writeLoop() {
        val buf = ByteArray(WRITE_BUFFER)
        var drained = false
        try {
            while (true) {
                val n = withCore { poll(buf, 0, clock()) }
                if (n > 0) {
                    output.writeFully(buf, 0, n)
                    written.update { it + 1 }
                    continue
                }
                output.flush()
                if (lock.withLock { core.isClosed && !core.wantsWrite }) {
                    drained = true
                    break
                }
                kick.receive()
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            lost(e)
        } finally {
            // RFC 9113 section 5.4.1 and 6.8: the last GOAWAY is in the output; a transport that is still sound is closed
            // in order behind it (a hard close would drop what the transport has not sent yet)
            closeTransportOnce(graceful = drained && (transportLost == null || lostInOrder))
            closed.complete(Unit)
            job.cancel()
        }
    }

    private suspend fun timerLoop() {
        var nextPing = if (pingIntervalNanos == Long.MAX_VALUE) Long.MAX_VALUE else clock() + pingIntervalNanos
        while (true) {
            val now = clock()
            val t = lock.withLock { if (core.isClosed) null else core.nextTimeout() ?: Long.MAX_VALUE } ?: return
            if (t <= now) {
                withCore { onTimeout(now) }
                continue
            }
            if (nextPing <= now) {
                val unanswered = lock.withLock { awaitingPong >= 0 }
                if (unanswered) {
                    // OkHttp's pingInterval: a PING still unanswered when the next one is due ends the connection; the
                    // transport is sound as far as we know, so its GOAWAY goes out first (RFC 9113 section 5.4.1)
                    lost(IOException("no PING acknowledgement within ${pingIntervalNanos / 1_000_000} ms"), inOrder = true)
                    return
                }
                withCore { awaitingPong = ping(now) }
                nextPing = now + pingIntervalNanos
                continue
            }
            val deadline = minOf(t, nextPing)
            val waitMs = if (deadline == Long.MAX_VALUE) Long.MAX_VALUE else ((deadline - now + 999_999) / 1_000_000).coerceAtLeast(1)
            withTimeoutOrNull(waitMs) { timerKick.receive() }
        }
    }

    /**
     * The transport failed or ended under the core ([cause]): every open stream fails, and the transport is closed. [inOrder]:
     * the transport itself is sound (a peer that stopped answering), so the GOAWAY is written and the transport closed in
     * order behind it, or hard after [IN_ORDER_CLOSE_BOUND] when the writer cannot get it out.
     */
    fun lost(
        cause: Throwable,
        inOrder: Boolean = false,
    ) {
        val first =
            lock.withLock {
                if (transportLost == null && !core.isClosed) {
                    transportLost = cause
                    true
                } else {
                    false
                }
            }
        // the core reports every stream (those that never went out as not processed) and its end
        if (first && inOrder) lostInOrder = true
        if (first) withCore { goAway(Http2ErrorCode.INTERNAL_ERROR, ByteArray(0), graceful = false, now = clock()) }
        if (first && inOrder) {
            scope.launch(CoroutineName("kuicksilver-h2-close")) {
                if (withTimeoutOrNull(IN_ORDER_CLOSE_BOUND) { closed.await() } == null) closeTransportOnce(graceful = false)
            }
        } else {
            closeTransportOnce(graceful = false)
        }
    }

    /** [lost] was told the transport is sound: the writer closes it in order. */
    @Volatile private var lostInOrder = false

    private fun closeTransportOnce(graceful: Boolean) {
        if (!transportClosed.compareAndSet(false, true)) return
        val gracefully = closeTransportGracefully
        runCatching { if (graceful && gracefully != null) gracefully() else closeTransport() }
    }

    // ---- the driver's actions ----

    /** Not ending, not told to go away, transport alive: a new stream may be opened. */
    val usable: Boolean get() = lock.withLock { usableLocked() }

    private fun usableLocked(): Boolean = !core.isClosed && !goAwayReceived && transportLost == null && !shuttingDown && core.streamIdsLeft

    /** Takes a stream slot within the peer's SETTINGS_MAX_CONCURRENT_STREAMS; false when full or not [usable]. */
    fun tryReserve(): Boolean =
        lock.withLock {
            // before the peer's preface one stream (the request that opened the connection): its SETTINGS_MAX_CONCURRENT_STREAMS
            // is not known yet, and a burst under the initial "unlimited" (RFC 9113 section 6.5.2) would only be refused
            val limit = if (core.peerPrefaceReceived) core.peerMaxConcurrentStreams else 1L
            if (!usableLocked() || reserved >= limit) {
                false
            } else {
                reserved++
                true
            }
        }

    fun unreserve() {
        val drained =
            lock.withLock {
                reserved--
                if (reserved == 0) idleSince = clock()
                reserved == 0 && !core.streamIdsLeft && !core.isClosed
            }
        // a connection without identifiers left has nothing more to do: GOAWAY and close, now that its streams are done
        // (a GOAWAY earlier could reach the server before the last stream's HEADERS)
        if (drained) shutdown()
        onChange()
    }

    /** Streams reserved and not released. */
    val reservedStreams: Int get() = lock.withLock { reserved }

    /** The peer's SETTINGS_MAX_CONCURRENT_STREAMS. */
    val peerMaxConcurrentStreams: Long get() = lock.withLock { core.peerMaxConcurrentStreams }

    /** Opens a client stream with [fields] (already valid, RFC 9113 section 8.3.1) on a reservation of [tryReserve]. */
    fun open(
        fields: List<Pair<String, String>>,
        endStream: Boolean,
        headRequest: Boolean,
    ): StreamRt {
        var s: StreamRt? = null
        try {
            withCore {
                val id = openStream(fields, endStream)
                val rt = StreamRt(this@H2Runtime, id, headRequest, beforePeerSettings = !peerPrefaceReceived)
                rt.localEnded = endStream
                this@H2Runtime.streams[id] = rt
                s = rt
            }
            // the last identifier went (section 5.1.1): no new stream here (usable is false), and the connection ends once
            // its streams are done (unreserve)
            if (!lock.withLock { core.streamIdsLeft }) onChange()
        } catch (e: H2StreamLimit) {
            throw Http2Exception.StreamReset(
                0,
                Http2ErrorCode.REFUSED_STREAM,
                byPeer = false,
                notProcessed = true,
                e.message ?: "stream limit",
            )
        } catch (e: H2ConnectionUnusable) {
            throw Http2Exception.ConnectionClosed(goAwayCode, byPeer = goAwayReceived, notProcessed = true, e.message ?: "unusable")
        } catch (e: H2HeaderListTooLarge) {
            throw Http2Exception.FieldSectionTooLarge("the request's ${e.message}")
        }
        return s!!
    }

    /** RFC 9110 section 10.1.1: waits until the peer answered (an interim or final response), at most [millis]. */
    suspend fun awaitAnswer(
        s: StreamRt,
        millis: Long,
    ) {
        withTimeoutOrNull(millis) { runCatching { s.answered.await() } }
    }

    /**
     * Sends [source] as the content of [s] and ends it, within the peer's windows; a wait for window longer than
     * [stallMillis] (null: none) fails the stream with [stallError]. Returns quietly when the peer stopped the stream after
     * a complete response (RFC 9113 section 8.1).
     */
    suspend fun sendBody(
        s: StreamRt,
        source: ByteReadChannel,
        stallMillis: Long?,
        stallError: () -> Throwable,
        end: Boolean = true,
    ) {
        val buf = ByteArray(SEND_CHUNK)
        try {
            while (true) {
                val n = source.readAvailable(buf, 0, buf.size)
                if (n < 0) {
                    source.closedCause?.let { throw it } // a body that failed is not a body that ended
                    break
                }
                var off = 0
                while (off < n) {
                    if (!sendable(s)) return
                    val k = sendStep(s) { sendData(s.id, buf, off, n - off, endStream = false) } ?: continue
                    off += k
                    if (k == 0) awaitWindow(s, stallMillis, stallError)
                }
            }
            if (!end) return
            while (true) {
                if (!sendable(s)) return
                // read before trying: the writer may write the frame in the way between the try and the wait
                val seen = written.value
                beforeEndStreamForTest?.invoke()
                val ended = sendStep(s) { endStream(s.id) } ?: continue
                if (ended) {
                    lock.withLock { s.localEnded = true }
                    return
                }
                waitWithin(s, stallMillis, stallError) { written.first { it != seen } }
            }
        } catch (e: CancellationException) {
            abandon(s, e)
            throw e
        } catch (e: Throwable) {
            val failure = lock.withLock { s.failure }
            if (failure != null && failure !== e) throw failure
            abandon(s, e)
            throw e
        }
    }

    /**
     * Our side of [s] cannot go on: RST_STREAM CANCEL unless the stream already failed or ended. A server whose response is
     * complete does not reset: a reset would drop the response's frames still queued (RFC 9113 section 6.4); once the
     * stream is released, the core asks the client to stop with NO_ERROR after those frames (section 8.1).
     */
    private fun abandon(
        s: StreamRt,
        cause: Throwable,
    ) {
        val reset =
            lock.withLock {
                s.failure == null && !(s.remoteEnded && s.localEnded) && (client || !s.localEnded)
            }
        if (!reset) return
        fail(s, cause)
        withCore { reset(s.id, Http2ErrorCode.CANCEL, clock()) }
    }

    private fun sendable(s: StreamRt): Boolean =
        lock.withLock {
            s.failure?.let { throw it }
            !s.localEnded
        }

    /**
     * A core call of [s]'s sender, after a suspension: null when the core refused it because the stream ended under us (a
     * reset or GOAWAY from the peer, the connection). The core can be ahead of the runtime there: its event may still be
     * waiting for another thread's dispatch, so this waits until the runtime knows (the stream failed, or the peer ended
     * our side after a complete response), and the caller's next round reports that, never the core's refusal.
     */
    private suspend fun <T : Any> sendStep(
        s: StreamRt,
        block: H2ConnectionCore.() -> T,
    ): T? {
        val r = withCoreUnlessRefused(block)
        if (r == null) {
            while (lock.withLock { s.failure == null && !s.localEnded }) {
                if (closed.isCompleted) {
                    // the connection is over and nothing failed the stream: it fails now, typed
                    fail(
                        s,
                        closeCause ?: Http2Exception.ConnectionClosed(null, byPeer = false, notProcessed = false, "the connection ended"),
                    )
                    break
                }
                kotlinx.coroutines.selects.select {
                    s.writable.onReceive {}
                    closed.onAwait {}
                }
            }
        }
        return r
    }

    /**
     * A core call for [s] that does not suspend (a server's response head and trailers): a refusal because the stream
     * ended under us becomes the stream's failure, or a typed reset when the runtime does not know it yet; the core's
     * IllegalStateException never reaches the application.
     */
    private inline fun guarded(
        s: StreamRt,
        crossinline block: H2ConnectionCore.() -> Unit,
    ) {
        withCoreUnlessRefused { block() } ?: throw lock.withLock { s.failure } ?: closeCause
            ?: Http2Exception.StreamReset(
                s.id,
                Http2ErrorCode.CANCEL,
                byPeer = true,
                notProcessed = false,
                "stream ${s.id} ended under us",
            )
    }

    private suspend fun awaitWindow(
        s: StreamRt,
        stallMillis: Long?,
        stallError: () -> Throwable,
    ) = waitWithin(s, stallMillis, stallError) { s.writable.receive() }

    private suspend fun waitWithin(
        s: StreamRt,
        stallMillis: Long?,
        stallError: () -> Throwable,
        wait: suspend () -> Unit,
    ) {
        if (stallMillis == null) return wait()
        try {
            withTimeout(stallMillis) { wait() }
        } catch (e: TimeoutCancellationException) {
            val err = stallError()
            abandon(s, err)
            throw err
        }
    }

    /** The content [s] holds: taken off the stream and credited to the peer (the application is reading it). */
    fun pull(s: StreamRt): List<ByteArray> {
        var n = 0L
        val taken =
            lock.withLock {
                if (s.chunks.isEmpty()) return emptyList()
                val l = s.chunks.toList()
                s.chunks.clear()
                for (c in l) n += c.size
                l
            }
        withCore { consumed(s.id, n, clock()) }
        return taken
    }

    /** The application gave up the body of [s] before its end. */
    fun cancelRead(
        s: StreamRt,
        cause: Throwable,
    ) {
        val complete = lock.withLock { s.remoteEnded }
        if (complete) return
        abandon(s, cause)
    }

    /**
     * The application is done with [s] (its call ended): a stream not finished both ways is reset with CANCEL (RFC 9113
     * section 8.1: the client no longer wants the response), the core releases it and its reservation comes back. True for
     * the first call, false for every later one.
     */
    fun release(s: StreamRt): Boolean {
        val first =
            lock.withLock {
                if (s.released) {
                    false
                } else {
                    s.released = true
                    true
                }
            }
        if (!first) return false
        abandon(s, CancellationException("the call ended"))
        withCore { release(s.id) }
        lock.withLock {
            streams.remove(s.id)
            s.chunks.clear()
        }
        if (client) unreserve()
        return true
    }

    /** A server's response head on [s]. */
    fun respond(
        s: StreamRt,
        status: Int,
        fields: List<Pair<String, String>>,
        endStream: Boolean,
    ) {
        guarded(s) { sendHeaders(s.id, listOf(":status" to status.toString()) + fields, endStream) }
        if (endStream) lock.withLock { s.localEnded = true }
    }

    /** Trailers on [s] (RFC 9113 section 8.1): they end our side. */
    fun respondTrailers(
        s: StreamRt,
        fields: List<Pair<String, String>>,
    ) {
        guarded(s) { sendHeaders(s.id, fields, endStream = true) }
        lock.withLock { s.localEnded = true }
    }

    /** Resets [s] with [code] (tests and the server's handlers). */
    fun reset(
        s: StreamRt,
        code: Http2ErrorCode,
    ) {
        fail(s, Http2Exception.StreamReset(s.id, code, byPeer = false, notProcessed = false, "reset with $code"))
        withCore { reset(s.id, code, clock()) }
    }

    /** GOAWAY (NO_ERROR) without new streams; the transport closes once the streams in flight are done. */
    fun shutdown() {
        shuttingDown = true
        withCore { goAway(Http2ErrorCode.NO_ERROR, ByteArray(0), graceful = !this@H2Runtime.client, now = clock()) }
        onChange()
    }

    /** GOAWAY with [code] at once (not graceful); an error code also ends the connection once it is written. */
    fun goAwayNow(code: Http2ErrorCode) {
        withCore { goAway(code, ByteArray(0), graceful = false, now = clock()) }
        onChange()
    }

    /** The health check in flight, shared by every caller that asks meanwhile (under lock). */
    private var healthCheck: CompletableDeferred<Boolean?>? = null

    /**
     * Sends a PING and waits for its acknowledgement at most [timeoutMillis]; false when none came (or the connection
     * ended). One check at a time per connection: callers that ask while one is in flight share its answer, so a burst of
     * requests sends one PING, not one each (the core keeps 16 outstanding PINGs and forgets the oldest, whose answers
     * would then never be seen; a server may also take a PING burst for a flood). The caller retires a connection that
     * fails it. A check whose caller was cancelled gives its sharers no verdict, and one of them checks again.
     */
    suspend fun checkHealth(timeoutMillis: Long): Boolean {
        while (true) {
            if (closed.isCompleted) return false
            var mine = false
            val shared =
                lock.withLock {
                    healthCheck ?: CompletableDeferred<Boolean?>().also {
                        healthCheck = it
                        mine = true
                    }
                }
            if (mine) return runHealthCheck(shared, timeoutMillis)
            shared.await()?.let { return it } // null: its caller went away without a verdict
        }
    }

    /** The PING of [checkHealth], by the caller that owns [shared]. */
    private suspend fun runHealthCheck(
        shared: CompletableDeferred<Boolean?>,
        timeoutMillis: Long,
    ): Boolean {
        val acked = CompletableDeferred<Unit>()
        val payload =
            withCore {
                val p = ping(clock())
                healthPings[p] = acked
                p
            }
        val ok =
            try {
                withTimeoutOrNull(timeoutMillis) {
                    kotlinx.coroutines.selects.select {
                        acked.onAwait { true }
                        closed.onAwait { false }
                    }
                } ?: false
            } catch (e: CancellationException) {
                // the caller went away: the others get no verdict (null), not a "dead" that would retire a healthy
                // connection, and one of them checks again
                lock.withLock {
                    healthPings.remove(payload)
                    healthCheck = null
                }
                shared.complete(null)
                throw e
            }
        lock.withLock {
            if (!ok) healthPings.remove(payload)
            healthCheck = null
        }
        shared.complete(ok)
        return ok
    }

    /** Ends the connection now ([cause] for the streams still running). */
    fun abort(cause: Throwable) = lost(cause)

    private companion object {
        /** How long a connection [lost] in order waits for its writer before the transport is closed hard. */
        val IN_ORDER_CLOSE_BOUND = 2.seconds
        const val READ_BUFFER = 16_384
        const val WRITE_BUFFER = 65_536
        const val SEND_CHUNK = 16_384
    }
}

/** A response head (RFC 9113 section 8.3.2): the status and the regular fields, validated. */
@io.kuicksilver.annotations.InternalKuicksilverApi
public class H2ResponseHead internal constructor(
    /** The status code, 200..599 (interim responses are not reported here). */
    public val status: Int,
    /** The regular fields, lowercase names, in the order received. */
    public val fields: List<Pair<String, String>>,
)
