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
) {
    private val client = role == Role.CLIENT
    val lock = SpinLock()
    val core = H2ConnectionCore(role, settings, clock())
    private val streams = HashMap<Int, StreamRt>()
    private val pending = ArrayDeque<H2Event>()
    private var dispatching = false
    private val kick = Channel<Unit>(Channel.CONFLATED)
    private val timerKick = Channel<Unit>(Channel.CONFLATED)

    /** Counts what the writer handed to the transport (an `endStream` that had to wait for its frame's predecessor). */
    private val written = MutableStateFlow(0L)

    private val job = SupervisorJob(parent.coroutineContext[Job])
    private val scope = CoroutineScope(parent.coroutineContext + job)

    /** Completed by the peer's first SETTINGS (its preface, RFC 9113 section 3.4); failed when the connection ends first. */
    val prefaceReceived = CompletableDeferred<Unit>()

    /** Completed when the connection is over, with nothing left to write. */
    val closed = CompletableDeferred<Unit>()

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
                    while (true) pending.addLast(core.nextEvent() ?: break)
                    wantsWrite = core.wantsWrite || core.isClosed
                }
            }
        } finally {
            afterCore(wantsWrite)
        }
    }

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
                lock.withLock { if (e.payload == awaitingPong) awaitingPong = -1 }
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
            // RFC 9113 section 8.2 and the core's contract: a server answers 431
            withCore {
                sendHeaders(s.id, listOf(":status" to "431"), endStream = true)
                release(s.id)
            }
            lock.withLock { streams.remove(s.id) }
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
        if (e.byPeer && e.code == Http2ErrorCode.NO_ERROR && lock.withLock { s.remoteEnded }) {
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
                    Http2Exception.ConnectionClosed(e.code, byPeer = false, e.notProcessed, "the connection ended with ${e.code}")
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
        goAwayReceived = true
        goAwayCode = e.code
        onChange()
    }

    private fun onClosed(e: H2Event.Closed) {
        val cause =
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
        closeCause = cause
        prefaceReceived.completeExceptionally(cause)
        val left = lock.withLock { streams.values.toList() }
        for (s in left) fail(s, cause) // a complete response stays complete (fail keeps it)
        onChange()
        kick.trySend(Unit) // the writer drains what is left, then closes the transport
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
        s.head.completeExceptionally(cause)
        s.answered.completeExceptionally(cause)
        s.readable.trySend(Unit)
        s.writable.trySend(Unit)
    }

    // ---- loops ----

    private suspend fun readLoop() {
        val buf = ByteArray(READ_BUFFER)
        try {
            while (true) {
                val n = input.readAvailable(buf, 0, buf.size)
                if (n < 0) {
                    // a channel closed with a cause answers -1 too: the cause says it failed, not ended
                    lost(input.closedCause ?: IOException("the peer closed the connection"))
                    return
                }
                if (n == 0) continue
                withCore { receive(buf, 0, n, clock()) }
                if (lock.withLock { core.isClosed }) return
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            lost(e)
        }
    }

    private suspend fun writeLoop() {
        val buf = ByteArray(WRITE_BUFFER)
        try {
            while (true) {
                val n = withCore { poll(buf, 0, clock()) }
                if (n > 0) {
                    output.writeFully(buf, 0, n)
                    written.update { it + 1 }
                    continue
                }
                output.flush()
                if (lock.withLock { core.isClosed && !core.wantsWrite }) break
                kick.receive()
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            lost(e)
        } finally {
            closeTransportOnce()
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
                    // OkHttp's pingInterval: a PING still unanswered when the next one is due ends the connection
                    lost(IOException("no PING acknowledgement within ${pingIntervalNanos / 1_000_000} ms"))
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

    /** The transport failed or ended under the core ([cause]): every open stream fails, and the transport is closed. */
    fun lost(cause: Throwable) {
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
        if (first) withCore { goAway(Http2ErrorCode.INTERNAL_ERROR, ByteArray(0), graceful = false, now = clock()) }
        closeTransportOnce()
    }

    private fun closeTransportOnce() {
        if (transportClosed.compareAndSet(false, true)) runCatching { closeTransport() }
    }

    // ---- the driver's actions ----

    /** Not ending, not told to go away, transport alive: a new stream may be opened. */
    val usable: Boolean get() = lock.withLock { usableLocked() }

    private fun usableLocked(): Boolean = !core.isClosed && !goAwayReceived && transportLost == null && !shuttingDown && core.streamIdsLeft

    /** Takes a stream slot within the peer's SETTINGS_MAX_CONCURRENT_STREAMS; false when full or not [usable]. */
    fun tryReserve(): Boolean =
        lock.withLock {
            if (!usableLocked() || reserved >= core.peerMaxConcurrentStreams) {
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
                val rt = StreamRt(this@H2Runtime, id, headRequest)
                rt.localEnded = endStream
                streams[id] = rt
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
                    val k = guarded(s) { sendData(s.id, buf, off, n - off, endStream = false) }
                    off += k
                    if (k == 0) awaitWindow(s, stallMillis, stallError)
                }
            }
            if (!end) return
            while (true) {
                if (!sendable(s)) return
                // read before trying: the writer may write the frame in the way between the try and the wait
                val seen = written.value
                if (guarded(s) { endStream(s.id) }) {
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
     * complete does not reset: a reset would drop the response's frames still queued (RFC 9113 section 6.4); the request's
     * remaining content is credited as it arrives. (Asking the client to stop with NO_ERROR once those frames are out,
     * section 8.1, comes with the server engine.)
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

    private inline fun <T> guarded(
        s: StreamRt,
        block: H2ConnectionCore.() -> T,
    ): T =
        try {
            withCore(block)
        } catch (e: IllegalStateException) {
            // the stream ended under us (a reset, the connection): its failure says why
            throw lock.withLock { s.failure } ?: closeCause ?: e
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
     * section 8.1: the client no longer wants the response), the core releases it and its reservation comes back.
     */
    fun release(s: StreamRt) {
        val first =
            lock.withLock {
                if (s.released) {
                    false
                } else {
                    s.released = true
                    true
                }
            }
        if (!first) return
        abandon(s, CancellationException("the call ended"))
        withCore { release(s.id) }
        lock.withLock {
            streams.remove(s.id)
            s.chunks.clear()
        }
        if (client) unreserve()
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
        withCore { goAway(Http2ErrorCode.NO_ERROR, ByteArray(0), graceful = !client, now = clock()) }
        onChange()
    }

    /** GOAWAY with [code] at once (not graceful); an error code also ends the connection once it is written. */
    fun goAwayNow(code: Http2ErrorCode) {
        withCore { goAway(code, ByteArray(0), graceful = false, now = clock()) }
        onChange()
    }

    /** Ends the connection now ([cause] for the streams still running). */
    fun abort(cause: Throwable) = lost(cause)

    private companion object {
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
