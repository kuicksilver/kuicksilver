// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * One stream of the core as two ktor-io channels. The input pulls from the core only when the application
 * awaits content, so flow-control credit returns at the application's pace; the output hands bytes to the core on every
 * flush and suspends while the core's send buffer is full. No pump coroutines: every core access hops onto the loop.
 */
// ByteReadChannel/ByteWriteChannel implementations need ktor's opt-in (readBuffer/writeBuffer)
@OptIn(ExperimentalKuicksilverApi::class, io.ktor.utils.io.InternalAPI::class)
internal class StreamRuntime(
    internal val conn: ConnectionRuntime,
    internal val loop: EndpointLoop,
    override val id: Long,
    recv: Boolean,
    send: Boolean,
    initialPriority: StreamPriority = StreamPriority.Default,
    /**
     * The core's [io.kuicksilver.quic.stream.StreamManager.zeroRttResets] when this wrapper was made for a stream we
     * opened; -1 for a peer's stream, which no rejected 0-RTT drops.
     */
    private val epoch: Int = -1,
) : QuicStream {
    @Volatile
    override var receivedEarly: Boolean = false
        internal set

    private val inChannel: StreamInput? = if (recv) StreamInput(this) else null

    /** The peer sends on this stream (it has an input). */
    internal val receives: Boolean get() = inChannel != null
    private val outChannel: StreamOutput? = if (send) StreamOutput(this) else null
    override val input: ByteReadChannel get() = inChannel ?: throw IllegalStateException("stream $id is send-only")
    override val output: ByteWriteChannel get() = outChannel ?: throw IllegalStateException("stream $id is receive-only")
    internal val readable = Channel<Unit>(Channel.CONFLATED)

    /**
     * The final size of our sending half, -1 while unknown (loop). This and the fields below are what the observers follow
     * ([sentFinalSize], [receivedFinalSize], [receivedOffset], [sendReleased]); the Deferreds and flows that publish them
     * are made only when someone reads one ([watch]): a stream nobody observes (an idle HTTP/3 connection's control and
     * QPACK streams, a plain request) allocates none of them, and no exception for the half it lacks.
     */
    @Volatile
    private var sentFinalKnown = -1L

    /** The final size of the peer's sending half, -1 while unknown (loop). */
    @Volatile
    private var receivedFinalKnown = -1L

    /** Why a final size still unknown never will be (loop). */
    @Volatile
    private var finalsLost: Throwable? = null

    /** The highest offset of the peer's half received so far (loop). */
    @Volatile
    private var receivedHigh = 0L

    /** The bytes of our send buffer released so far, as far as the loop followed them. */
    @Volatile
    private var sendReleasedTotal = 0L

    /** The Deferreds and flows handed to observers, made once by the first reader. */
    private class Watch(
        val sentFinal: kotlinx.coroutines.CompletableDeferred<Long>,
        val receivedFinal: kotlinx.coroutines.CompletableDeferred<Long>,
        val receivedOffset: kotlinx.coroutines.flow.MutableStateFlow<Long>,
        val sendReleased: kotlinx.coroutines.flow.MutableStateFlow<Long>,
    )

    @OptIn(ExperimentalAtomicApi::class)
    private val watchRef = kotlin.concurrent.atomics.AtomicReference<Watch?>(null)

    /**
     * The observers' objects, made on the first call. The loop writes a field before it reads [watchRef], a reader publishes
     * [watchRef] before it reads the fields ([sync]): with sequentially consistent volatile accesses one of the two sees the
     * other. The maker also syncs once more on the loop ([confirmOnLoop]), which needs no more than happens-before.
     */
    @OptIn(ExperimentalAtomicApi::class)
    private fun watch(): Watch {
        watchRef.load()?.let { return it }
        val made =
            Watch(
                kotlinx.coroutines.CompletableDeferred<Long>().also {
                    if (outChannel == null) it.completeExceptionally(IllegalStateException("stream $id is receive-only"))
                },
                kotlinx.coroutines.CompletableDeferred<Long>().also {
                    if (inChannel == null) it.completeExceptionally(IllegalStateException("stream $id is send-only"))
                },
                kotlinx.coroutines.flow.MutableStateFlow(0L),
                kotlinx.coroutines.flow.MutableStateFlow(0L),
            )
        if (!watchRef.compareAndSet(null, made)) return watchRef.load()!!.also(::sync)
        sync(made)
        confirmOnLoop { sync(made) }
        return made
    }

    /**
     * Runs [check] on the loop after a reader published an object the loop completes (a [Watch], a waiter) and read the
     * loop's state itself. That read relies on volatile accesses being sequentially consistent: the JVM guarantees it (JLS
     * 17.4.4, a total synchronization order), Kotlin/Native compiles them as sequentially consistent atomics without
     * documenting more than happens-before. This needs only happens-before: a write the loop made before [check] runs,
     * [check] sees in program order; a write after it follows the publication through the dispatch, so the loop sees the
     * published object and completes it itself. Once the loop's scope ended (or ends before the check ran), the check runs
     * when its job completes: the loop no longer writes then, and the cancellation that ended the job came after its last
     * write. The handler sits on this short-lived job, never on the scope's.
     */
    private fun confirmOnLoop(check: () -> Unit) {
        loop.scope.launch { check() }.invokeOnCompletion { if (it != null) check() }
    }

    /** Brings [w] up to the fields; any thread, any number of times: Deferreds complete once, flows only grow. */
    private fun sync(w: Watch) {
        // the loss first: the loop writes it after any size it fixed before, so a loss seen here brings those sizes with it
        // and the first outcome stands even without sequentially consistent accesses
        val lost = finalsLost
        val sent = sentFinalKnown
        val received = receivedFinalKnown
        settle(w.sentFinal, sent, lost)
        settle(w.receivedFinal, received, lost)
        grow(w.receivedOffset, receivedHigh)
        grow(w.sendReleased, sendReleasedTotal)
    }

    private fun settle(
        d: kotlinx.coroutines.CompletableDeferred<Long>,
        size: Long,
        lost: Throwable?,
    ) {
        when {
            size >= 0 -> d.complete(size)
            lost != null -> d.completeExceptionally(lost)
        }
    }

    private fun grow(
        flow: kotlinx.coroutines.flow.MutableStateFlow<Long>,
        to: Long,
    ) {
        while (true) {
            val v = flow.value
            if (to <= v || flow.compareAndSet(v, to)) return
        }
    }

    @OptIn(ExperimentalAtomicApi::class)
    private fun synced() {
        watchRef.load()?.let(::sync)
    }

    override val receivedOffset: kotlinx.coroutines.flow.StateFlow<Long> get() = watch().receivedOffset

    /** On the loop: the core received up to [offset] on this stream; the flow only grows. */
    internal fun noteReceived(offset: Long) {
        if (offset <= receivedHigh) return
        receivedHigh = offset
        synced()
    }

    /** [sendReleased] was read: the loop keeps the flow up to date. */
    @Volatile
    internal var watchingSend = false
        private set

    /** Bytes the core took for this stream's sending half (on the loop, by [StreamOutput]). */
    internal var sentToCore = 0L

    override val sendReleased: kotlinx.coroutines.flow.StateFlow<Long>
        get() {
            if (outChannel != null && !watchingSend) {
                watchingSend = true
                loop.scope.launch {
                    if (!current) return@launch
                    conn.core.watchStreamSend(id)
                    noteSendReleased(conn.core.streamSendReleased(id))
                }
            }
            return watch().sendReleased
        }

    /** On the loop: the core released up to [total] bytes of this stream's send buffer; the flow only grows. */
    internal fun noteSendReleased(total: Long) {
        if (total <= sendReleasedTotal) return
        sendReleasedTotal = total
        synced()
    }

    override val sentFinalSize: kotlinx.coroutines.Deferred<Long> get() = watch().sentFinal
    override val receivedFinalSize: kotlinx.coroutines.Deferred<Long> get() = watch().receivedFinal

    /** On the loop: the core fixed the final size of one half ([io.kuicksilver.quic.ConnectionEvent.StreamFinalSize]). */
    internal fun finalSize(
        sending: Boolean,
        size: Long,
    ) {
        // the first outcome stands, as a Deferred's would: a half that lacks it, already known or already lost keeps it
        if (finalsLost == null && (if (sending) outChannel else inChannel) != null) {
            if (sending && sentFinalKnown < 0) sentFinalKnown = size
            if (!sending && receivedFinalKnown < 0) receivedFinalKnown = size
        }
        if (!sending) noteReceived(size)
        synced()
    }

    /** The final sizes will never be known: the connection ended, or a rejected 0-RTT dropped the stream. */
    private fun finalSizesLost(cause: Throwable) {
        if (finalsLost == null) finalsLost = cause
        synced()
    }

    internal val ticker = conn.newTicker()

    // the loop applies the value the property holds when its turn comes, not the one this setter wrote: setters on several
    // threads may have their hand-overs run in another order than their writes, and the last one to run must leave the
    // scheduler on the property's final value
    @Volatile
    override var priority: StreamPriority = initialPriority
        set(v) {
            field = v
            loop.scope.launch { if (live()) conn.core.setPriority(id, priority) }
        }

    /** See [io.kuicksilver.quic.markTunnel]. */
    internal fun markTunnel() {
        loop.scope.launch { if (live()) conn.core.markTunnel(id) }
    }

    internal fun signalReadable() {
        readable.trySend(Unit)
    }

    /** The peer's FIN and every byte before it arrived ([io.kuicksilver.quic.receivedAll]). Set on the loop, read anywhere. */
    @Volatile
    internal var receivedAll: Boolean = false
        private set

    /** Bytes [input] took from the core so far (a test hook). */
    internal val inputTakenForTest: Long get() = inChannel?.takenForTest ?: 0

    /** How far beyond the reader's position [input] may take bytes from the core ([io.kuicksilver.quic.readAhead]). */
    internal var readAhead: Long
        get() = inChannel?.readAhead ?: Long.MAX_VALUE
        set(v) {
            inChannel?.readAhead = v
        }

    /** The core's [io.kuicksilver.quic.stream.StreamManager.sendCredit] for this stream, read on the loop; 0 once it is gone. */
    internal suspend fun sendCredit(): Long =
        kotlinx.coroutines.withContext(loop.dispatcher) {
            if (live()) conn.core.streamSendCredit(id) else 0L
        }

    /** On the loop: notes whether the core holds the whole stream now; once true it stays true. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal fun updateReceivedAll() {
        if (!receivedAll && current && conn.core.streamReceivedAll(id)) {
            receivedAll = true
            receivedAllWaiter.load()?.complete(Unit)
        }
    }

    /** Made only by a test that waits ([awaitReceivedAllForTest]), once for all its waiters: nothing otherwise. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private val receivedAllWaiter =
        kotlin.concurrent.atomics.AtomicReference<kotlinx.coroutines.CompletableDeferred<Unit>?>(null)

    /** Suspends until [receivedAll] is true (a test hook). */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal suspend fun awaitReceivedAllForTest() {
        // one deferred for every waiter: two that race publish the first one made, so the loop's completion reaches both
        val made = kotlinx.coroutines.CompletableDeferred<Unit>()
        val first = receivedAllWaiter.compareAndSet(null, made)
        val waiter = if (first) made else receivedAllWaiter.load()!!
        // the loop sets the flag before it reads the waiter, and this reads the flag after the waiter was published: one of
        // the two sees the other ([confirmOnLoop])
        if (receivedAll) return
        if (first) confirmOnLoop { if (receivedAll) made.complete(Unit) }
        waiter.await()
    }

    /** Completes when both halves are done (our data acknowledged or reset, the peer's consumed) or the connection ended. */
    internal val done = kotlinx.coroutines.CompletableDeferred<Unit>()

    internal fun finished() {
        noteSendReleased(sentToCore) // retired: nothing of it is buffered any more
        readable.trySend(Unit)
        conn.removeTicker(ticker)
        done.complete(Unit)
        settleStop(ENDED) // both halves are done: no STOP_SENDING stops this stream any more
    }

    /**
     * Where a peer-initiated stream is on its way to the application: [QUEUED] in the accept queue, [RESET_UNREAD] queued with a
     * RESET_STREAM the runtime has not consumed for it, [HANDED_OUT] returned by acceptStream (and every stream we opened).
     * The core counts a peer stream closed for MAX_STREAMS only once its reset was consumed; consuming it for a stream still in
     * the queue let a peer open streams without bound by resetting them (0.2.1 review). The loop thread moves QUEUED to
     * RESET_UNREAD, acceptStream moves either to HANDED_OUT and consumes a pending reset itself: exactly one of them consumes it.
     */
    @OptIn(ExperimentalAtomicApi::class)
    internal val handOut = AtomicInt(HANDED_OUT)

    /** On the loop: a reset arrived for a stream still waiting for acceptStream; true when its consumption is now left to [handOut]'s taker. */
    @OptIn(ExperimentalAtomicApi::class)
    internal fun deferReset(): Boolean = handOut.compareAndSet(QUEUED, RESET_UNREAD)

    /** The peer's reset; after RESET_STREAM_AT ([afterData]) the bytes the input still holds are read first. */
    internal fun peerReset(
        code: Long,
        afterData: Boolean = false,
    ) {
        val e = QuicException.StreamError.Reset(id, code, Initiator.Peer)
        if (afterData) inChannel?.closeAfterBuffered(e) else inChannel?.closeWith(e)
        if (inChannel != null) settleReceiveAbort(e)
    }

    /**
     * Why the peer's half was aborted, set once on the loop: its RESET_STREAM (or RESET_STREAM_AT), or the rejected 0-RTT
     * that dropped the stream; null while neither happened. Never a FIN, and not the connection's end, which its observers
     * watch on their own.
     */
    @Volatile
    private var receiveAbortCause: Throwable? = null

    /** Made only by a reader of [receiveAborted], once for all of them. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private val receiveAbortWaiter = kotlin.concurrent.atomics.AtomicReference<kotlinx.coroutines.CompletableDeferred<Throwable>?>(null)

    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private fun settleReceiveAbort(e: Throwable) {
        if (receiveAbortCause != null) return
        receiveAbortCause = e
        receiveAbortWaiter.load()?.complete(e)
    }

    /**
     * Completes with the cause once the peer aborted its half of this stream (`io.kuicksilver.quic.receiveAborted`): a
     * RESET_STREAM or RESET_STREAM_AT, or a rejected 0-RTT that dropped the stream. A FIN never completes it, so a waiter
     * tells an aborted stream from a finished one exactly. The loop sets the cause before it reads the waiter, this reads
     * the cause after the waiter was published: one of the two sees the other ([confirmOnLoop]).
     */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal val receiveAborted: kotlinx.coroutines.Deferred<Throwable>
        get() {
            receiveAbortWaiter.load()?.let { return it }
            val made = kotlinx.coroutines.CompletableDeferred<Throwable>()
            if (!receiveAbortWaiter.compareAndSet(null, made)) return receiveAbortWaiter.load()!!
            receiveAbortCause?.let { made.complete(it) }
            confirmOnLoop { receiveAbortCause?.let { made.complete(it) } }
            return made
        }

    internal fun peerStopped(code: Long) {
        settleStop(code)
        outChannel?.closeWith(QuicException.StreamError.Stopped(id, code, Initiator.Peer))
    }

    /**
     * How the peer's STOP_SENDING for this stream stands, set once on the loop: its code (a Long), or why none can come any
     * more ([ENDED]: both halves are done; the connection's [QuicException.ConnectionLost]; the
     * [QuicException.StreamError.EarlyDataRejected] of a stream a rejected 0-RTT dropped); null while neither.
     */
    @Volatile
    private var stopState: Any? = null

    /** Made only by a caller of [awaitSendStopped], once for all of them: a stream nobody watches allocates nothing. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private val stopWaiter = kotlin.concurrent.atomics.AtomicReference<kotlinx.coroutines.CompletableDeferred<Unit>?>(null)

    /** On the loop: the first of the peer's STOP_SENDING and the end of the stream decides [awaitSendStopped]. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private fun settleStop(state: Any) {
        if (stopState != null) return
        stopState = state
        stopWaiter.load()?.complete(Unit)
    }

    /**
     * Suspends until the peer's STOP_SENDING for this stream arrives and returns its code (`io.kuicksilver.quic.awaitSendStopped`),
     * or null once both halves are done without one; throws when the connection ended or a rejected 0-RTT dropped the stream
     * (RFC 9001 section 4.6.2 resets "application state bound to" those streams): a watcher never outlives its stream.
     */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal suspend fun awaitSendStopped(): Long? {
        // one deferred for every waiter; the loop sets the state before it reads the waiter, and this reads the state after
        // the waiter was published: one of the two sees the other ([confirmOnLoop])
        val made = kotlinx.coroutines.CompletableDeferred<Unit>()
        val first = stopWaiter.compareAndSet(null, made)
        val waiter = if (first) made else stopWaiter.load()!!
        if (stopState == null) {
            if (first) confirmOnLoop { if (stopState != null) made.complete(Unit) }
            waiter.await()
        }
        return when (val s = stopState) {
            is Long -> s
            is Throwable -> throw s
            else -> null
        }
    }

    /** The server rejected 0-RTT and the core dropped this stream (RFC 9001 section 4.6.2): the wrapper failed for good. */
    @Volatile
    internal var dropped = false
        private set

    /**
     * On the loop: whether this wrapper still names the core's stream [id]. A rejected 0-RTT drops every stream we opened
     * and restarts their IDs inside the core; the runtime learns it only when it drains the event, a suspension later (a
     * flush waiting in a socket send in between). Until then a stream opened meanwhile may own [id] already, so every core
     * access of this wrapper asks this first, never the event.
     */
    internal val current: Boolean get() = !dropped && (epoch < 0 || epoch == conn.core.streams.zeroRttResets)

    /** On the loop: [current]; a wrapper that is not fails now with EarlyDataRejected and leaves the connection, and false. */
    internal fun live(): Boolean {
        if (current) return true
        if (!dropped) conn.dropRejected(this)
        return false
    }

    /** The core dropped this stream at a rejected 0-RTT: nothing here touches the core again, its ID may name a new stream. */
    internal fun earlyDataRejected() {
        dropped = true
        val e = QuicException.StreamError.EarlyDataRejected(id)
        finalSizesLost(e)
        if (inChannel != null) settleReceiveAbort(e)
        inChannel?.closeWith(e)
        outChannel?.closeWith(e)
        settleStop(e)
        finished()
    }

    internal fun connectionLost(reason: QuicException.ConnectionLost) {
        finalSizesLost(reason)
        inChannel?.connectionLost(reason) // what the peer sent before is still read
        outChannel?.closeWith(reason)
        settleStop(reason)
        noteSendReleased(sentToCore) // the buffer went with the connection
        done.complete(Unit)
    }

    override fun reset(code: Long) {
        outChannel?.closeWith(QuicException.StreamError.Reset(id, code, Initiator.Local))
        loop.scope.launch {
            if (!live()) return@launch
            conn.core.resetStream(id, code)
            loop.flush(conn.core)
        }
    }

    override fun resetAt(
        code: Long,
        reliableSize: Long,
    ) {
        outChannel?.closeWith(QuicException.StreamError.Reset(id, code, Initiator.Local))
        loop.scope.launch {
            if (!live()) return@launch
            conn.core.resetStreamAt(id, code, reliableSize)
            loop.flush(conn.core)
        }
    }

    override fun stopSending(code: Long) {
        inChannel?.closeWith(QuicException.StreamError.Stopped(id, code, Initiator.Local))
        loop.scope.launch {
            if (!live()) return@launch
            conn.core.stopSending(id, code)
            loop.flush(conn.core)
        }
    }

    internal companion object {
        const val HANDED_OUT = 0
        const val QUEUED = 1
        const val RESET_UNREAD = 2

        /** [stopState] of a stream whose halves are both done without a STOP_SENDING. */
        private val ENDED = Any()
    }
}
