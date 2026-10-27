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
) : QuicStream {
    @Volatile
    override var receivedEarly: Boolean = false
        internal set

    private val inChannel: StreamInput? = if (recv) StreamInput(this) else null
    private val outChannel: StreamOutput? = if (send) StreamOutput(this) else null
    override val input: ByteReadChannel get() = inChannel ?: throw IllegalStateException("stream $id is send-only")
    override val output: ByteWriteChannel get() = outChannel ?: throw IllegalStateException("stream $id is receive-only")
    internal val readable = Channel<Unit>(Channel.CONFLATED)
    internal val ticker = conn.newTicker()
    override var priority: StreamPriority = initialPriority
        set(v) {
            field = v
            loop.scope.launch { if (!dropped) conn.core.setPriority(id, v) }
        }

    internal fun signalReadable() {
        readable.trySend(Unit)
    }

    /** Completes when both halves are done (our data acknowledged or reset, the peer's consumed) or the connection ended. */
    internal val done = kotlinx.coroutines.CompletableDeferred<Unit>()

    internal fun finished() {
        readable.trySend(Unit)
        conn.removeTicker(ticker)
        done.complete(Unit)
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
    }

    internal fun peerStopped(code: Long) {
        outChannel?.closeWith(QuicException.StreamError.Stopped(id, code, Initiator.Peer))
    }

    /**
     * The server rejected 0-RTT and the core dropped this stream (RFC 9001 section 4.6.2); its ID may already name a new
     * stream, so nothing here touches the core again.
     */
    @Volatile
    internal var dropped = false
        private set

    internal fun earlyDataRejected() {
        dropped = true
        val e = QuicException.StreamError.EarlyDataRejected(id)
        inChannel?.closeWith(e)
        outChannel?.closeWith(e)
        finished()
    }

    internal fun connectionLost(reason: QuicException.ConnectionLost) {
        inChannel?.connectionLost(reason) // what the peer sent before is still read
        outChannel?.closeWith(reason)
        done.complete(Unit)
    }

    override fun reset(code: Long) {
        outChannel?.closeWith(QuicException.StreamError.Reset(id, code, Initiator.Local))
        loop.scope.launch {
            if (dropped) return@launch
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
            if (dropped) return@launch
            conn.core.resetStreamAt(id, code, reliableSize)
            loop.flush(conn.core)
        }
    }

    override fun stopSending(code: Long) {
        inChannel?.closeWith(QuicException.StreamError.Stopped(id, code, Initiator.Local))
        loop.scope.launch {
            if (dropped) return@launch
            conn.core.stopSending(id, code)
            loop.flush(conn.core)
        }
    }

    internal companion object {
        const val HANDED_OUT = 0
        const val QUEUED = 1
        const val RESET_UNREAD = 2
    }
}
