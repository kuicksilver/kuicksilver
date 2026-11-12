// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.ktor.utils.io.InternalAPI::class)

package io.kuicksilver.http2.runtime

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.ClosedWriteChannelException
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.readAvailable
import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.io.Buffer
import kotlinx.io.Sink

/**
 * A channel that writes into an HTTP/2 stream with at most [limit] flushed bytes ahead of the stream: what its writer
 * flushed goes out in its own coroutine ([done], started in [scope]) through [send] (the stream's `sendBody`, which
 * waits for the peer's flow-control window, RFC 9113 section 5.2), and a `flush` suspends while more than [limit] flushed
 * bytes have not been handed to the stream yet. So a writer ahead of a peer that reads slowly is held, after a flush, at
 * the stream's window plus [limit] plus the 16 KiB piece being handed on; what it wrote and has not flushed yet (a large
 * frame being written, up to the 1 MiB at which ktor-io's writers flush on their own) comes on top. Before, a Ktor
 * `ByteChannel` in front of the stream let a writer run up to about 3 MiB ahead.
 *
 * [flushAndClose] hands the rest on without waiting for the lead (the stream's end must not wait for a window the peer may
 * never open: the owner bounds that) and ends the stream: [send] gets an empty source with `end` true once the rest went
 * out. [cancel] (a session that failed or was cancelled) never ends the stream, also during a [flushAndClose]: the owner
 * resets it (RFC 8441 section 5: RST_STREAM with CANCEL). A failure of [send] (the stream was reset, the send-stall
 * deadline) fails this channel with it, so the writer's next call throws; it is never thrown into [scope]. One writer
 * coroutine at a time. For the engines only.
 */
@InternalKuicksilverApi
public class H2StreamOutput(
    scope: CoroutineScope,
    private val limit: Int = DEFAULT_LIMIT,
    send: suspend (source: ByteReadChannel, end: Boolean) -> Unit,
) : ByteWriteChannel {
    private val buffer = Buffer()
    private val channel = ByteChannel()

    /** Bytes flushed into [channel] (the writer's count). */
    private var flushed = 0L

    /** Bytes [send] took; [Long.MAX_VALUE] once [done] is over, so a waiting writer wakes. */
    private val handed = MutableStateFlow(0L)

    private val waiting0 = MutableStateFlow(false)

    /** [releaseLead] was called: flushes no longer wait. */
    private val released = MutableStateFlow(false)

    @kotlin.concurrent.Volatile private var failure: Throwable? = null

    @kotlin.concurrent.Volatile private var closed = false

    @kotlin.concurrent.Volatile private var cause: Throwable? = null

    /** The coroutine that hands the bytes to the stream; done once the stream was ended, failed or this was cancelled. */
    public val done: Job =
        scope.launch {
            val chunk = ByteArray(CHUNK)
            try {
                while (true) {
                    val n = channel.readAvailable(chunk, 0, chunk.size)
                    if (n < 0) {
                        channel.closedCause?.let { throw it }
                        break
                    }
                    if (n == 0) continue
                    // a session cancelled after its flushAndClose: what is left is not sent, nor the end
                    if (cause != null) return@launch
                    // a ByteReadChannel over a range copies that range (at most one 16 KiB slice here) into its own
                    // buffer, so the chunk is free again at once; sendBody reads that copy to its end before it returns
                    send(ByteReadChannel(chunk, 0, n), false)
                    handed.update { if (it == Long.MAX_VALUE) it else it + n }
                }
                // RFC 8441 section 5: END_STREAM only for an orderly close, never for a session cancelled meanwhile
                if (cause == null) send(ByteReadChannel.Empty, true)
            } catch (e: Throwable) {
                // kept here, never thrown into [scope] (a call's): the writer's next call and [closedCause] report it
                if (failure == null && cause == null) failure = e
                channel.cancel(e)
            } finally {
                handed.value = Long.MAX_VALUE
            }
        }

    /** The writer waits in [flush] for the stream to take what it is ahead by (tests). */
    public val writerWaiting: StateFlow<Boolean> get() = waiting0

    /** Flushed bytes not handed to the stream yet (tests; [Long.MIN_VALUE]-ish once [done] is over). */
    public val lead: Long get() = flushed - handed.value

    override val isClosedForWrite: Boolean get() = closed

    override val closedCause: Throwable? get() = cause ?: failure

    /** The stream took everything and its END_STREAM: closed by [flushAndClose], nothing failed. */
    public val endedInOrder: Boolean get() = done.isCompleted && failure == null && cause == null && closed

    /** Why handing the bytes to the stream failed, if it did. */
    public val failed: Throwable? get() = failure

    @InternalAPI
    override val writeBuffer: Sink
        get() {
            throwIfClosed()
            return buffer
        }

    private fun throwIfClosed() {
        cause?.let { throw it }
        failure?.let { throw it }
        if (closed) throw ClosedWriteChannelException(kotlinx.io.IOException("the WebSocket output is closed"))
    }

    /** What the writer wrote goes to [channel], counted before anything suspends. */
    private fun handOn() {
        val n = buffer.size
        if (n == 0L) return
        flushed += n
        buffer.transferTo(channel.writeBuffer)
        channel.flushWriteBuffer()
    }

    override suspend fun flush() {
        throwIfClosed()
        handOn()
        val bound = flushed - limit
        if (handed.value < bound && !released.value) {
            waiting0.value = true
            try {
                combine(handed, released) { h, r -> r || h >= bound }.first { it }
            } finally {
                waiting0.value = false
            }
        }
        cause?.let { throw it }
        failure?.let { throw it }
    }

    /**
     * The session is closing (the peer's Close arrived, or its side ended): from now on flushes do not wait for the lead,
     * so the session can write its last frames, its Close among them, and end; what is left is bounded by those frames,
     * and its delivery by the owner (the client's close wait). Without it a writer held behind a peer that never reads
     * again would hold the session's close for good (RFC 6455 section 7.1.1: the closing handshake must not depend on
     * the peer reading the rest).
     */
    public fun releaseLead() {
        released.value = true
    }

    override suspend fun flushAndClose() {
        if (closed) {
            cause?.let { throw it }
            return
        }
        try {
            throwIfClosed()
            handOn()
        } catch (e: Throwable) {
            cancel(e)
            throw e
        }
        closed = true
        // no wait for space: the rest is the owner's to bound (its close wait, its send-stall deadline)
        channel.close()
    }

    override fun cancel(cause: Throwable?) {
        if (this.cause != null) return
        this.cause = cause ?: kotlinx.io.IOException("the channel was cancelled")
        closed = true
        // the writer's [buffer] is the writer's: it is dropped with the channel, never cleared from here (another thread)
        channel.cancel(this.cause)
        handed.value = Long.MAX_VALUE // a writer waiting in flush wakes and throws
    }

    public companion object {
        /**
         * The lead the engines give a WebSocket session over its HTTP/2 stream: 64 KiB of flushed bytes not handed to the
         * stream yet (which holds at most the peer's window more).
         */
        public const val DEFAULT_LIMIT: Int = 65_536

        /** The most handed to the stream at a time (one DATA frame of the default size). */
        private const val CHUNK = 16_384
    }
}
