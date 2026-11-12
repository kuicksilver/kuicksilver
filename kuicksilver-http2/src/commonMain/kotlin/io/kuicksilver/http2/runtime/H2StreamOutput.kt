// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.ktor.utils.io.InternalAPI::class)

package io.kuicksilver.http2.runtime

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.io.Buffer
import kotlinx.io.Sink
import kotlinx.io.readByteArray

/**
 * A channel that writes into an HTTP/2 stream with at most [limit] bytes ahead of the stream: what its writer flushed
 * goes out in its own coroutine ([done], started in [scope]) through [send] (the stream's `sendBody`, which waits for the
 * peer's flow-control window, RFC 9113 section 5.2), and a `flush` suspends while more than [limit] flushed bytes have not
 * been handed to the stream yet. A writer that is ahead of a peer that reads slowly is therefore held back at the
 * stream's window plus [limit] (plus what it has written but not flushed), never at the 1 MiB of each side of a Ktor
 * `ByteChannel` (up to about 3 MiB in all, as seen on Android, where its reader holds a buffer of its own).
 *
 * [flushAndClose] ends the stream: [send] gets an empty source with `end` true once the rest went out. [cancel] (a
 * session that failed) stops [done] without ending the stream; the owner resets it. A failure of [send] (the stream was
 * reset, the send-stall deadline) fails this channel with it ([failed]), so the writer's next call throws; it is never
 * thrown into [scope]. For the engines only.
 */
@InternalKuicksilverApi
public class H2StreamOutput(
    scope: CoroutineScope,
    private val limit: Int,
    send: suspend (source: ByteReadChannel, end: Boolean) -> Unit,
) : ByteWriteChannel {
    private val buffer = Buffer()
    private val channel = ByteChannel()
    private var flushed = 0L
    private val handed = MutableStateFlow(0L)

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
                    send(ByteReadChannel(chunk.copyOf(n)), false)
                    handed.update { it + n }
                }
                send(ByteReadChannel.Empty, true)
            } catch (e: Throwable) {
                // kept here, never thrown into [scope] (a call's): the writer's next call and [closedCause] report it
                failure = e
                channel.cancel(e)
                handed.value = Long.MAX_VALUE // releases a writer waiting in flush, which then throws
            }
        }

    override val isClosedForWrite: Boolean get() = closed

    /** The stream took everything and its END_STREAM: closed by [flushAndClose], nothing failed. */
    public val endedInOrder: Boolean get() = done.isCompleted && failure == null && cause == null && closed

    /** Why handing the bytes to the stream failed, if it did. */
    public val failed: Throwable? get() = failure

    override val closedCause: Throwable? get() = cause ?: failure

    @InternalAPI
    override val writeBuffer: Sink
        get() {
            check(!closed) { "the channel is closed" }
            failure?.let { throw it }
            return buffer
        }

    override suspend fun flush() {
        failure?.let { throw it }
        if (buffer.size > 0) {
            val bytes = buffer.readByteArray()
            channel.writeFully(bytes)
            channel.flush()
            flushed += bytes.size
        }
        val bound = flushed - limit
        if (handed.value < bound) handed.first { it >= bound }
        failure?.let { throw it }
    }

    override suspend fun flushAndClose() {
        if (closed) return
        try {
            flush()
        } finally {
            closed = true
            channel.flushAndClose()
        }
    }

    override fun cancel(cause: Throwable?) {
        if (closed && this.cause != null) return
        closed = true
        this.cause = cause ?: kotlinx.io.IOException("the channel was cancelled")
        buffer.clear()
        channel.cancel(this.cause)
    }

    private companion object {
        /** The most handed to the stream at a time (one DATA frame of the default size). */
        const val CHUNK = 16_384
    }
}
