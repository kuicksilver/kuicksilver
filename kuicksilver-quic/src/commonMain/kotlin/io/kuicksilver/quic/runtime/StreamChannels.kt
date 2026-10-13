// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.ClosedWriteChannelException
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.yield
import kotlinx.io.Buffer
import kotlinx.io.IOException
import kotlinx.io.Sink
import kotlinx.io.Source
import kotlin.concurrent.Volatile

// The two ktor-io halves of a [StreamRuntime]: StreamInput pulls from the core when the application awaits content,
// StreamOutput hands bytes to the core on every flush. Every core access hops onto the loop.

@OptIn(ExperimentalKuicksilverApi::class, io.ktor.utils.io.InternalAPI::class)
internal class StreamInput(
    private val stream: StreamRuntime,
) : ByteReadChannel {
    private val buffer = Buffer()
    private val tmp = ByteArray(16384)
    private var eof = false

    @Volatile override var closedCause: Throwable? = null
        private set
    override val readBuffer: Source get() = buffer
    override val isClosedForRead: Boolean get() = closedCause != null || (eof && buffer.exhausted())

    override suspend fun awaitContent(min: Int): Boolean {
        if (closedCause != null) return false
        if (buffer.size >= min) return true
        return withContext(stream.loop.dispatcher) {
            while (true) {
                if (closedCause != null) return@withContext false
                var pulled = 0
                var touched = false
                while (buffer.size < maxOf(min.toLong(), PULL_TARGET) &&
                    pulled < PULL_TARGET
                ) {
                    val n = stream.conn.core.readStream(stream.id, tmp, 0, tmp.size)
                    if (n >
                        0
                    ) {
                        buffer.write(tmp, 0, n)
                        pulled += n
                        touched = true
                    } else {
                        if (n <
                            0
                        ) {
                            touched = !eof
                            eof = true
                        }
                        break
                    }
                }
                // credit (MAX_STREAM_DATA / MAX_DATA) and MAX_STREAMS (a consumed stream) leave as the application consumes
                if (touched) stream.loop.flush(stream.conn.core)
                if (buffer.size >= min) return@withContext true
                if (eof) return@withContext false
                try {
                    stream.readable.receive()
                } catch (
                    e: CancellationException,
                ) {
                    throw e
                } catch (_: Throwable) {
                    return@withContext buffer.size >=
                        min
                }
            }
            @Suppress("UNREACHABLE_CODE")
            false
        }
    }

    override fun cancel(cause: Throwable?) {
        if (closedCause !=
            null
        ) {
            return
        }
        closeWith(cause ?: IOException("stream input cancelled"))
        stream.loop.scope.launch {
            stream.conn.core.stopSending(stream.id, stream.conn.defaultCode())
            stream.loop.flush(stream.conn.core)
        }
    }

    fun closeWith(cause: Throwable) {
        if (closedCause == null) closedCause = cause
        stream.readable.close()
    }

    private companion object {
        const val PULL_TARGET = 64 * 1024L
    }
}

@OptIn(ExperimentalKuicksilverApi::class, io.ktor.utils.io.InternalAPI::class)
internal class StreamOutput(
    private val stream: StreamRuntime,
) : ByteWriteChannel {
    private val buffer = Buffer()
    private val tmp = ByteArray(16384)
    override val autoFlush: Boolean get() = true

    @Volatile override var isClosedForWrite: Boolean = false
        private set

    @Volatile override var closedCause: Throwable? = null
        private set
    override val writeBuffer: Sink get() {
        closedCause?.let { throw ClosedWriteChannelException(it) }
        if (isClosedForWrite) throw ClosedWriteChannelException(null)
        return buffer
    }

    override suspend fun flush() {
        if (buffer.exhausted()) {
            closedCause?.let { throw ClosedWriteChannelException(it) }
            return
        }
        withContext(stream.loop.dispatcher) {
            drain()
            stream.loop.flush(stream.conn.core) // drain handed the data to the core; this sends it now
        }
    }

    /**
     * Hands every buffered byte to the core, on the loop. The loop is flushed only when the core's send buffer is full (to
     * make room by sending), so a caller can still add the FIN to the last frame before the packet is built.
     */
    private suspend fun drain() {
        var unsent = false
        while (!buffer.exhausted()) {
            closedCause?.let { throw ClosedWriteChannelException(it) }
            // copied, not consumed: only what the core accepted leaves the buffer, so a flush cancelled while waiting loses nothing
            val n = buffer.peek().readAtMostTo(tmp, 0, tmp.size)
            val w = writeToCore(tmp, 0, n, false)
            if (w > 0) {
                buffer.skip(w.toLong())
                unsent = true
            } else {
                // only a flush that sends what was handed over since the last one: every flush ticks every stream's ticker, so
                // flushing on each wake would wake this loop again at once and spin while the peer's credit stays at zero
                if (unsent) {
                    stream.loop.flush(stream.conn.core)
                    unsent = false
                }
                try {
                    stream.ticker.receive()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    // the core's 4 MiB send buffer is full: wait for ACKs; a lost connection surfaces as a closed channel with its reason
                    throw ClosedWriteChannelException(closedCause ?: e)
                }
            }
        }
    }

    /** Sends what is buffered and the FIN together: the last data and the FIN share one STREAM frame when they fit one packet. */
    override suspend fun flushAndClose() {
        closedCause?.let {
            throw ClosedWriteChannelException(it)
        } // the peer's STOP_SENDING or a reset: the writer learns it here, not from a silent return
        if (isClosedForWrite) return
        withContext(stream.loop.dispatcher) {
            drain()
            isClosedForWrite = true
            closedCause?.let { throw ClosedWriteChannelException(it) }
            writeToCore(tmp, 0, 0, fin = true)
            // the data and the FIN are the core's now: the send must not be lost to a cancellation. Yielding first lets the
            // closes already queued on the loop hand over theirs, so concurrent requests share packets instead of taking one
            // each (interop zerortt: one packet per request filled the initial window before the last 0-RTT requests left)
            withContext(NonCancellable) {
                yield()
                stream.loop.flush(stream.conn.core)
            }
        }
    }

    /** The core refuses writes to a stream it reset or retired; between the peer's STOP_SENDING and the runtime's event that is a stream error, never an IllegalStateException. */
    private fun writeToCore(
        data: ByteArray,
        off: Int,
        len: Int,
        fin: Boolean,
    ): Int =
        try {
            stream.conn.core.writeStream(stream.id, data, off, len, fin)
        } catch (e: IllegalStateException) {
            throw ClosedWriteChannelException(
                closedCause ?: QuicException.StreamError
                    .Reset(
                        stream.id,
                        stream.conn.defaultCode(),
                        Initiator.Local,
                    ).also {
                        closeWith(it)
                    },
            )
        }

    override fun cancel(cause: Throwable?) {
        if (isClosedForWrite) return
        closeWith(cause ?: IOException("stream output cancelled"))
        stream.loop.scope.launch {
            stream.conn.core.resetStream(stream.id, stream.conn.defaultCode())
            stream.loop.flush(stream.conn.core)
        }
    }

    fun closeWith(cause: Throwable) {
        if (closedCause == null) closedCause = cause
        isClosedForWrite = true
    }
}
