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

/**
 * The receiving half. Only the peer's FIN, with every byte before it taken, is the end of the stream (`isClosedForRead`,
 * -1 from `readAvailable`); a RESET_STREAM, a lost connection or our own STOP_SENDING fails every read with its cause
 * instead. A lost connection does so only once the bytes the peer sent before it are read: what the core holds of the
 * stream (contiguous, up to a FIN it may include, a clean end then) is still delivered, as a peer that sends its last
 * bytes and closes at once (Firefox closing a WebTransport session) expects. ktor-io's own `ByteChannel` reports a
 * cause as "closed" and lets `readAvailable` answer -1, which an application cannot tell from a complete stream (the
 * interop client wrote a truncated download, 0.2.0 release gate); so a failed input is never "closed for read", and
 * `readBuffer` and `awaitContent` throw the cause, as `readAvailable` and every other ktor-io read goes through one of
 * them. [closedCause] still tells why.
 */
@OptIn(ExperimentalKuicksilverApi::class, io.ktor.utils.io.InternalAPI::class)
internal class StreamInput(
    private val stream: StreamRuntime,
) : ByteReadChannel {
    private val buffer = Buffer()
    private val tmp = ByteArray(16384)

    /** The FIN was taken from the core: all the peer's data is in [buffer] or was read; a later cause changes nothing. */
    @Volatile private var eof = false

    @Volatile override var closedCause: Throwable? = null
        private set

    /**
     * The connection is gone: nothing more arrives, but what the core holds of the stream is still read (up to its FIN,
     * then a clean end); once it held nothing more, this fails the input.
     */
    @Volatile private var lostCause: Throwable? = null

    override val readBuffer: Source get() {
        closedCause?.let { throw it }
        return buffer
    }
    override val isClosedForRead: Boolean get() = eof && buffer.exhausted()

    private fun failNow(cause: Throwable): Throwable {
        if (closedCause == null) closedCause = cause
        return closedCause!!
    }

    override suspend fun awaitContent(min: Int): Boolean {
        if (eof) return buffer.size >= min
        closedCause?.let { throw it }
        if (buffer.size >= min) return true
        return withContext(stream.loop.dispatcher) {
            while (true) {
                if (eof) return@withContext buffer.size >= min
                closedCause?.let { throw it }
                var pulled = 0
                var touched = false
                var resetSeen: Throwable? = null
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
                            // -1 is also the end of a reset stream, whose event the loop may not have handed over yet (its
                            // flush waits in a send): that is no end of the stream, it fails like the reset
                            val reset = stream.conn.core.streams.lastReadResetCode
                            if (reset != null) {
                                resetSeen = QuicException.StreamError.Reset(stream.id, reset, Initiator.Peer)
                            } else {
                                touched = !eof
                                eof = true
                            }
                        }
                        break
                    }
                }
                // credit (MAX_STREAM_DATA / MAX_DATA) and MAX_STREAMS (a consumed stream) leave as the application consumes;
                // a connection that is gone sends nothing more
                if (touched && lostCause == null) stream.loop.flush(stream.conn.core)
                if (buffer.size >= min) return@withContext true
                resetSeen?.let { throw failNow(it) }
                if (eof) return@withContext false
                // the core held nothing more of a stream whose connection is gone: it is cut short there
                lostCause?.let { throw failNow(it) }
                try {
                    stream.readable.receive()
                } catch (
                    e: CancellationException,
                ) {
                    throw e
                } catch (_: Throwable) {
                    // the signal channel closed: with a cause, the next round throws it, and with a lost connection it reads
                    // what is left first (answering here made a waiting reader take the end of its input for a clean one:
                    // readAvailable answered 0); a finished stream has nothing more
                    if (closedCause == null && lostCause == null) return@withContext buffer.size >= min
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

    /**
     * The connection is gone with [cause]: the bytes the core holds are still read, up to the FIN if it came; then the
     * input fails with [cause]. A FIN already taken leaves the stream complete.
     */
    fun connectionLost(cause: Throwable) {
        if (lostCause == null && !eof) lostCause = cause
        stream.readable.close()
    }

    /** Fails the input with [cause] unless the peer's FIN was already taken: a complete stream stays complete. */
    fun closeWith(cause: Throwable) {
        if (closedCause == null && !eof) closedCause = cause
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
        // read again: the loop may have closed the stream (cause first, then the flag) between the two reads above, and the
        // exception must carry the connection's reason, not none
        if (isClosedForWrite) throw ClosedWriteChannelException(closedCause)
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
