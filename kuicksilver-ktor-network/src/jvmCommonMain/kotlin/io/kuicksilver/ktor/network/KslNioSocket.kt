// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectInterest
import io.ktor.network.selector.Selectable
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.Socket
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ReaderJob
import io.ktor.utils.io.availableForRead
import io.ktor.utils.io.cancel
import io.ktor.utils.io.read
import io.ktor.utils.io.reader
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException
import java.net.StandardSocketOptions
import java.nio.channels.ClosedChannelException
import java.nio.channels.SocketChannel
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * A ktor-network JVM TCP socket whose write side is Kuicksilver's own writer; reading stays ktor's (CIOReader selects when a
 * read answers 0).
 *
 * ktor-network 3.6.0's writer (`attachForWritingDirectImpl`, CIOWriter.kt) loops `while (buffer.hasRemaining()) { do { rc =
 * write(buffer) } while (buffer.hasRemaining() && rc > 0) }` inside `channel.read {}`: when the kernel's send buffer is full
 * `write` answers 0 and the outer loop retries at once, so the select after it is never reached. Every peer that reads slower
 * than we write kept a `Dispatchers.IO` thread at 100 % CPU, and the loop cannot be cancelled; some 64 such peers exhaust
 * `Dispatchers.IO` (0.2.1 review). This writer writes what the channel holds, and when `write` answers 0
 * suspends in [SelectorManager.select] on the socket's own selector until the socket is writable again: a slow or silent peer
 * costs a suspended coroutine, and cancelling the socket's job ends the wait.
 *
 * Closing: the write channel is flushed and closed, the writer drains it and shuts the output down (a FIN, as ktor's writer
 * does), and then the ktor socket is closed, which closes the descriptor once its reader has ended; when the writer had ended
 * already, at once. The drain is bounded by [closeTimeout] when one is set: past it the writer is cancelled. A writer that is cancelled (by that bound or
 * by the socket's job) or fails (a reset, or a failed channel) closes the descriptor itself, so a socket never stays open
 * behind a stalled write; a failed one with a reset, so the peer sees the stream cut, not ended.
 * Writing after [close] fails with an IOException, as with ktor's sockets.
 */
internal class KslNioSocket(
    private val delegate: Socket,
    private val selector: SelectorManager,
    closeTimeout: Duration?,
) : Socket by delegate {
    private val selectable = delegate as Selectable
    private val nio = selectable.channel as SocketChannel
    private val closing = AtomicBoolean(false)

    /** Set by [abort] before it cancels the writer: the writer then ends without shutting the output down. */
    @Volatile private var aborted = false

    @Volatile private var writer: ReaderJob? = null

    /**
     * How long [close] lets the writer drain what is queued before it drops the rest and closes the socket; null: as long as
     * the peer takes. Owned by whoever opened the socket ([setCloseTimeout]): a client's connection 3 s (closing after the
     * response is complete drops nothing it wants), a server's accepted one none of its own, since a fixed bound would cut a
     * slow reader's last response short; whoever accepted the socket bounds it (setCloseTimeout).
     */
    @Volatile internal var closeTimeout: Duration? = closeTimeout

    /** Times a write answered 0 and the writer waited for the socket to become writable (tests). */
    internal val writeWaits = AtomicLong()

    /** Bytes the kernel has taken from the writer ([bytesSent]): the progress of a drain. */
    internal val bytesWritten = AtomicLong()

    /** The ktor socket underneath, for what only it offers ([Selectable.channel], e.g. an abort with SO_LINGER 0). */
    internal val ktorSocket: Socket get() = delegate

    /** False once the descriptor is closed (tests). */
    internal val isOpen: Boolean get() = nio.isOpen

    override fun attachForWriting(channel: ByteChannel): ReaderJob {
        if (closing.get()) {
            val e = IOException("Socket closed")
            channel.cancel(e)
            throw e
        }
        check(writer == null) { "writing channel has already been set" }
        val job = delegate.reader(Dispatchers.IO + CoroutineName("ksl-tcp-writer"), channel) { writeLoop(this.channel) }
        writer = job
        // cancelled (the socket's job, or close()'s bound): nothing will drain the rest, release the descriptor; a failed writer
        // closed it already (writeLoop), since `reader` completes its job normally after a failure
        job.job.invokeOnCompletion { cause -> if (cause != null) runCatching { nio.close() } }
        return job
    }

    private suspend fun writeLoop(channel: ByteReadChannel) {
        selectable.interestOp(SelectInterest.WRITE, false)
        try {
            while (true) {
                if (channel.availableForRead == 0 && !channel.awaitContent()) break
                var blocked = false
                channel.read { buffer ->
                    val n = nio.write(buffer)
                    if (n == 0) blocked = true else bytesWritten.addAndGet(n.toLong())
                }
                if (blocked) {
                    writeWaits.incrementAndGet()
                    selectable.interestOp(SelectInterest.WRITE, true)
                    try {
                        selector.select(selectable, SelectInterest.WRITE)
                    } finally {
                        selectable.interestOp(SelectInterest.WRITE, false) // writable again: no wake-ups until the next 0
                    }
                }
            }
        } catch (e: Throwable) {
            // a reset, another I/O error, or the application's channel failed (a handler that threw mid-response): `reader`
            // closes the channel with it (the application's writes fail) and completes the job normally, so the descriptor
            // is closed here, with a reset (SO_LINGER 0) as abort() does: a FIN would end the stream as if complete, and a
            // peer reading to the end of a close-delimited body would take the cut one for the whole
            if (e !is CancellationException) {
                runCatching { nio.setOption(StandardSocketOptions.SO_LINGER, 0) }
                runCatching { nio.close() }
            }
            throw e
        } finally {
            selectable.interestOp(SelectInterest.WRITE, false)
            // an aborted socket ends with the reset of its close: a FIN first would reach the peer as a clean end
            if (!aborted) {
                try {
                    nio.shutdownOutput()
                } catch (_: ClosedChannelException) {
                } catch (_: IOException) {
                }
            }
        }
    }

    override fun close() {
        if (!closing.compareAndSet(false, true)) return
        val w = writer
        if (w == null) {
            delegate.close()
            return
        }
        // the ktor socket closes once the writer has ended, at once when it already has (a drained, failed or cancelled writer)
        w.job.invokeOnCompletion { delegate.close() }
        delegate.launch(CoroutineName("ksl-tcp-close")) {
            // bounded, the flush too: a peer that stops reading would hold the drain, and with it the socket, as long as it likes
            val drain: suspend () -> Unit = {
                try {
                    w.channel.flushAndClose()
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Throwable) {
                    // closed or failed already: the writer ends on its own
                }
                w.job.join()
            }
            val bound = closeTimeout
            if (bound == null) {
                drain()
            } else if (withTimeoutOrNull(bound) { drain() } == null) {
                w.job.cancel()
            }
        }
    }

    override fun dispose(): Unit = close()

    /**
     * [abort]: closes at once, dropping what is queued with a reset (`SO_LINGER` 0): the writer is cancelled, which closes
     * the descriptor, and the ktor socket then closes as after any writer.
     */
    internal fun abort() {
        aborted = true
        runCatching { nio.setOption(StandardSocketOptions.SO_LINGER, 0) }
        close()
        writer?.job?.cancel()
    }
}

/** How long a client connection's [KslNioSocket.close] waits for the writer to drain: as long as `TlsSocket.close` waits. */
internal val CLIENT_CLOSE_TIMEOUT: Duration = 3.seconds

/** A ktor-network JVM listening socket whose accepted sockets are [KslNioSocket]s. */
internal class KslNioServerSocket(
    private val delegate: ServerSocket,
    private val selector: SelectorManager,
) : ServerSocket by delegate {
    override suspend fun accept(): Socket = KslNioSocket(delegate.accept(), selector, closeTimeout = null) // the engine owns the bound

    override fun dispose(): Unit = delegate.close()
}
