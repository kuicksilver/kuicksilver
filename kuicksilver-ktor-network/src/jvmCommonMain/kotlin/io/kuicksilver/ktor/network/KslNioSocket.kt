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
import io.ktor.utils.io.read
import io.ktor.utils.io.reader
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.nio.channels.ClosedChannelException
import java.nio.channels.SocketChannel
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * A ktor-network JVM TCP socket whose write side is Kuicksilver's own writer; reading stays ktor's (CIOReader selects when a
 * read answers 0).
 *
 * ktor-network 3.6.0's writer (`attachForWritingDirectImpl`, CIOWriter.kt) loops `while (buffer.hasRemaining()) { do { rc =
 * write(buffer) } while (buffer.hasRemaining() && rc > 0) }` inside `channel.read {}`: when the kernel's send buffer is full
 * `write` answers 0 and the outer loop retries at once, so the select after it is never reached. Every peer that reads slower
 * than we write kept a `Dispatchers.IO` thread at 100 % CPU, and the loop cannot be cancelled; some 64 such peers exhaust
 * `Dispatchers.IO` (fable review of k8/native-fixes). This writer writes what the channel holds, and when `write` answers 0
 * suspends in [SelectorManager.select] on the socket's own selector until the socket is writable again: a slow or silent peer
 * costs a suspended coroutine, and cancelling the socket's job ends the wait.
 *
 * Closing: the write channel is flushed and closed, the writer drains it and shuts the output down (a FIN, as ktor's writer
 * does), and only then is the ktor socket closed, which closes the descriptor once its reader has ended. A writer that ends
 * by cancellation or failure closes the descriptor itself, so an aborted socket never stays open behind a stalled write.
 */
internal class KslNioSocket(
    private val delegate: Socket,
    private val selector: SelectorManager,
) : Socket by delegate {
    private val selectable = delegate as Selectable
    private val nio = selectable.channel as SocketChannel
    private val closing = AtomicBoolean(false)

    @Volatile private var writer: ReaderJob? = null

    /** Times a write answered 0 and the writer waited for the socket to become writable (tests). */
    internal val writeWaits = AtomicLong()

    /** The ktor socket underneath, for what only it offers ([Selectable.channel], e.g. an abort with SO_LINGER 0). */
    internal val ktorSocket: Socket get() = delegate

    /** False once the descriptor is closed (tests). */
    internal val isOpen: Boolean get() = nio.isOpen

    override fun attachForWriting(channel: ByteChannel): ReaderJob {
        check(writer == null) { "writing channel has already been set" }
        val job = delegate.reader(Dispatchers.IO + CoroutineName("ksl-tcp-writer"), channel) { writeLoop(this.channel) }
        writer = job
        job.job.invokeOnCompletion { cause ->
            if (cause != null) {
                runCatching { nio.close() } // cancelled or failed: nothing will drain the rest, release the descriptor
                delegate.close()
            } else if (closing.get()) {
                delegate.close() // close() waited for the drain; a writer the application ended alone only half-closed (FIN)
            }
        }
        return job
    }

    private suspend fun writeLoop(channel: ByteReadChannel) {
        selectable.interestOp(SelectInterest.WRITE, false)
        try {
            while (true) {
                if (channel.availableForRead == 0 && !channel.awaitContent()) break
                var blocked = false
                channel.read { buffer -> if (nio.write(buffer) == 0) blocked = true }
                if (blocked) {
                    writeWaits.incrementAndGet()
                    selectable.interestOp(SelectInterest.WRITE, true)
                    selector.select(selectable, SelectInterest.WRITE)
                }
            }
        } finally {
            selectable.interestOp(SelectInterest.WRITE, false)
            try {
                nio.shutdownOutput()
            } catch (_: ClosedChannelException) {
            } catch (_: java.io.IOException) {
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
        // the writer's completion closes the ktor socket (above), after what was written reached the kernel
        delegate.launch(CoroutineName("ksl-tcp-close")) { runCatching { w.channel.flushAndClose() } }
    }

    override fun dispose(): Unit = close()
}

/** A ktor-network JVM listening socket whose accepted sockets are [KslNioSocket]s. */
internal class KslNioServerSocket(
    private val delegate: ServerSocket,
    private val selector: SelectorManager,
) : ServerSocket by delegate {
    override suspend fun accept(): Socket = KslNioSocket(delegate.accept(), selector)

    override fun dispose(): Unit = delegate.close()
}
