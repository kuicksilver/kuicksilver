// Copyright 2014-2025 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Adapted from Ktor 3.6.0 ktor-network (SocketBase, NativeSocketImpl, CIOReader, CIOWriter, TCPSocketNative,
// TCPServerSocketNative, ConnectUtilsNative; internal there): the same socket life cycle on ktor-network's public selector API,
// over this module's system calls (TcpSys.kt), which bind and connect the address itself; Ktor 3.6.0's NativeIPv6SocketAddress
// puts `::` into every IPv6 sockaddr (Ktor issue KTOR-10017). Reads and writes go through a buffer of their own
// instead of the channel's internal memory.
@file:OptIn(ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.ClosedChannelCancellationException
import io.ktor.network.selector.SelectInterest
import io.ktor.network.selector.Selectable
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.SocketAddress
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ChannelJob
import io.ktor.utils.io.ReaderJob
import io.ktor.utils.io.WriterJob
import io.ktor.utils.io.attachJob
import io.ktor.utils.io.availableForRead
import io.ktor.utils.io.cancel
import io.ktor.utils.io.errors.PosixException
import io.ktor.utils.io.getCancellationException
import io.ktor.utils.io.invokeOnCompletion
import io.ktor.utils.io.isCancelled
import io.ktor.utils.io.isCompleted
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.reader
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writer
import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.io.IOException
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.coroutines.CoroutineContext
import kotlin.time.Duration

/** The listen backlog of ktor-network's native TCP server socket. */
private const val BACKLOG = 50

/** Bytes per `recv`/`send` call. */
private const val IO_BUFFER = 8192

/** "[::1]" -> "::1": `getaddrinfo` takes no brackets. */
private fun String.unbracketed(): String = if (length >= 2 && first() == '[' && last() == ']') substring(1, length - 1) else this

@InternalKuicksilverApi
public actual suspend fun connectTcp(
    selector: SelectorManager,
    remote: InetSocketAddress,
): Socket {
    tcpStartup()
    var last: Throwable? = null
    for (resolved in tcpResolve(remote.hostname.unbracketed(), remote.port)) {
        val to = resolved.unmapped()
        val fd =
            try {
                tcpOpen(to.family)
            } catch (e: PosixException) {
                last = e
                continue
            }
        val socket = NativeTcpSocket(selector, fd, to.toInet(), null)
        try {
            if (!tcpConnect(fd, to)) {
                while (true) {
                    selector.select(socket, SelectInterest.CONNECT)
                    val error = tcpPendingError(fd)
                    if (error == 0) break
                    if (!tcpWouldBlock(error)) throw PosixException.forErrno(error, "connect")
                }
            }
            return socket
        } catch (e: PosixException) {
            socket.close()
            last = e
        } catch (e: Throwable) {
            socket.close()
            throw e
        }
    }
    throw IOException("Failed to connect to $remote.", last)
}

@InternalKuicksilverApi
public actual suspend fun bindTcp(
    selector: SelectorManager,
    host: String,
    port: Int,
): ServerSocket {
    tcpStartup()
    val at = tcpResolve(host.unbracketed(), port).firstOrNull()?.unmapped() ?: throw IOException("Failed to resolve address for $host")
    val fd = tcpOpen(at.family)
    try {
        tcpBindListen(fd, at, BACKLOG)
        return NativeTcpServerSocket(selector, fd, tcpAddressOf(fd, peer = false).toInet())
    } catch (e: Throwable) {
        tcpClose(fd)
        throw e
    }
}

/** A listening socket; accepted connections are children of its [socketContext], as in ktor-network. */
internal class NativeTcpServerSocket(
    private val selector: SelectorManager,
    override val descriptor: Int,
    override val localAddress: SocketAddress,
) : ServerSocket,
    Selectable,
    CoroutineScope {
    override val socketContext: CompletableJob = SupervisorJob(selector.coroutineContext[Job])
    override val coroutineContext: CoroutineContext = selector.coroutineContext + Dispatchers.Unconfined + socketContext
    private val closed = AtomicBoolean(false)

    override suspend fun accept(): Socket {
        val peer = ByteArray(SOCKADDR_STORAGE)
        while (true) {
            if (closed.load()) throw ClosedChannelCancellationException()
            val fd =
                try {
                    tcpAccept(descriptor, peer)
                } catch (e: PosixException) {
                    throw IOException("Accept failed", e)
                }
            if (fd == null) {
                selector.select(this, SelectInterest.ACCEPT)
                continue
            }
            return try {
                NativeTcpSocket(selector, fd, TcpAddress(peer).toInet(), socketContext)
            } catch (e: Throwable) {
                tcpClose(fd)
                throw e
            }
        }
    }

    override fun close() {
        if (!closed.compareAndSet(expectedValue = false, newValue = true)) return
        tcpShutdown(descriptor, TCP_SHUT_RDWR)
        // the CLOSE select goes in before notifyClosed, which closes the descriptor; a closed selector closes it at once
        launch(start = CoroutineStart.UNDISPATCHED) {
            try {
                selector.select(this@NativeTcpServerSocket, SelectInterest.CLOSE)
            } catch (_: IOException) {
            }
        }
        selector.notifyClosed(this)
        socketContext.complete()
    }
}

/** A connected socket: one read and one write loop on its channels; the descriptor closes once both have ended (after [close]). */
internal class NativeTcpSocket(
    private val selector: SelectorManager,
    override val descriptor: Int,
    override val remoteAddress: SocketAddress,
    parent: Job?,
) : Socket,
    Selectable {
    override val socketContext: CompletableJob = Job(parent)
    override val coroutineContext: CoroutineContext get() = socketContext
    override val localAddress: SocketAddress by lazy { tcpAddressOf(descriptor, peer = false).toInet() }

    private val closeFlag = AtomicBoolean(false)
    private val actualCloseFlag = AtomicBoolean(false)
    private val readerJob = AtomicReference<ReaderJob?>(null)
    private val writerJob = AtomicReference<WriterJob?>(null)

    override fun close() {
        if (!closeFlag.compareAndSet(expectedValue = false, newValue = true)) return
        launch(CoroutineName("socket-close")) {
            // what was written is still sent: the write loop drains the closed channel, then ends
            readerJob.load()?.channel?.let { runCatching { it.flushAndClose() } }
            writerJob.load()?.cancel()
            checkChannels()
        }
    }

    override fun attachForReading(channel: ByteChannel): WriterJob = attachFor("reading", channel, writerJob) { readLoop(it) }

    override fun attachForWriting(channel: ByteChannel): ReaderJob = attachFor("writing", channel, readerJob) { writeLoop(it) }

    private inline fun <J : ChannelJob> attachFor(
        name: String,
        channel: ByteChannel,
        ref: AtomicReference<J?>,
        producer: (ByteChannel) -> J,
    ): J {
        if (closeFlag.load()) {
            val e = IOException("Socket closed")
            channel.cancel(e)
            throw e
        }
        val j = producer(channel)
        if (!ref.compareAndSet(null, j)) {
            j.cancel()
            throw IllegalStateException("$name channel has already been set")
        }
        if (closeFlag.load()) {
            val e = IOException("Socket closed")
            j.cancel()
            channel.cancel(e)
            throw e
        }
        channel.attachJob(j)
        j.invokeOnCompletion { checkChannels() }
        return j
    }

    private fun readLoop(user: ByteChannel): WriterJob =
        writer(Dispatchers.IO, user) {
            val buffer = ByteArray(IO_BUFFER)
            try {
                while (!channel.isClosedForWrite) {
                    val n = tcpRecv(descriptor, buffer)
                    if (n > 0) {
                        channel.writeFully(buffer, 0, n)
                        channel.flush()
                    } else if (n == 0) {
                        break
                    } else {
                        try {
                            selector.select(this@NativeTcpSocket, SelectInterest.READ)
                        } catch (_: IOException) {
                            break
                        }
                    }
                }
            } finally {
                tcpShutdown(descriptor, TCP_SHUT_RD)
                channel.flushAndClose()
            }
        }

    private fun writeLoop(user: ByteChannel): ReaderJob =
        reader(Dispatchers.IO, user) {
            val buffer = ByteArray(IO_BUFFER)
            var socketClosed = false
            while (!socketClosed) {
                val n = channel.readAvailable(buffer, 0, buffer.size)
                if (n < 0) break
                var offset = 0
                while (offset < n) {
                    val sent = tcpSend(descriptor, buffer, offset, n - offset)
                    if (sent < 0) {
                        selector.select(this@NativeTcpSocket, SelectInterest.WRITE)
                    } else if (sent == 0) {
                        socketClosed = true
                        break
                    } else {
                        offset += sent
                    }
                }
            }
            if (!channel.isClosedForRead) {
                channel.cancel(IOException("Failed writing to closed socket. Some bytes remaining: ${channel.availableForRead}"))
            } else {
                channel.closedCause?.let { throw it }
            }
        }.apply { invokeOnCompletion { tcpShutdown(descriptor, TCP_SHUT_WR) } }

    private fun actualClose(): Throwable? =
        try {
            tcpShutdown(descriptor, TCP_SHUT_RDWR)
            // the CLOSE select goes in before notifyClosed, which closes the descriptor; a closed selector closes it at once
            launch(start = CoroutineStart.UNDISPATCHED) {
                try {
                    selector.select(this@NativeTcpSocket, SelectInterest.CLOSE)
                } catch (_: IOException) {
                }
            }
            null
        } catch (cause: Throwable) {
            cause
        } finally {
            selector.notifyClosed(this)
        }

    private fun checkChannels() {
        if (!closeFlag.load() || !readerJob.doneOrUnused() || !writerJob.doneOrUnused()) return
        if (!actualCloseFlag.compareAndSet(expectedValue = false, newValue = true)) return
        val combined = combine(combine(readerJob.failure(), writerJob.failure()), actualClose())
        if (combined == null) socketContext.complete() else socketContext.completeExceptionally(combined)
    }

    private fun AtomicReference<out ChannelJob?>.doneOrUnused(): Boolean = load().let { it == null || it.isCompleted }

    private fun AtomicReference<out ChannelJob?>.failure(): Throwable? =
        load()?.takeIf { it.isCancelled }?.getCancellationException()?.cause

    private fun combine(
        e1: Throwable?,
        e2: Throwable?,
    ): Throwable? =
        when {
            e1 == null -> e2
            e2 == null || e1 === e2 -> e1
            else -> e1.also { it.addSuppressed(e2) }
        }
}

// Kuicksilver's Native TCP socket closes once its writer has drained, with no bound of its own; TlsSocket bounds itself
internal actual fun Socket.setRawCloseTimeout(timeout: Duration?) {}
