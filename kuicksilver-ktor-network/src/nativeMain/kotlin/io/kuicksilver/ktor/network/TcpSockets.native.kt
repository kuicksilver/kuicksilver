// Copyright 2014-2025 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Adapted from Ktor 3.6.0 ktor-network (SocketBase, NativeSocketImpl, CIOReader, CIOWriter, TCPSocketNative,
// TCPServerSocketNative, ConnectUtilsNative; internal there): the same socket life cycle on ktor-network's public selector API,
// over this module's system calls (TcpSys.kt), which bind and connect the address itself instead of ktor-network's native
// bind and connect (Ktor issue KTOR-10017, security, under coordinated disclosure). Reads and writes go through a buffer
// of their own instead of the channel's internal memory.
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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.isActive
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.coroutines.CoroutineContext
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** The listen backlog of ktor-network's native TCP server socket. */
private const val BACKLOG = 50

/** Bytes per `recv`/`send` call. */
private const val IO_BUFFER = 8192

/**
 * How long the write loop waits for room before it tries the send again ([NativeTcpSocket.RoomWait]): the bound on how
 * long a reset the selector does not report keeps a writer waiting (Windows reports it as `FD_CLOSE`, not `FD_WRITE`).
 */
private val ROOM_RECHECK = 1.seconds

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

    /** Set once the connection ends with a reset ([reset]): no shutdown may then send a FIN ahead of it. */
    private val resetFlag = AtomicBoolean(false)

    /** Bytes the kernel has taken from the write loop ([bytesSent]): the progress of a drain. */
    val bytesWritten = AtomicLong(0L)
    private val actualCloseFlag = AtomicBoolean(false)
    private val readerJob = AtomicReference<ReaderJob?>(null)
    private val writerJob = AtomicReference<WriterJob?>(null)

    /** Why the connection is gone, as the read loop's receive failed ([connectionLost]): a wait for room fails with it. */
    private val lost = AtomicReference<Throwable?>(null)

    /** The waits for room of the write loop ([RoomWait]), cancelled when the connection is [lost]. */
    private val roomWaits = AtomicReference<Job?>(null)

    /** How long a wait for room lasts before the send is tried again ([ROOM_RECHECK]; tests shorten or lengthen it). */
    @Volatile internal var roomRecheck: Duration = ROOM_RECHECK

    override fun close() {
        if (!closeFlag.compareAndSet(expectedValue = false, newValue = true)) return
        launch(CoroutineName("socket-close")) {
            // what was written is still sent: the write loop drains the closed channel, then ends
            readerJob.load()?.channel?.let { runCatching { it.flushAndClose() } }
            writerJob.load()?.cancel()
            checkChannels()
        }
    }

    /** [abort]: the connection ends with a reset ([reset]), dropping what is unsent. */
    fun abort() {
        reset(cancelWriteLoop = true)?.let { resetFailure = it }
    }

    /** Why the last [abort] could not set `SO_LINGER` 0 (the close then sends a FIN); null when it could (tests). */
    @Volatile internal var resetFailure: Throwable? = null

    /**
     * Ends the connection with a reset: `SO_LINGER` 0, then closed with the loops cancelled and no shutdown, so the
     * descriptor's close sends a reset instead of a FIN and the kernel drops what was unsent. The peer sees an error, not
     * the end of a stream that was cut. A failed write loop ends by itself with its failure ([cancelWriteLoop] false): a
     * cancellation would hide that failure from the application's channel. Nothing is set on a descriptor the socket has
     * already released (its number may belong to another socket by now). Returns why `SO_LINGER` 0 could not be set, if
     * it could not: the socket is closed all the same.
     */
    private fun reset(cancelWriteLoop: Boolean): Throwable? {
        if (actualCloseFlag.load()) return null
        if (!resetFlag.compareAndSet(expectedValue = false, newValue = true)) return null
        val failure = runCatching { tcpLingerZero(descriptor) }.exceptionOrNull()
        close()
        if (cancelWriteLoop) readerJob.load()?.cancel()
        writerJob.load()?.cancel()
        return failure
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
            var atEnd = false
            try {
                while (!channel.isClosedForWrite) {
                    val n =
                        try {
                            tcpRecv(descriptor, buffer)
                        } catch (e: PosixException) {
                            connectionLost(e)
                            throw e
                        }
                    if (n > 0) {
                        channel.writeFully(buffer, 0, n)
                        channel.flush()
                    } else if (n == 0) {
                        atEnd = true
                        break
                    } else {
                        selector.select(this@NativeTcpSocket, SelectInterest.READ)
                    }
                }
            } catch (e: Throwable) {
                // a receive error (a reset) or a select that fails is not the peer's end: the channel fails with it. The
                // close below ran first and closed it cleanly (a select failure even broke out of the loop as if at the
                // end), so a reader took a cut stream for a complete one
                if (e !is CancellationException) channel.cancel(e)
                throw e
            } finally {
                // not on Windows before the end of the stream: input arriving after SD_RECEIVE resets the connection there,
                // so a server that stopped reading a request could lose the response it is about to write
                if (atEnd || tcpShutdownReadBeforeEnd) tcpShutdown(descriptor, TCP_SHUT_RD)
                channel.flushAndClose()
            }
        }

    private fun writeLoop(user: ByteChannel): ReaderJob =
        reader(Dispatchers.IO, user) {
            val room = RoomWait(this)
            try {
                val buffer = ByteArray(IO_BUFFER)
                while (true) {
                    val n = channel.readAvailable(buffer, 0, buffer.size)
                    if (n < 0) break
                    var offset = 0
                    while (offset < n) {
                        val sent = tcpSend(descriptor, buffer, offset, n - offset)
                        if (sent < 0) {
                            room.await()
                        } else if (sent == 0) {
                            // nothing taken of a non-empty send: the stream is cut like after a send error
                            throw IOException(
                                "Failed writing to closed socket. Some bytes remaining: ${n - offset + channel.availableForRead}",
                            )
                        } else {
                            offset += sent
                            bytesWritten.addAndFetch(sent.toLong())
                        }
                    }
                }
                channel.closedCause?.let { throw it }
            } catch (e: Throwable) {
                // a send error, or the application's channel failed (a handler that threw mid-response): the stream is cut,
                // and a FIN would end it as if complete (a peer reading a close-delimited body to the end would take the cut
                // one for the whole), so the connection ends with a reset. The application's channel fails first: the
                // reset's close flushes it, and that flush would take the place of an application's write waiting for
                // room, which then failed with ktor's ConcurrentIOException instead of this failure
                if (e !is CancellationException) {
                    channel.cancel(e)
                    reset(cancelWriteLoop = false)?.let { e.addSuppressed(it) }
                }
                throw e
            } finally {
                room.cancel()
            }
        }.apply { invokeOnCompletion { if (!resetFlag.load()) tcpShutdown(descriptor, TCP_SHUT_WR) } }

    /**
     * The read loop's receive failed (a reset): the connection is gone in both directions, so a write loop waiting for room
     * fails now. On Windows nothing else would wake it: ktor-network's selector waits for `FD_WRITE` there, and a reset
     * is reported as `FD_CLOSE` alone.
     */
    private fun connectionLost(cause: Throwable) {
        if (lost.compareAndSet(null, cause)) roomWaits.load()?.cancel()
    }

    /**
     * The write loop's wait for room in the send buffer: a WRITE select, given up after [roomRecheck] so the loop tries the
     * send again, which fails on a connection the peer has reset; and failed at once when the read loop finds the
     * connection [lost]. Without the bound, a writer on Windows waited for ever on a reset connection: ktor-network's
     * selector there (`WSAEventSelect`) waits for `FD_WRITE`, which a reset never brings (it is reported as `FD_CLOSE`,
     * once), where `poll`/`select` on POSIX report a reset socket as writable. The select outlives a wait that gave up and
     * serves the next one, so a peer that reads nothing for long leaves one select behind, not one per recheck.
     */
    private inner class RoomWait(
        private val scope: CoroutineScope,
    ) {
        private val waits = SupervisorJob(scope.coroutineContext.job)
        private var select: Deferred<Unit>? = null

        init {
            roomWaits.store(waits)
            if (lost.load() != null) waits.cancel()
        }

        /** Returns when the send may be tried again: the socket is writable, or [roomRecheck] has passed. */
        suspend fun await() {
            val pending =
                select ?: scope
                    .async(waits, start = CoroutineStart.UNDISPATCHED) { selector.select(this@NativeTcpSocket, SelectInterest.WRITE) }
                    .also { select = it }
            try {
                if (withTimeoutOrNull(roomRecheck) { pending.await() } != null) select = null
            } catch (e: CancellationException) {
                val cause = lost.load()
                if (cause != null && scope.isActive) throw IOException("Connection reset by peer", cause)
                throw e
            }
        }

        /** Cancels the select in flight: the write loop has ended. */
        fun cancel() = waits.cancel()
    }

    private fun actualClose(): Throwable? =
        try {
            if (!resetFlag.load()) tcpShutdown(descriptor, TCP_SHUT_RDWR)
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

internal actual fun Socket.rawBytesSent(): Long? = (this as? NativeTcpSocket)?.bytesWritten?.load()

internal actual fun Socket.abortTcp() {
    if (this is NativeTcpSocket) {
        abort()
    } else {
        close()
        socketContext.cancel()
    }
}
