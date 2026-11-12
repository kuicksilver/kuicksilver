// Copyright 2014-2025 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Adapted from Ktor 3.6.0 ktor-network (SocketBase, NativeSocketImpl, CIOReader, CIOWriter, TCPSocketNative,
// TCPServerSocketNative, ConnectUtilsNative; internal there): the same socket life cycle on ktor-network's public selector API,
// over this module's system calls (TcpSys.kt), which bind and connect the address itself instead of ktor-network's native
// bind and connect (Ktor issue KTOR-10017, security, under coordinated disclosure). Reads and writes go through a buffer
// of their own instead of the channel's internal memory.
@file:OptIn(ExperimentalAtomicApi::class, InternalKuicksilverApi::class)

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
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.coroutines.CoroutineContext
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/** The listen backlog of ktor-network's native TCP server socket. */
private const val BACKLOG = 50

/** Bytes per `recv`/`send` call. */
private const val IO_BUFFER = 8192

/**
 * How long a pending connect waits for the selector before it looks at the socket itself, or null to wait until the
 * selector reports it. Windows posts `FD_CONNECT` once, like `FD_CLOSE`, and ktor-network's selector there can lose such
 * an event (see [tcpReadRecheck]): a connect that completed or failed meanwhile would wait for ever, and callers of
 * [connectTcp] outside the engines (which bound it with their connect timeout) have no other bound (review 2026-10-28
 * readwait.md R2).
 */
internal val tcpConnectRecheck: Duration? = tcpReadRecheck

/**
 * How long a connect whose selector wait is bounded ([tcpConnectRecheck]) may stay pending with no verdict from the socket
 * (`SO_ERROR` 0 and not connected) before it fails: the longest a system's own connect timeout runs (Windows retries a SYN
 * for about 21 s, Linux for about 2 minutes), so a failure whose error the lost event took with it ends too.
 */
internal val CONNECT_UNDECIDED_LIMIT: Duration = 3.minutes

/**
 * Waits for the pending connect of [fd]: connected once `SO_ERROR` is 0 and [tcpConnectedNow] says so, failed with any
 * other error that is not "not yet". With [recheck] the selector's wait is given up after that long (the select is
 * kept for the next wait) and the socket is looked at; after [undecidedLimit] of rechecks without a verdict the connect
 * fails. [rechecks] counts the waits that gave up (tests).
 */
internal suspend fun awaitConnected(
    selector: SelectorManager,
    socket: NativeTcpSocket,
    fd: Int,
    recheck: Duration?,
    undecidedLimit: Duration = CONNECT_UNDECIDED_LIMIT,
    rechecks: (() -> Unit)? = null,
) = awaitConnectedWith(
    select = { selector.select(socket, SelectInterest.CONNECT) },
    pendingError = { tcpPendingError(fd) },
    connected = { tcpConnectedNow(fd) },
    wouldBlock = ::tcpWouldBlock,
    failed = { throw PosixException.forErrno(it, "connect") },
    recheck = recheck,
    undecidedLimit = undecidedLimit,
    rechecks = rechecks,
)

/**
 * [awaitConnected] over its seams (tests drive it without sockets): [select] waits for the selector's CONNECT report,
 * [pendingError] reads `SO_ERROR`, [connected] asks the system whether the connect completed ([tcpConnectedNow]), [failed]
 * throws for an error. A report with no error that is not connected fails at once: the selector reports a connect once
 * (Windows posts FD_CONNECT once), so nothing more will come.
 */
internal suspend fun awaitConnectedWith(
    select: suspend () -> Unit,
    pendingError: () -> Int,
    connected: () -> Boolean,
    wouldBlock: (Int) -> Boolean,
    failed: (Int) -> Nothing,
    recheck: Duration?,
    undecidedLimit: Duration = CONNECT_UNDECIDED_LIMIT,
    rechecks: (() -> Unit)? = null,
) {
    if (recheck == null) {
        while (true) {
            select()
            val error = pendingError()
            if (error == 0) return
            if (!wouldBlock(error)) failed(error)
        }
    }
    coroutineScope {
        var pending: Deferred<Unit>? = null
        var undecided = Duration.ZERO
        try {
            while (true) {
                val wait = pending ?: async(start = CoroutineStart.UNDISPATCHED) { select() }.also { pending = it }
                val reported = withTimeoutOrNull(recheck) { wait.await() } != null
                if (reported) pending = null else rechecks?.invoke()
                val error = pendingError()
                if (error != 0 && !wouldBlock(error)) failed(error)
                if (error == 0 && connected()) return@coroutineScope
                if (reported && error == 0) {
                    throw IOException("the connect was reported done, but the socket is neither connected nor failed")
                }
                if (!reported) {
                    undecided += recheck
                    if (undecided >= undecidedLimit) {
                        throw IOException("the connect was neither completed nor failed after $undecided (its event was lost)")
                    }
                }
            }
        } finally {
            pending?.cancel()
        }
    }
}

/** How many times [NativeTcpSocket.readRecheck] an idle read waits at most between two receives (1 s grows to 8 s on Windows). */
private const val MAX_READ_BACKOFF = 8

/**
 * The idle backoff of a bounded wait for data: the next wait is [base], doubled each time a wait gives up with nothing
 * read, up to [MAX_READ_BACKOFF] times [base], and [base] again once data was read.
 */
internal class ReadBackoff(
    val base: Duration,
) {
    var next: Duration = base
        private set

    fun gaveUp() {
        next = minOf(next * 2, base * MAX_READ_BACKOFF)
    }

    fun dataRead() {
        next = base
    }
}

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
    receiveBufferSize: Int,
): Socket {
    require(receiveBufferSize >= 0) { "receiveBufferSize $receiveBufferSize is negative" }
    var last: Throwable? = null
    for (address in resolveTcp(remote.hostname, remote.port)) {
        try {
            return connectTcpAddressWith(selector, address, tcpConnectRecheck, receiveBufferSize = receiveBufferSize)
        } catch (e: IOException) {
            last = e
        }
    }
    throw IOException("Failed to connect to $remote.", last)
}

@InternalKuicksilverApi
public actual suspend fun connectTcpAddress(
    selector: SelectorManager,
    address: TcpAddress,
): Socket = connectTcpAddressWith(selector, address, tcpConnectRecheck)

/**
 * [connectTcpAddress] with the bounds of [awaitConnected] given (tests use short ones). [start] begins the connect and
 * says whether it completed at once ([tcpConnect]); tests leave it pending without sending a SYN, a stall no network
 * decides.
 */
internal suspend fun connectTcpAddressWith(
    selector: SelectorManager,
    address: TcpAddress,
    recheck: Duration?,
    undecidedLimit: Duration = CONNECT_UNDECIDED_LIMIT,
    receiveBufferSize: Int = 0,
    start: (fd: Int, to: Sockaddr) -> Boolean = ::tcpConnect,
    rechecks: (() -> Unit)? = null,
): Socket {
    tcpStartup()
    val to = Sockaddr.of(address)
    val fd =
        try {
            tcpOpen(to.family).also { fd ->
                if (receiveBufferSize > 0) {
                    try {
                        tcpReceiveBuffer(fd, receiveBufferSize)
                    } catch (e: Throwable) {
                        tcpClose(fd)
                        throw e
                    }
                }
            }
        } catch (e: PosixException) {
            throw IOException("Failed to connect to $address.", e)
        }
    val socket = NativeTcpSocket(selector, fd, to.toInet(), null)
    try {
        if (!start(fd, to)) awaitConnected(selector, socket, fd, recheck, undecidedLimit, rechecks)
        return socket
    } catch (e: PosixException) {
        socket.close()
        throw IOException("Failed to connect to $address.", e)
    } catch (e: Throwable) {
        socket.close() // cancelled (a Happy Eyeballs loser, a connect timeout): the descriptor goes with it
        throw e
    }
}

internal actual fun platformResolveTcp(
    name: String,
    port: Int,
    numericHost: Boolean,
): List<TcpAddress> {
    tcpStartup()
    return tcpResolve(name, port, numericHost).map { it.toTcpAddress() }
}

/** None here: the system's own caches (mDNSResponder, the Windows DNS client, systemd-resolved) do it, as before. */
internal actual fun platformLookupCacheTtl(): LookupTtl = LookupTtl(0, 0)

internal actual fun platformResolveFamily(
    name: String,
    ipv6: Boolean,
): List<TcpAddress> = kslResolveFamily(name, ipv6) ?: throw IOException("Failed to resolve $name: the native library is not usable")

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
                NativeTcpSocket(selector, fd, Sockaddr(peer).toInet(), socketContext)
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

    /** The application's side of [readerJob], as given to [attachForWriting] (closeFromSocketClose). */
    private val writeChannel = AtomicReference<ByteChannel?>(null)
    private val writerJob = AtomicReference<WriterJob?>(null)

    /** The read loop ([writerJob]) has ended (tests: the close order). */
    internal val readLoopEnded: Boolean get() = writerJob.load()?.isCompleted ?: true

    /** The write loop ([readerJob]) has ended (tests: the close order). */
    internal val writeLoopEnded: Boolean get() = readerJob.load()?.isCompleted ?: true

    /** How the read loop fails its channel ([openDeliveringReadChannel]). */
    internal val readDelivery: ReadDelivery = ReadDelivery()

    /** The write loop's send failures, for the read loop ([SendFailures]). */
    internal val sendFailures = SendFailures()

    /**
     * Held, when set, by the read loop once a receive returned the end of the stream, before it asks [sendFailures] what that
     * end stands for (tests: a send that fails in between).
     */
    @Volatile internal var atReadEndForTest: (suspend () -> Unit)? = null

    /** Why the connection is gone, as the read loop's receive failed ([connectionLost]): a wait for room fails with it. */
    private val lost = AtomicReference<Throwable?>(null)

    /** The waits for room of the write loop ([RoomWait]), cancelled when the connection is [lost]. */
    private val roomWaits = AtomicReference<Job?>(null)

    /** How long a wait for room lasts before the send is tried again ([ROOM_RECHECK]; tests shorten or lengthen it). */
    @Volatile internal var roomRecheck: Duration = ROOM_RECHECK

    /**
     * How long a wait for data lasts before the receive is tried again ([ReadWait]); null: until the selector reports the
     * socket readable ([tcpReadRecheck]: bounded on Windows only; tests set it).
     */
    @Volatile internal var readRecheck: Duration? = tcpReadRecheck

    /** Each wait for data that [ReadWait] gave up, as how long it waited (tests: the idle backoff). */
    internal val readRechecksForTest = kotlinx.coroutines.flow.MutableStateFlow<List<Duration>>(emptyList())

    override fun close() {
        if (!closeFlag.compareAndSet(expectedValue = false, newValue = true)) return
        // ATOMIC: a socket whose job was cancelled already (a hard stop cancels the listening socket's job, whose children the
        // accepted sockets are) still runs this; a plain launch there never started, the loops had ended without the close
        // flag, and the descriptor stayed open (selector.notifyClosed, which closes it, never ran)
        @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
        launch(CoroutineName("socket-close"), start = CoroutineStart.ATOMIC) {
            try {
                // what was written is still sent: the write loop drains the closed channel, then ends; only then is the read
                // loop cancelled (its end shuts the read side down): cancelled earlier, a close with unread received data can
                // make the kernel drop the response's tail (Linux answers it with a reset)
                writeChannel.load()?.let { runCatching { it.closeFromSocketClose() } }
                readerJob.load()?.job?.join()
            } finally {
                // cancelled: nothing is drained any more, both loops end, and the descriptor closes once they have
                if (!isActive) readerJob.load()?.cancel()
                writerJob.load()?.cancel()
                checkChannels()
            }
        }
    }

    /** [abort]: the connection ends with a reset ([reset]), dropping what is unsent. */
    fun abort() {
        aborted = true
        reset(cancelWriteLoop = true)?.let { resetFailure = it }
    }

    /** Set by [abort]: the read side then fails with "The connection was aborted". */
    @Volatile private var aborted = false

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

    // the read channel is failed by the read loop alone, on its own coroutine ([ReadDelivery]): ktor's attachJob would
    // cancel it with the loop's cancellation, from the thread that cancels the loop (dropping a delivering channel's bytes,
    // and handing the reader a CancellationException)
    override fun attachForReading(channel: ByteChannel): WriterJob =
        attachFor("reading", channel, writerJob, attachJob = false) { readLoop(it) }

    override fun attachForWriting(channel: ByteChannel): ReaderJob =
        attachFor("writing", channel, readerJob) { writeLoop(it) }.also { writeChannel.store(channel) }

    private inline fun <J : ChannelJob> attachFor(
        name: String,
        channel: ByteChannel,
        ref: AtomicReference<J?>,
        attachJob: Boolean = true,
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
        if (attachJob) channel.attachJob(j)
        j.invokeOnCompletion { checkChannels() }
        return j
    }

    // started unconfined, so the loop's own failure handling is in place before a close can cancel it; it reads on IO
    private fun readLoop(user: ByteChannel): WriterJob =
        writer(Dispatchers.Unconfined, user) {
            val buffer = ByteArray(IO_BUFFER)
            var atEnd = false
            val data = ReadWait(this)
            try {
                withContext(Dispatchers.IO) {
                    while (!channel.isClosedForWrite) {
                        val n =
                            try {
                                tcpRecv(descriptor, buffer)
                            } catch (e: PosixException) {
                                connectionLost(e)
                                throw e
                            }
                        if (n > 0) {
                            data.dataRead()
                            channel.writeFully(buffer, 0, n)
                            channel.flush()
                        } else if (n == 0) {
                            atEnd = true
                            // the end a send that took the peer's reset left behind is no end ([SendFailures])
                            atReadEndForTest?.invoke()
                            sendFailures.settled()?.let { throw it }
                            break
                        } else {
                            data.await()
                        }
                    }
                }
            } catch (e: CancellationException) {
                // after a send that failed, the read side fails with that failure; after an abort, a reset (a failed
                // application stream) or a local close, with an IOException that says so: never a CancellationException,
                // which a reading coroutine would take for its own, nor an end, which the peer did not send (as on the
                // JVM). A delivering channel keeps what was received before it. Only the socket's job cancelled under the
                // loop leaves its cancellation
                val cause =
                    sendFailures.recorded ?: when {
                        aborted -> IOException("The connection was aborted")
                        resetFlag.load() -> IOException("The connection was reset")
                        closeFlag.load() -> IOException("Socket closed")
                        else -> null
                    }
                readDelivery.fail(channel, cause ?: e)
                throw e
            } catch (e: Throwable) {
                // a receive error (a reset) or a select that fails is not the peer's end: the channel fails with it (a send's
                // failure that came first is the cause). The close below ran first and closed it cleanly (a select failure
                // even broke out of the loop as if at the end), so a reader took a cut stream for a complete one
                val cause = sendFailures.recorded ?: if (aborted) IOException("The connection was aborted", e) else e
                readDelivery.fail(channel, cause)
                throw cause
            } finally {
                data.cancel()
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
                        val sent = sendFailures.send { tcpSend(descriptor, buffer, offset, n - offset) }
                        if (sent < 0) {
                            room.await()
                        } else if (sent == 0) {
                            // nothing taken of a non-empty send: the stream is cut like after a send error
                            val cut =
                                IOException(
                                    "Failed writing to closed socket. Some bytes remaining: ${n - offset + channel.availableForRead}",
                                )
                            sendFailures.send<Unit> { throw cut }
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
                    // a send the system refused: the read side fails with that failure ([SendFailures]) before the reset
                    // cancels the read loop, whose cancellation would otherwise reach the reader as a CancellationException
                    // (a delivering channel is failed by the read loop itself, after its bytes)
                    sendFailures.recorded?.let { failed ->
                        writerJob
                            .load()
                            ?.channel
                            ?.takeIf { !readDelivery.delivers(it) }
                            ?.cancel(failed)
                    }
                    reset(cancelWriteLoop = false)?.let { e.addSuppressed(it) }
                }
                throw e
            } finally {
                room.cancel()
            }
        }.apply { invokeOnCompletion { if (!resetFlag.load()) tcpShutdown(descriptor, TCP_SHUT_WR) } }

    /**
     * The read loop's wait for data: a READ select, given up after [readRecheck] (when set) so the loop tries the receive
     * again, which returns the data or the end of the stream the selector did not report (see [tcpReadRecheck]). Like
     * [RoomWait], the select outlives a wait that gave up and serves the next one: an idle connection leaves one select
     * behind, not one per recheck. While nothing arrives the recheck backs off, doubling up to [MAX_READ_BACKOFF] times
     * [readRecheck] (1, 2, 4, 8 s on Windows), and starts over once data was read: an idle keep-alive connection costs a
     * receive every 8 s instead of every second (review 2026-10-28 readwait.md R3), and a lost end of stream right after
     * data still shows within [readRecheck].
     */
    private inner class ReadWait(
        scope: CoroutineScope,
    ) {
        private val waits = SupervisorJob(scope.coroutineContext.job)
        private val waitScope = CoroutineScope(scope.coroutineContext + waits)
        private var select: Deferred<Unit>? = null
        private var backoff: ReadBackoff? = null

        /** Returns when the receive may be tried again: the socket is readable, or the recheck has passed. */
        suspend fun await() {
            val base = readRecheck ?: return selector.select(this@NativeTcpSocket, SelectInterest.READ)
            val steps = backoff?.takeIf { it.base == base } ?: ReadBackoff(base).also { backoff = it }
            val recheck = steps.next
            val pending =
                select ?: waitScope
                    .async(start = CoroutineStart.UNDISPATCHED) { selector.select(this@NativeTcpSocket, SelectInterest.READ) }
                    .also { select = it }
            try {
                if (withTimeoutOrNull(recheck) { pending.await() } != null) {
                    select = null
                } else {
                    readRechecksForTest.value += recheck
                    steps.gaveUp()
                }
            } catch (e: Throwable) {
                select = null // a select that failed is not kept: the read loop ends with its failure
                throw e
            }
        }

        /** Data was read: the next wait gives up after [readRecheck] again. */
        fun dataRead() {
            backoff?.dataRead()
        }

        /** Cancels the select in flight: the read loop has ended. */
        fun cancel() = waits.cancel()
    }

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
     * serves the next one, so a peer that reads nothing for long leaves one select behind, not one per recheck. Internal for
     * the tests.
     */
    internal inner class RoomWait(
        private val scope: CoroutineScope,
    ) {
        private val waits = SupervisorJob(scope.coroutineContext.job)
        private val waitScope = CoroutineScope(scope.coroutineContext + waits)
        private var select: Deferred<Unit>? = null

        init {
            roomWaits.store(waits)
            if (lost.load() != null) waits.cancel()
        }

        /** Returns when the send may be tried again: the socket is writable, or [roomRecheck] has passed. */
        suspend fun await() {
            val pending =
                select ?: waitScope
                    .async(start = CoroutineStart.UNDISPATCHED) { selector.select(this@NativeTcpSocket, SelectInterest.WRITE) }
                    .also { select = it }
            try {
                if (withTimeoutOrNull(roomRecheck) { pending.await() } != null) select = null
            } catch (e: CancellationException) {
                val cause = lost.load()
                if (cause != null && scope.isActive) throw IOException("Connection reset by peer", cause)
                throw e
            } catch (e: Throwable) {
                select = null // a select that failed is not kept: its failure is thrown once, the next wait selects again
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

internal actual fun Socket.holdReadEndForTest(hook: (suspend () -> Unit)?) {
    if (this is NativeTcpSocket) atReadEndForTest = hook
}

internal actual fun Socket.tcpReadDelivery(): ReadDelivery? = (this as? NativeTcpSocket)?.readDelivery

internal actual fun Socket.sendFailuresForTest(): SendFailures? = (this as? NativeTcpSocket)?.sendFailures

internal actual fun platformSourceAddress(destination: TcpAddress): TcpAddress? {
    tcpStartup()
    return udpSourceAddress(Sockaddr.of(destination))?.toTcpAddress()?.let { TcpAddress(it.bytes, 0, it.scopeId) }
}
