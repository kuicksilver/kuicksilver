// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.EndpointCore
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.core.fail
import io.kuicksilver.quic.core.failInternal
import io.kuicksilver.quic.ipLiteral
import io.kuicksilver.quic.withLiteralHost
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.time.Duration
import kotlin.time.TimeSource

/**
 * The endpoint loop (docs/architecture.md, `kuicksilver-quic`): one single-threaded dispatcher owns the [EndpointCore] and every [ConnectionCore].
 * Application calls hop onto that dispatcher (`withContext`), so they queue behind the loop's own work; nothing
 * blocks inside it. Datagrams arrive from a receiver coroutine, timers from a timer coroutine, both on the dispatcher.
 *
 * A flush visits only the connections something happened to since the last one (the core's dirty list) and the timer
 * coroutine keeps a heap of deadlines, so neither costs O(connections) per datagram. Several loops of one
 * [LoopGroup] share a port: a datagram whose connection ID names another loop ([EndpointCore.ownerLoop]) is copied to
 * that loop's [forwarded] channel; only the owner ever answers a Stateless Reset for it.
 */
@OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class, InternalKuicksilverApi::class)
internal class EndpointLoop private constructor(
    private val config: QuicEndpointConfig,
    private val io: DatagramIo,
    internal val dispatcher: CoroutineDispatcher,
    internal val index: Int = 0,
    private val group: LoopGroup? = null,
    private val pendingAccept: AtomicInt = AtomicInt(0),
    private val acceptQueue: Channel<QuicConnection> = acceptChannel(pendingAccept),
) : QuicEndpoint {
    /** Last-resort failures of coroutines the loop launched (none is expected to throw): counted, never handed to the thread's uncaught handler, which on Android kills the process. */
    internal val uncaughtFailures = AtomicLong(0)
    internal val scope =
        CoroutineScope(
            SupervisorJob() + dispatcher + kotlinx.coroutines.CoroutineExceptionHandler { _, _ -> uncaughtFailures.incrementAndFetch() },
        )

    // one unsynchronised CSPRNG stream per loop: every call into the core stays on this loop's thread
    internal val core = EndpointCore(config, KslRandom.newSource(), index)
    private val inBatch = PacketBatch(16, SLOT_SIZE)
    private val outBatch = PacketBatch(32, SLOT_SIZE)
    private val wake = Channel<Unit>(Channel.CONFLATED)
    private val flushLock = Mutex() // a suspending DatagramIo.send must not interleave with another flush over the same batch
    internal val runtimes = HashMap<ConnectionCore, ConnectionRuntime>()
    private val timers = TimerHeap()
    private val start = TimeSource.Monotonic.markNow()
    private val closingFlag = AtomicInt(0) // set once, by compare-and-set: two concurrent close() calls must not both tear down
    private val closing: Boolean get() = closingFlag.load() != 0
    override val localAddress: InetSocketAddress get() = io.localAddress

    /** A datagram another loop of the group hands over: [asReceived] ones are treated as if they arrived on this socket (test hook), the rest belong to a connection here. */
    internal class Forwarded(
        val bytes: ByteArray,
        val from: InetSocketAddress,
        val ecn: Ecn,
        val asReceived: Boolean,
    )

    internal val forwarded = Channel<Forwarded>(FORWARD_QUEUE)
    internal val forwardedCount = AtomicLong(0)

    /** Test hook: every datagram received on this socket is handed to loop [testMisrouteTo] as if the kernel had hashed it there. */
    @Volatile internal var testMisrouteTo: Int = -1

    internal fun now(): TimeMark = TimeMark(1_000_000_000L + start.elapsedNow().inWholeNanoseconds)

    private var receiveJob: kotlinx.coroutines.Job? = null
    private var forwardJob: kotlinx.coroutines.Job? = null

    /** Batches whose send threw (a transient socket error): the datagrams are treated as lost, nothing else happens. */
    internal var sendFailures = 0L

    internal val pendingAcceptForTest: Int get() = pendingAccept.load()

    /** Datagrams the sockets did not take (failed or partial sends), stateless replies included. */
    internal var socketDrops = 0L

    /** Server connections this loop adopted whose handshake has not completed yet (bookkeeping and tests; admission does not count them). */
    private var handshaking = 0

    @Volatile internal var handshakingForTest: Int = 0
        private set

    /** Handshakes that completed while the accept queue was full: refused with CONNECTION_REFUSED. */
    internal var acceptOverflows = 0L

    init {
        // admission counts only the connections waiting for accept(): counting unvalidated handshakes too would let
        // acceptQueue spoofed-source Initials per handshakeTimeout lock every client out before the admission policy (and
        // its Retry) could step in; the bound is enforced where a handshake completes (onHandshakeCompleted)
        core.acceptBacklog = { pendingAccept.load() }
    }

    /** Starts the receive, timer and forward coroutines; a [LoopGroup] calls it only once every loop exists, so no datagram is forwarded to a loop not built yet. */
    internal fun start() {
        receiveJob = scope.launch { receiveLoop() }
        scope.launch { timerLoop() }
        scope.launch { followCapabilities(io, PathId.Initial) }
        if (group !=
            null
        ) {
            forwardJob = scope.launch { forwardLoop() }
        }
    }

    /** A loop whose socket or forwarding died ends its endpoint; in a group, the whole group (its accept queue is shared). */
    private fun fatal(
        what: String,
        e: Throwable,
    ) {
        failAll(QuicException.ConnectionLost.Internal("$what: ${e.message}", e))
        if (group !=
            null
        ) {
            group.close()
        } else {
            close()
        }
    }

    /** Receives on a migrating client's extra socket [io] for [core]'s path [path]; cancelled when the path closes. */
    internal fun receiveOn(
        io: DatagramIo,
        core: ConnectionCore,
        path: PathId,
    ): kotlinx.coroutines.Job =
        scope.launch {
            val caps = launch { followCapabilities(io, path, core) }
            val batch = PacketBatch(16, SLOT_SIZE)
            val limiter = WorkLimiter()
            try {
                limiter.start(now())
                while (true) {
                    batch.clear()
                    io.receive(batch)
                    val now = now()
                    for (i in 0 until batch.count) {
                        this@EndpointLoop.core.handleDatagram(
                            batch.buffer(i),
                            batch.length(i),
                            batch.address(i)!!,
                            batch.ecn(i),
                            now,
                            path,
                        )
                    }
                    flush()
                    if (limiter.shouldYield(now)) {
                        yield()
                        limiter.start(now())
                    }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                if (!closing &&
                    isActive
                ) {
                    core.failInternal(e)
                    flush(core)
                }
            } finally {
                caps.cancel()
                batch.close()
            } // a cancelled path closes its socket: not a failure
        }

    /**
     * A socket's capabilities can drop while connections run on it (ECN marking turned off, a route without DF): every
     * connection hears of it on the paths that use [socket] (the endpoint's socket is [PathId.Initial], a migrating client's
     * extra socket its path id). Runs on the loop dispatcher, so never inside a connection's poll.
     */
    private suspend fun followCapabilities(
        io: DatagramIo,
        socket: PathId,
        only: ConnectionCore? = null,
    ) {
        // the current value too: a drop between the path's setup and this subscription must not be missed (a repeat changes nothing)
        io.capabilities.collect { caps ->
            for (rt in runtimes.values) {
                if (only != null && rt.core !== only) continue
                rt.core.updateSocketCapabilities(socket, caps)
                core.markDirty(rt.core)
            }
        }
    }

    /** The socket a slot of [out] goes out on: the endpoint's, or the one of the connection's path. */
    private fun ioFor(
        rt: ConnectionRuntime,
        path: PathId,
    ): DatagramIo =
        if (path ==
            PathId.Initial
        ) {
            io
        } else {
            (rt.paths.firstOrNull { it.id == path } as? PathRuntime)?.io ?: io
        }

    private val single = PacketBatch(1, SLOT_SIZE)
    private val copy = ByteArray(SLOT_SIZE)

    /** Sends [out]: in one call when every slot uses the endpoint socket, otherwise slot by slot through each path's socket. */
    private suspend fun sendOut(
        rt: ConnectionRuntime,
        out: PacketBatch,
    ) {
        var mixed = false
        for (i in 0 until out.count) if (out.path(i) != PathId.Initial) mixed = true
        if (!mixed) {
            sendOrLose(io, out, rt)
            return
        }
        for (i in 0 until out.count) {
            val n = out.length(i)
            out.buffer(i).copyTo(copy, 0, 0, n)
            single.clear()
            single.buffer(0).copyFrom(copy, 0, 0, n)
            single.setLength(0, n)
            single.setAddress(0, out.address(i)!!)
            single.setEcn(0, out.ecn(i))
            sendOrLose(ioFor(rt, out.path(i)), single, rt)
        }
    }

    /**
     * A send that throws (EPERM from a filter, an unreachable route, a socket closed under a closing endpoint) loses this batch,
     * one that takes only part of it (a full send buffer) loses the rest; loss detection repairs both, and [rt]'s connection
     * counts them (a throwing send counts its whole batch, so the count may exceed what was really lost when the socket
     * fails mid-batch). It never propagates: it would end a loop coroutine.
     */
    private suspend fun sendOrLose(
        target: DatagramIo,
        batch: PacketBatch,
        rt: ConnectionRuntime?,
    ) {
        val lost =
            try {
                // a socket that already refused part of a batch in this flush (after its one wait for room) is not waited on
                // again: the flush holds flushLock, so each wait would stall ACKs and timers of every other connection
                val full = fullThisFlush.any { it === target }
                val sent = (if (full) target.trySend(batch) else target.send(batch)).coerceIn(0, batch.count)
                if (sent < batch.count && !full) fullThisFlush.add(target)
                batch.count - sent
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                sendFailures++
                batch.count
            }
        if (lost > 0) {
            socketDrops += lost
            if (rt != null) rt.core.datagramsDroppedSocket += lost
        }
    }

    /** One datagram off this loop's socket: routed by the core, or, in a group, copied to the loop its connection ID names. */
    private fun onDatagram(
        buf: PacketBuffer,
        length: Int,
        from: InetSocketAddress,
        ecn: Ecn,
        now: TimeMark,
    ) {
        val misroute = testMisrouteTo
        if (misroute >= 0 && group != null) {
            group.forward(misroute, buf, length, from, ecn, asReceived = true)
            return
        }
        if (core.handleDatagram(buf, length, from, ecn, now) != null || group == null) return
        val owner = core.ownerLoop(buf, length)
        if (owner >= 0 && owner != index) group.forward(owner, buf, length, from, ecn, asReceived = false)
    }

    /** Receive rounds (this socket's and the forwarded ones) between two yields: timers and commands share the dispatcher with the receivers. */
    private val limiter = WorkLimiter()

    private suspend fun receiveLoop() {
        try {
            limiter.start(now())
            while (true) {
                inBatch.clear()
                io.receive(inBatch)
                val now = now()
                for (i in 0 until inBatch.count) onDatagram(inBatch.buffer(i), inBatch.length(i), inBatch.address(i)!!, inBatch.ecn(i), now)
                afterReceive(now)
                // a socket that never runs dry (a flood) must not starve the timer coroutine and the queued application commands
                if (limiter.shouldYield(now)) {
                    yield()
                    limiter.start(now())
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            if (!closing) fatal("transport failed", e)
        } // a dead socket ends the endpoint: accept() and connect() must not hang
    }

    /** Admission + flush rounds run so far (test hook). */
    @Volatile internal var afterReceiveCount: Long = 0
        private set

    private suspend fun afterReceive(now: TimeMark) {
        afterReceiveCount++
        core.processPending(now) // admission runs once per receive batch
        while (true) {
            val c = core.nextAccepted() ?: break
            val rt = adopt(c)
            rt.serverSide = true
            rt.handshaking = true
            handshaking++
            handshakingForTest = handshaking
        } // new server connections leave the core's queue at once
        flush()
    }

    /** Datagrams other loops of the group handed over (a flow the kernel hashed onto their socket). */
    private suspend fun forwardLoop() {
        val buf = PacketBuffer.allocate(FORWARD_MAX)
        try {
            // in batches like the receive loop: admission and a flush after each, then a yield, so a rebound high-rate flow cannot starve this loop's own socket, timers and commands
            var sinceRound = 0
            limiter.start(now())
            for (f in forwarded) {
                forwardedCount.incrementAndFetch()
                buf.copyFrom(f.bytes, 0, 0, f.bytes.size)
                val now = now()
                if (f.asReceived) {
                    onDatagram(
                        buf,
                        f.bytes.size,
                        f.from,
                        f.ecn,
                        now,
                    )
                } else {
                    core.handleDatagram(buf, f.bytes.size, f.from, f.ecn, now)
                }
                @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
                val drained = forwarded.isEmpty
                if (++sinceRound == FORWARD_BATCH || drained) {
                    sinceRound = 0
                    afterReceive(now)
                    if (limiter.shouldYield(now) || drained) {
                        yield()
                        limiter.start(now())
                    }
                }
            }
        } catch (
            e: CancellationException,
        ) {
            throw e
        } catch (e: Throwable) {
            if (!closing) fatal("forwarding failed", e)
        } finally {
            buf.close()
        }
    }

    private suspend fun timerLoop() {
        try {
            timerTicks()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            if (!closing) fatal("timer failed", e)
        } // like the receive loop: a dead timer ends the endpoint instead of escaping
    }

    private suspend fun timerTicks() {
        while (true) {
            val head = timers.peek()
            val wait = head?.let { it.heapDeadline - now() }
            if (wait == null) {
                wake.receive()
            } else if (wait > Duration.ZERO) {
                withTimeoutOrNull(wait) { wake.receive() }
            }
            val now = now()
            while (true) {
                val c = timers.peek() ?: break
                if (c.heapDeadline > now) break
                timers.remove(c)
                core.markDirty(c)
                try {
                    c.onTimeout(now)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    c.failInternal(e)
                }
            }
            flush(signalTimer = false) // the timer loop re-reads the heap itself; signalling itself here would spin
        }
    }

    /** Flushes that returned with connections still on the dirty list (test hook). */
    @Volatile internal var flushesEndingDirtyForTest: Long = 0
        private set

    /** Sockets that did not take a whole batch during the current flush: the rest of the flush only `trySend`s on them. */
    private val fullThisFlush = ArrayList<DatagramIo>(2)

    /** Drains events, sends what the dirty connections have to send, retires closed ones, re-arms their timers. Loop dispatcher only; [touched] joins the dirty list first. */
    internal suspend fun flush(
        touched: ConnectionCore? = null,
        signalTimer: Boolean = true,
    ) {
        flushLock.withLock {
            if (touched != null) core.markDirty(touched)
            val now = now()
            val dirty = core.dirtyConnections
            if (dirty.isEmpty() && !core.hasStateless) return@withLock
            val head = timers.peek()?.heapDeadline ?: TimeMark.NEVER
            fullThisFlush.clear()
            // connections marked dirty while this flush runs (a refusal in onHandshakeCompleted, a failure marking others) get
            // further rounds here: their CONNECTION_CLOSE must not wait for the next datagram or timer
            var rounds = 0
            while (dirty.isNotEmpty() && rounds++ < FLUSH_ROUNDS) {
                // the list is copied: a flush can retire connections, and a failure inside one marks others dirty
                val list = dirty.toList()
                core.clearDirty()
                for (c in list) {
                    val rt = runtimes[c] ?: continue
                    try {
                        rt.drainEvents()
                        outBatch.clear()
                        if (c.poll(outBatch, now) > 0) sendOut(rt, outBatch)
                        rt.drainEvents()
                        rt.tick()
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Throwable) {
                        c.failInternal(e)
                        rt.drainEvents()
                    }
                    if (c.state ==
                        ConnectionState.Closed
                    ) {
                        handshakeEnded(rt)
                        rt.finish()
                        timers.remove(c)
                        core.remove(c)
                        runtimes.remove(c)
                    } else {
                        timers.update(c, c.nextTimeoutOrNever())
                    }
                }
            }
            if (dirty.isNotEmpty()) wake.trySend(Unit) // still more after the bounded rounds: the timer coroutine flushes again
            outBatch.clear()
            if (core.pollStateless(outBatch) > 0) sendOrLose(io, outBatch, null)
            if (core.dirtyConnections.isNotEmpty()) flushesEndingDirtyForTest++
            val newHead = timers.peek()?.heapDeadline ?: TimeMark.NEVER
            if (signalTimer && newHead < head) wake.trySend(Unit)
        }
    }

    private fun adopt(c: ConnectionCore): ConnectionRuntime {
        val rt = ConnectionRuntime(this, c)
        runtimes[c] = rt
        c.setPathCapabilities(PathId.Initial, io.capabilities.value)
        c.onEcnFailed =
            { path ->
                ioFor(rt, path).disableEcnMarking()
            }
        // the failed path's own socket; a per-datagram io ignores it
        core.markDirty(c)
        return rt
    }

    internal fun onHandshakeCompleted(rt: ConnectionRuntime) {
        if (!rt.serverSide) return
        handshakeEnded(rt)
        // the accept queue never holds more than acceptQueue (shared by a group's loops, hence the compare-and-set)
        while (true) {
            val n = pendingAccept.load()
            if (n >= config.acceptQueue) {
                acceptOverflows++
                rt.core.fail(TransportError.CONNECTION_REFUSED, 0, "accept queue full", null)
                core.markDirty(rt.core)
                return
            }
            if (pendingAccept.compareAndSet(n, n + 1)) break
        }
        acceptQueue.trySend(rt)
        acceptHandOffsForTest++
    }

    /** Connections handed to the accept queue so far (test hook). */
    @Volatile internal var acceptHandOffsForTest: Long = 0
        private set

    /** [rt] no longer counts as a handshake in flight: it completed, or it closed before it could. */
    private fun handshakeEnded(rt: ConnectionRuntime) {
        if (rt.handshaking) {
            rt.handshaking = false
            handshaking--
            handshakingForTest = handshaking
        }
    }

    private fun failAll(reason: QuicException.ConnectionLost) {
        for (rt in runtimes.values) rt.failed(reason)
        runtimes.clear()
        handshaking = 0
    }

    override suspend fun connect(
        remote: InetSocketAddress,
        config: QuicClientConfig,
    ): QuicConnection = connectResolved(resolveOnce(remote), config)

    /**
     * The connect target as an IP literal, resolved once here: the socket reports peers as IP literals, Kotlin/Native's
     * InetSocketAddress compares strings, the loop compares addresses by bytes, and `hostname` would do a reverse DNS lookup (see
     * [ipLiteral]).
     */
    private fun resolveOnce(remote: InetSocketAddress): InetSocketAddress =
        if (remote.resolveAddress() ==
            null
        ) {
            remote
        } else {
            remote.withLiteralHost()
        }

    private suspend fun connectResolved(
        remote: InetSocketAddress,
        config: QuicClientConfig,
    ): QuicConnection {
        var adopted: ConnectionRuntime? = null // set on the loop; a cancellation at the withContext exit must not lose it
        try {
            val rt =
                withContext(dispatcher) {
                    if (closing) throw QuicException.EndpointClosing()
                    checkPayloadSize(config.quic)
                    val c = core.connect(config, remote, now())
                    val rt = adopt(c)
                    adopted = rt
                    flush()
                    rt
                }
            rt.handshake.await() // ConnectionLost on failure; a cancelled caller sees its CancellationException
            return rt
        } catch (e: CancellationException) {
            // a cancelled connect closes what it started: CONNECTION_CLOSE, then the closing period retires it
            adopted?.let { rt ->
                withContext(kotlinx.coroutines.NonCancellable + dispatcher) {
                    if (!closing) {
                        rt.core.close(0, "connect cancelled", now())
                        flush(rt.core)
                    }
                }
            }
            throw e
        }
    }

    override suspend fun accept(): QuicConnection {
        if (closing) throw QuicException.EndpointClosing()
        val c =
            try {
                acceptQueue.receive()
            } catch (
                e: kotlinx.coroutines.channels.ClosedReceiveChannelException,
            ) {
                throw QuicException.EndpointClosing()
            }
        pendingAccept.decrementAndFetch()
        // a connection still queued at close() is closed with the endpoint: never handed out
        if (closing) throw QuicException.EndpointClosing()
        return c
    }

    /** Closes every connection with CONNECTION_CLOSE (one last flush), then frees the native resources and the socket; all of it on the loop. */
    private var closeJob: kotlinx.coroutines.Job? = null

    override suspend fun closeAndJoin() {
        close()
        closeJob?.join()
    }

    override fun close() {
        if (!closingFlag.compareAndSet(0, 1)) return
        if (group == null) acceptQueue.close(QuicException.EndpointClosing()) // a group's queue is shared: only LoopGroup.close() closes it
        forwarded.close()
        closeJob =
            scope.launch {
                try {
                    val now = now()
                    for (c in core.connections().toList()) {
                        c.close(0, "endpoint closed", now)
                        core.markDirty(c)
                    }
                    flush(signalTimer = false)
                } finally {
                    for (rt in runtimes.values.toList()) {
                        rt.failed(
                            QuicException.ConnectionLost.Internal("endpoint closed", QuicException.EndpointClosing()),
                        )
                    }
                    runtimes.clear()
                    // the socket first: it wakes a receiver blocked inside the socket call; its batch is freed only once that call returned (a native receive writes into the batch's memory)
                    io.close()
                    receiveJob?.cancel()
                    forwardJob?.cancel()
                    withContext(kotlinx.coroutines.NonCancellable) {
                        receiveJob?.join()
                        forwardJob?.join()
                    }
                    core.close()
                    inBatch.close()
                    outBatch.close()
                    single.close()
                    scope.cancel()
                }
            }
    }

    companion object {
        /** Forwarded datagrams a loop may hold unprocessed; more are dropped (a burst after a rebind, never steady state). */
        const val FORWARD_QUEUE: Int = 1024

        /** Bytes per datagram slot of the runtime's batches: the largest UDP payload it sends or receives. */
        const val SLOT_SIZE: Int = 1500
        const val FORWARD_MAX: Int = SLOT_SIZE

        /** The runtime's slots bound what may be advertised as `max_udp_payload_size` (and so what PMTUD probes): refused above, never silently truncated. */
        internal fun checkPayloadSize(quic: io.kuicksilver.quic.QuicConfig) =
            require(quic.maxUdpPayloadSize <= SLOT_SIZE) {
                "maxUdpPayloadSize ${quic.maxUdpPayloadSize} exceeds the endpoint runtime's $SLOT_SIZE-byte datagram slots"
            }

        /** Rounds one flush runs over connections that became dirty during it; more go to the next flush. */
        const val FLUSH_ROUNDS: Int = 4

        /** Forwarded datagrams handled before admission, flush and a yield. */
        const val FORWARD_BATCH: Int = 16

        @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
        internal fun ownDispatcher(): CoroutineDispatcher = Dispatchers.Default.limitedParallelism(1)

        suspend fun bind(
            local: InetSocketAddress,
            config: QuicEndpointConfig,
        ): QuicEndpoint {
            config.server?.let { checkPayloadSize(it.quic) }
            val io = config.io?.invoke(local) ?: DatagramIo.open(local)
            // a Native server needs the accelerated transport (the portable Native io is client-only, ADR-0006); a caller-supplied io is trusted
            if (config.server != null && config.io == null && !portableServerSupported &&
                io !is io.kuicksilver.quic.KslDatagramIo
            ) {
                io.close()
                throw UnsupportedOperationException("Native server requires the accelerated DatagramIo (Linux, Apple)")
            }
            return EndpointLoop(config, io, config.dispatcher ?: ownDispatcher()).also { it.start() }
        }

        /** One loop of a [LoopGroup]: its own dispatcher, the group's accept queue. */
        internal fun inGroup(
            config: QuicEndpointConfig,
            io: DatagramIo,
            index: Int,
            group: LoopGroup,
            acceptQueue: Channel<QuicConnection>,
            pendingAccept: AtomicInt,
        ): EndpointLoop = EndpointLoop(config, io, ownDispatcher(), index, group, pendingAccept, acceptQueue)

        /**
         * The accept queue, whose slots [pending] counts. A connection the queue cannot deliver (an `accept()` cancelled
         * after the queue had handed it the connection, or the queue closed) releases its slot and is closed: otherwise
         * each such race would keep a slot forever and, once acceptQueue of them leaked, every handshake would be refused.
         */
        internal fun acceptChannel(pending: AtomicInt): Channel<QuicConnection> =
            Channel(Channel.UNLIMITED) { c ->
                pending.decrementAndFetch()
                c.close() // CONNECTION_CLOSE with application code 0, on the connection's loop
            }
    }
}
