// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.EndpointCore
import io.kuicksilver.quic.EndpointStats
import io.kuicksilver.quic.IoPreference
import io.kuicksilver.quic.KslDatagramIo
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.PREFERRED_SOCKET
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.Releaser
import io.kuicksilver.quic.SocketDefunctException
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.core.AddressClass
import io.kuicksilver.quic.core.fail
import io.kuicksilver.quic.core.failInternal
import io.kuicksilver.quic.core.zeroRttWritable
import io.kuicksilver.quic.emit
import io.kuicksilver.quic.ipLiteral
import io.kuicksilver.quic.openDatagramIo
import io.kuicksilver.quic.tokenStoreKey
import io.kuicksilver.quic.withLiteralHost
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.SessionCache
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
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
 * blocks inside it but a receive on its own thread while datagrams keep coming, at most 1 ms and never past the next timer
 * ([BatchReceiver]). Datagrams arrive from a receiver coroutine, timers from a timer coroutine, both on the dispatcher.
 *
 * A flush visits only the connections something happened to since the last one (the core's dirty list) and the timer
 * coroutine keeps a heap of deadlines, so neither costs O(connections) per datagram. Several loops of one
 * [LoopGroup] share a port: a datagram whose connection ID names another loop ([EndpointCore.ownerLoop]) is copied to
 * that loop's [forwarded] channel; only the owner ever answers a Stateless Reset for it.
 */
@OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class, InternalKuicksilverApi::class)
internal class EndpointLoop private constructor(
    private val config: QuicEndpointConfig,
    internal val io: DatagramIo,
    internal val dispatcher: CoroutineDispatcher,
    internal val index: Int = 0,
    internal val group: LoopGroup? = null,
    private val pendingAccept: AtomicInt = AtomicInt(0),
    private val acceptQueue: Channel<QuicConnection> = acceptChannel(pendingAccept),
    /** The client's session tickets (per endpoint, single use; ADR-0015): a group's loops share one, `connect` picks any loop. */
    internal val sessions: SessionCache = SessionCache(),
    /** A group's Retry and NEW_TOKEN keys, shared by its loops (RFC 9000 section 8.1); null: the endpoint core makes its own. */
    tokens: io.kuicksilver.quic.endpoint.AddressTokens? = null,
    /** A group's QUIC-LB state, shared by its loops; null: the endpoint core makes its own when the config has a `loadBalancer`. */
    lb: io.kuicksilver.quic.endpoint.QuicLbState? = null,
    /** The sockets on the server's preferred addresses, one per family offered ([PREFERRED_SOCKET]). */
    preferredIos: List<DatagramIo> = emptyList(),
    /** Allocates the batches' buffers (a test seam: a failing allocator). */
    allocate: (Int) -> PacketBuffer = PacketBuffer::allocate,
) : QuicEndpoint {
    /** Last-resort failures of coroutines the loop launched (none is expected to throw): counted, never handed to the thread's uncaught handler, which on Android kills the process. */
    internal val uncaughtFailures = AtomicLong(0)
    internal val scope =
        CoroutineScope(
            SupervisorJob() + dispatcher + kotlinx.coroutines.CoroutineExceptionHandler { _, _ -> uncaughtFailures.incrementAndFetch() },
        )

    /** The preferred-address sockets; emptied when the preferred address goes down ([dropPreferred]). Loop dispatcher only. */
    internal var preferredIos: List<DatagramIo> = preferredIos

    /** Lifecycle counters, the connection listener and the logger of this loop (docs/guide/quic.md, "Observability"). */
    internal val observer = LoopObserver(config.logger, config.listener)

    // one unsynchronised CSPRNG stream per loop: every call into the core stays on this loop's thread
    internal val core: EndpointCore
    internal val inBatch: PacketBatch
    internal val outBatch: PacketBatch

    /** One datagram of a slot sent on its own (another socket than the batch's). */
    internal val single: PacketBatch

    init {
        // the core and the batches are native memory that only the close job frees: a constructor that fails part-way frees
        // what it made (the sockets stay the caller's, bind closes them)
        var c: EndpointCore? = null
        var i: PacketBatch? = null
        var o: PacketBatch? = null
        try {
            c = EndpointCore(config, KslRandom.newSource(), index, tokens, lb, group?.slots)
            core = c
            i = PacketBatch(16, SLOT_SIZE, allocate)
            inBatch = i
            o = PacketBatch(32, SLOT_SIZE, allocate)
            outBatch = o
            single = PacketBatch(1, SLOT_SIZE, allocate)
        } catch (e: Throwable) {
            val r = Releaser(e) // what a release throws is suppressed into e
            r.release { o?.close() }
            r.release { i?.close() }
            r.release { c?.close() } // and its reference to a group's address tokens
            scope.cancel()
            throw e
        }
    }

    /** [dispatcher] for a stream reader's hop onto the loop ([LoopDispatcher.Batched]). */
    internal val readHop: kotlin.coroutines.CoroutineContext = dispatcher + LoopDispatcher.Batched

    internal val wake = Channel<Unit>(Channel.CONFLATED)
    internal val flushLock = Mutex() // a suspending DatagramIo.send must not interleave with another flush over the same batch
    internal val runtimes = HashMap<ConnectionCore, ConnectionRuntime>()
    internal val timers = TimerHeap()

    /**
     * Staging bytes between the cores and the application's channels: a stream's input reads the core's data through it into
     * its buffer, a stream's output copies its buffer through it into the core, the datagram flow reads a datagram into it.
     * Each use fills and empties it within one task on [dispatcher], which runs one task at a time and never suspends in
     * between, so one array serves every stream and connection of this loop (it was 16 KiB per stream half and 64 KiB per
     * datagram collector). Not checked at run time: the runtime has no thread assertions to follow, and the loop's
     * confinement is already what every core access relies on.
     */
    internal val scratch = ByteArray(SCRATCH)
    private val start = TimeSource.Monotonic.markNow()
    private val closingFlag = AtomicInt(0) // set once, by compare-and-set: two concurrent close() calls must not both tear down
    internal val closing: Boolean get() = closingFlag.load() != 0
    override val localAddress: InetSocketAddress get() = io.localAddress

    /** A datagram another loop of the group hands over: [asReceived] ones are treated as if they arrived on this socket (test hook), the rest belong to a connection here. */
    internal class Forwarded(
        val bytes: ByteArray,
        val from: InetSocketAddress,
        val ecn: Ecn,
        val asReceived: Boolean,
        /** The socket kind it arrived on: the main one, or a preferred-address socket ([PREFERRED_SOCKET]). */
        val socket: PathId = PathId.Initial,
        /** Our address it was sent to, when the receiving socket reports it ([PacketBatch.localAddress]). */
        val local: InetSocketAddress? = null,
    )

    internal val forwarded = Channel<Forwarded>(FORWARD_QUEUE)
    internal val forwardedCount = AtomicLong(0)

    /** Test hook: every datagram received on this socket is handed to loop [testMisrouteTo] as if the kernel had hashed it there. */
    @Volatile internal var testMisrouteTo: Int = -1

    internal fun now(): TimeMark = TimeMark(1_000_000_000L + start.elapsedNow().inWholeNanoseconds)

    /** [now] for the receivers, read without boxing. */
    internal val clock = BatchReceiver.LoopClock { now() }

    private var receiveJob: kotlinx.coroutines.Job? = null
    private var forwardJob: kotlinx.coroutines.Job? = null

    // the coroutines that write into the core and the batches: the close job stops and joins them before it frees those
    private var timerJob: kotlinx.coroutines.Job? = null
    private val preferredJobs = ArrayList<kotlinx.coroutines.Job>(2)

    /** The coroutines that write into the core and the batches have all ended (test hook). */
    internal val writersEndedForTest: Boolean
        get() = (listOfNotNull(receiveJob, forwardJob, timerJob) + preferredJobs).all { it.isCompleted }

    /** Test hook: runs in the close job after the writers were joined and before the flush lock is taken to release. */
    internal var beforeReleaseForTest: (suspend () -> Unit)? = null

    /** Test hook: runs [block] holding the flush lock, as a flush does. */
    internal suspend fun <T> withFlushLockForTest(block: suspend () -> T): T = flushLock.withLock { block() }

    /** Set by the close job once the core and the batches are freed: a flush after that does nothing. Loop dispatcher only. */
    internal var released = false

    /** Batches whose send threw (a transient socket error): the datagrams are treated as lost, nothing else happens. */
    internal var sendFailures = 0L

    internal val pendingAcceptForTest: Int get() = pendingAccept.load()

    /** Datagrams the sockets did not take (failed or partial sends), stateless replies included. */
    internal var socketDrops = 0L

    /** Server connections this loop adopted whose handshake has not completed yet (bookkeeping and tests; admission does not count them). */
    internal var handshaking = 0

    @Volatile internal var handshakingForTest: Int = 0
        internal set

    /** Handshakes that completed while the accept queue was full: refused with CONNECTION_REFUSED. */
    internal var acceptOverflows = 0L

    init {
        // admission counts only the connections waiting for accept(): counting unvalidated handshakes too would let
        // acceptQueue spoofed-source Initials per handshakeTimeout lock every client out before the admission policy (and
        // its Retry) could step in; the bound is enforced where a handshake completes (onHandshakeCompleted)
        core.acceptBacklog = { pendingAccept.load() }
    }

    /** Frees what the constructor made, for a loop that was never started; its sockets stay the caller's. */
    internal fun discardUnstarted() {
        val r = Releaser()
        r.release { single.close() }
        r.release { outBatch.close() }
        r.release { inBatch.close() }
        r.release { core.close() } // and its reference to a group's address tokens
        scope.cancel()
        r.finish()
    }

    /** Starts the receive, timer and forward coroutines; a [LoopGroup] calls it only once every loop exists, so no datagram is forwarded to a loop not built yet. */
    internal fun start() {
        QuicResourceProbe.register(this)
        if (preloadsCloseClasses && closeClassesLoaded.compareAndSet(0, 1)) {
            // ATOMIC: it runs even if this endpoint closes at once, so the flag never stands for a preload that did not happen
            @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
            scope.launch(Dispatchers.Default, start = kotlinx.coroutines.CoroutineStart.ATOMIC) {
                try {
                    loadCloseClasses()
                } catch (e: Throwable) {
                    closeClassesLoaded.store(0) // the next endpoint tries again
                    throw e
                }
            }
        }
        receiveJob = scope.launch { receiveLoop() }
        timerJob = scope.launch(LoopDispatcher.Batched) { timerLoop() } // the receiver yields when a timer is due
        scope.launch { followCapabilities(io, PathId.Initial) }
        for (p in preferredIos) {
            preferredJobs += scope.launch { receivePreferred(p) }
            scope.launch { followCapabilities(p, PREFERRED_SOCKET) }
        }
        if (group !=
            null
        ) {
            forwardJob = scope.launch { forwardLoop() }
        }
    }

    /** A loop whose socket or forwarding died ends its endpoint; in a group, the whole group (its accept queue is shared). */
    internal fun fatal(
        what: String,
        e: Throwable,
    ) {
        observer.logger.emit(LogLevel.Error, e) { "endpoint ${io.localAddress} loop $index: $what; closing the endpoint" }
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
            val receiver = BatchReceiver(io, clock, directWait, dispatcher as? LoopDispatcher)
            try {
                limiter.start(now())
                while (true) {
                    batch.clear()
                    receiver.receive(batch, untilTimer)
                    observer.datagramsReceived += batch.count
                    val now = now()
                    for (i in 0 until batch.count) {
                        this@EndpointLoop.core.handleDatagram(
                            batch.buffer(i),
                            batch.length(i),
                            batch.address(i)!!,
                            batch.ecn(i),
                            now,
                            path,
                            batch.localAddress(i),
                        )
                    }
                    drainPacketTooBig(io, path, now)
                    flush()
                    if (limiter.shouldYield(now)) {
                        receiver.yieldToQueued()
                        limiter.start(now())
                    }
                }
            } catch (e: SocketDefunctException) {
                // the system took the socket (iOS background) or its interface: the path is lost, the connection is not
                if (!closing) socketLost(io, e)
            } catch (e: Throwable) {
                // a CancellationException while this coroutine is active came out of a socket or callback: a failure like any other
                if (e is CancellationException) currentCoroutineContext().ensureActive()
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

    internal val copy = ByteArray(SLOT_SIZE)

    /**
     * Set (for good) once a connection of this loop got a path socket whose `send` may suspend (an application's own
     * [DatagramIo]): flushes take the suspending path from then on. Set before the path can carry a datagram.
     */
    @Volatile internal var suspendingPathSockets = false

    /** The endpoint's own socket (tests). */
    internal val ioForTest: DatagramIo get() = io

    /** A path socket [io] was made for one of this loop's connections (see [suspendingPathSockets]). */
    internal fun pathSocketAdded(io: DatagramIo) {
        if (io !is io.kuicksilver.quic.NonSuspendingSend) suspendingPathSockets = true
    }

    /**
     * Receive rounds of this socket between two yields: timers and commands share the dispatcher with the receivers. The
     * receiver itself already lets queued work run after every 16 datagrams or 1 ms ([BatchReceiver]); this bounds a socket
     * whose rounds never wait at all (a flood).
     */
    internal val limiter = WorkLimiter()

    /**
     * How long a receive may wait on the loop's thread for the next datagrams: never on a dispatcher the caller supplied, which
     * other work shares (two endpoints on one dispatcher would each stall the other's sends for 1 ms per quiet gap);
     * what is already queued is still taken there.
     */
    internal val directWait: Duration = if (config.dispatcher != null) Duration.ZERO else BatchReceiver.PLATFORM_WAIT

    /** This socket's batches: on the loop's thread while datagrams keep coming, else through the blocking receive. */
    internal val receiver = BatchReceiver(io, clock, directWait, dispatcher as? LoopDispatcher)

    /** Time left until the loop's next timer: a receive on the loop's thread waits no longer. */
    internal val untilTimer = BatchReceiver.TimerHorizon { timers.peek()?.let { it.heapDeadline - now() } ?: Duration.INFINITE }

    /** True for an endpoint without a server role: its socket serves only its own connections, which can move off it. */
    internal val clientOnly: Boolean get() = config.server == null

    /** Sockets the system took away (identity; loop dispatcher only): never read or written again. */
    internal val defunct = ArrayList<DatagramIo>(2)

    /** Set once the endpoint's own socket is lost: connect() fails with it at once. */
    @Volatile private var endpointSocketLost: SocketDefunctException? = null

    /**
     * [socket] is gone ([SocketDefunctException]): it is not used again, and every connection reports `PathEvent.SocketLost` for
     * its paths on it, once. Loop dispatcher only.
     */
    internal fun socketLost(
        socket: DatagramIo,
        cause: SocketDefunctException,
    ) {
        if (isDefunct(socket)) return
        defunct += socket
        if (socket === io) endpointSocketLost = cause
        for (rt in runtimes.values.toList()) rt.onSocketLost(if (socket === io) null else socket, cause)
    }

    /** Lost sockets still remembered (tests). */
    internal suspend fun defunctCountForTest(): Int = withContext(dispatcher) { defunct.size }

    /** A lost path socket was closed (its path is gone): it no longer needs remembering. Loop dispatcher only. */
    internal fun forgetDefunct(socket: DatagramIo) {
        if (socket !== io) defunct.removeAll { it === socket }
    }

    /** Admission + flush rounds run so far (test hook). */
    @Volatile internal var afterReceiveCount: Long = 0
        internal set

    /** Flushes that returned with connections still on the dirty list (test hook). */
    @Volatile internal var flushesEndingDirtyForTest: Long = 0
        internal set

    /** Sockets that did not take a whole batch during the current flush: the rest of the flush only `trySend`s on them. */
    internal val fullThisFlush = ArrayList<DatagramIo>(2)

    /** The connections one flush round works through, copied off the dirty list (a flush can retire connections, and a failure marks others). */
    internal val flushRound = ArrayList<ConnectionCore>()

    internal fun adopt(c: ConnectionCore): ConnectionRuntime {
        val rt = ConnectionRuntime(this, c)
        runtimes[c] = rt
        observer.opened(rt)
        c.setPathCapabilities(PathId.Initial, io.capabilities.value)
        c.onEcnFailed =
            { path ->
                ioFor(rt, path)?.disableEcnMarking()
            }
        // the failed path's own socket; a per-datagram io ignores it
        core.markDirty(c)
        return rt
    }

    internal val tokenStoreSlowLogged = AtomicInt(0)

    internal fun onHandshakeCompleted(rt: ConnectionRuntime) {
        if (!rt.serverSide || rt.handedOff) return
        rt.handedOff = true
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
        observer.accepted++
        acceptHandOffsForTest++
    }

    /** Connections handed to the accept queue so far (test hook). */
    @Volatile internal var acceptHandOffsForTest: Long = 0
        private set

    /** [rt] no longer counts as a handshake in flight: it completed, or it closed before it could. */
    internal fun handshakeEnded(rt: ConnectionRuntime) {
        if (rt.handshaking) {
            rt.handshaking = false
            handshaking--
            handshakingForTest = handshaking
        }
    }

    private fun failAll(reason: QuicException.ConnectionLost) {
        for (rt in runtimes.values) rt.retire(reason)
        runtimes.clear()
        handshaking = 0
    }

    override suspend fun connect(
        remote: InetSocketAddress,
        config: QuicClientConfig,
    ): QuicConnection = connectResolved(resolveOnce(remote), config, early = false)

    override suspend fun connectEarly(
        remote: InetSocketAddress,
        config: QuicClientConfig,
    ): QuicConnection = connectResolved(resolveOnce(remote), config, early = true)

    /**
     * The connect target as an IP literal, resolved once here: the socket reports peers as IP literals, Kotlin/Native's
     * InetSocketAddress compares strings, the loop compares addresses by bytes, and `hostname` would do a reverse DNS lookup (see
     * [ipLiteral]).
     */
    private fun resolveOnce(remote: InetSocketAddress): InetSocketAddress = remote.withLiteralHost()

    private suspend fun connectResolved(
        remote: InetSocketAddress,
        config: QuicClientConfig,
        early: Boolean,
    ): QuicConnection {
        var adopted: ConnectionRuntime? = null // set on the loop; a cancellation at the withContext exit must not lose it
        try {
            // an address-validation token from an earlier connection to this server (RFC 9000 section 8.1.3; single use)
            val tokenKey = config.tokenStore?.let { tokenStoreKey(config.tls.serverName, remote) }
            val token = config.tokenStore?.let { takeToken(it, tokenKey!!) }
            // a resumable ticket of this TLS configuration whose chain still passes the current trust (single use)
            val ticket = if (config.earlyData == EarlyDataState.Disabled) null else sessions.takeQuic(config.tls)
            if (early && ticket == null && config.earlyData == EarlyDataState.Required) {
                throw QuicException.ConnectionLost.ZeroRttRejected()
            }
            var zeroRtt = false
            val rt =
                try {
                    withContext(dispatcher) {
                        if (closing || shuttingDown) throw QuicException.EndpointClosing()
                        endpointSocketLost?.let {
                            throw SocketDefunctException(
                                "the endpoint's socket is gone: bind a new endpoint",
                                it.errno,
                                it,
                            )
                        }
                        checkPayloadSize(config.quic)
                        val c = core.connect(config, remote, now(), ticket)
                        c.initialToken = token
                        val rt = adopt(c)
                        rt.tokenStore = config.tokenStore
                        rt.tokenKey = tokenKey
                        adopted = rt
                        flush()
                        zeroRtt = c.zeroRttWritable // the first poll drove TLS: the 0-RTT key exists when the ticket allowed it
                        if (zeroRtt) observer.zeroRttOffered++
                        rt
                    }
                } catch (t: Throwable) {
                    if (adopted == null) ticket?.close()
                    throw t
                }
            if (early && zeroRtt) return rt
            rt.handshake.await() // ConnectionLost on failure; a cancelled caller sees its CancellationException
            if (early && config.earlyData == EarlyDataState.Required && rt.earlyDataAccepted != true) {
                rt.close()
                throw QuicException.ConnectionLost.ZeroRttRejected()
            }
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

    override suspend fun updateLoadBalancer(config: io.kuicksilver.quic.QuicLbConfig?) {
        if (group != null) return group.updateLoadBalancer(config)
        val lb = core.lb ?: throw IllegalStateException("updateLoadBalancer needs an endpoint built with a loadBalancer")
        lbLock.withLock { applyLoadBalancer(lb, config, this) }
    }

    /** One configuration change at a time: a second one prepared meanwhile could reuse an entry the first retires. */
    private val lbLock = Mutex()

    /** Test hook: runs on the loop right after a configuration was committed (a caller cancelled there must not undo it). */
    internal var afterLbCommitForTest: (() -> Unit)? = null

    /** [block] on the loop's dispatcher while the endpoint is open (the core is alive there); [QuicException.EndpointClosing] once it closes. */
    internal suspend fun <T> runOnLoop(block: () -> T): T {
        if (closing) throw QuicException.EndpointClosing()
        try {
            return withContext(dispatcher) {
                if (closing) throw QuicException.EndpointClosing()
                block()
            }
        } catch (e: CancellationException) {
            if (closing) throw QuicException.EndpointClosing() // the loop's scope went away under a concurrent close
            throw e
        }
    }

    // ---- observability and graceful shutdown ----

    override val stats: EndpointStats get() =
        core.stats + observer.snapshot(acceptOverflows, uncaughtFailures.load(), sendFailures, socketDrops)

    /** Set once on the loop by [beginShutdown]: `connect` refuses, the core refuses new clients. */
    @Volatile internal var shuttingDown = false

    /** Completes once no connection is left after [beginShutdown], or when the endpoint closes. */
    internal val drained = kotlinx.coroutines.CompletableDeferred<Unit>()

    override suspend fun shutdown(
        grace: Duration,
        code: Long,
        reason: String,
    ) {
        beginShutdown()
        withTimeoutOrNull(grace) { drained.await() }
        closeWith(code, reason)
        closeJob?.join()
    }

    /** Stops taking new connections (a second call ends the grace period at once); a [LoopGroup] calls it on every loop. */
    internal suspend fun beginShutdown() {
        if (closing) return
        try {
            withContext(dispatcher) {
                if (shuttingDown) {
                    drained.complete(Unit)
                    return@withContext
                }
                observer.logger.emit(
                    LogLevel.Info,
                ) { "endpoint ${io.localAddress} loop $index shutting down with ${runtimes.size} connections" }
                shuttingDown = true
                core.shuttingDown = true
                if (runtimes.isEmpty()) drained.complete(Unit)
            }
        } catch (e: CancellationException) {
            if (closing) return // the loop's scope went away under a concurrent close
            throw e
        }
    }

    /** Waits until [beginShutdown] has no connection left to wait for. */
    internal suspend fun awaitDrained() = drained.await()

    override fun close() = closeWith(0, "endpoint closed")

    /** [close] with the application [code] and [reason] of the CONNECTION_CLOSE every live connection gets. */
    internal fun closeWith(
        code: Long,
        reason: String,
    ) {
        if (!closingFlag.compareAndSet(0, 1)) return
        drained.complete(Unit) // a shutdown waiting for its grace period ends now
        observer.logger.emit(LogLevel.Info) { "endpoint ${io.localAddress} loop $index closing" }
        if (group == null) acceptQueue.close(QuicException.EndpointClosing()) // a group's queue is shared: only LoopGroup.close() closes it
        forwarded.close()
        closeJob =
            scope.launch {
                // created first: a failure of the body below is the one rethrown, the releases' failures are suppressed into it
                val r = Releaser()
                try {
                    sessions.close() // a group's loops close together (LoopGroup.closeWith), so the shared cache can close too
                    val now = now()
                    for (c in core.connections().toList()) {
                        c.close(code, reason, now)
                        core.markDirty(c)
                    }
                    flush(signalTimer = false)
                } catch (e: Throwable) {
                    r.note(e)
                } finally {
                    // every step runs even when one before it threw (a socket whose close fails must not leak the core and the
                    // batches); the first failure is rethrown at the end, later ones suppressed
                    for (rt in runtimes.values.toList()) {
                        r.release {
                            rt.retire(
                                QuicException.ConnectionLost.Internal("endpoint closed", QuicException.EndpointClosing()),
                            )
                        }
                    }
                    runtimes.clear()
                    // the socket first: it wakes a receiver blocked inside the socket call; its batch is freed only once that call returned (a native receive writes into the batch's memory)
                    r.release { io.close() }
                    for (p in preferredIos) r.release { p.close() }
                    // every coroutine that writes into the core or the batches stops before they are freed: the receivers, the
                    // forwarder, the timer (its flush polls into the out batch) and the preferred-address receivers
                    val writers = listOfNotNull(receiveJob, forwardJob, timerJob) + preferredJobs
                    for (j in writers) j.cancel()
                    r.release { withContext(kotlinx.coroutines.NonCancellable) { for (j in writers) j.join() } }
                    beforeReleaseForTest?.invoke()
                    // a flush started elsewhere (an application call, the one after a verification) may be suspended in a send
                    // over the out batch: taking the flush lock waits for it, and every later flush sees `released`; the lock is
                    // also the happens-before edge for a dispatcher with more than one thread
                    r.release { withContext(kotlinx.coroutines.NonCancellable) { flushLock.withLock { released = true } } }
                    r.release { core.close() }
                    // the timer coroutine is gone: the heap would otherwise keep every released connection reachable through
                    // this endpoint for as long as the application holds it
                    timers.clear()
                    r.release { inBatch.close() }
                    r.release { outBatch.close() }
                    r.release { single.close() }
                    r.release { QuicResourceProbe.unregister(this@EndpointLoop) }
                    scope.cancel()
                    r.finish()
                }
            }
    }

    companion object {
        /** Forwarded datagrams a loop may hold unprocessed; more are dropped (a burst after a rebind, never steady state). */
        const val FORWARD_QUEUE: Int = 1024

        /** Bytes per datagram slot of the runtime's batches: the largest UDP payload it sends or receives. */
        const val SLOT_SIZE: Int = 1500
        const val FORWARD_MAX: Int = SLOT_SIZE

        /** How long `connect` waits for `QuicTokenStore.take` (and a stored token for `put`) before going on without it. */
        val TOKEN_STORE_TIMEOUT: Duration = Duration.parse("250ms")

        /** The runtime's slots bound what may be advertised as `max_udp_payload_size` (and so what PMTUD probes): refused above, never silently truncated. */
        internal fun checkPayloadSize(quic: io.kuicksilver.quic.QuicConfig) =
            require(quic.maxUdpPayloadSize <= SLOT_SIZE) {
                "maxUdpPayloadSize ${quic.maxUdpPayloadSize} exceeds the endpoint runtime's $SLOT_SIZE-byte datagram slots"
            }

        /** Rounds one flush runs over connections that became dirty during it; more go to the next flush. */
        const val FLUSH_ROUNDS: Int = 4

        /**
         * A preferred address must not be the endpoint's own: the same port on the same IP, or on any IP of its family when the socket
         * is bound to the unspecified address (an IPv6 one, `::`, also takes IPv4 on a dual-stack socket; `0.0.0.0` takes no IPv6
         * address). With SO_REUSEPORT the kernel would hash part of the new clients' Initials onto the preferred sockets, where a
         * connection never starts.
         */
        internal fun checkNotOwnAddress(
            pa: io.kuicksilver.quic.PreferredAddress,
            main: InetSocketAddress,
        ) {
            val m = AddressClass.ipBytes(main)
            val unspecified = m.all { it == 0.toByte() }
            for (a in listOfNotNull(pa.ipv4, pa.ipv6)) {
                if (a.port != main.port) continue
                val ip = AddressClass.ipBytes(a)
                if ((unspecified && (m.size == 16 || ip.size == 4)) || m.contentEquals(ip)) {
                    throw IllegalArgumentException("preferred address $a is the endpoint's own address ($main)")
                }
            }
        }

        private val closeClassesLoaded = AtomicInt(0)

        /**
         * Makes the exceptions a close carries once, so their classes are loaded and their message templates linked before the
         * first close() needs them: on a cold JVM the first `ConnectionLost` took 3 to 5 ms to make (measured inside
         * `ConnectionCore.close`, where it sat between close() and the CONNECTION_CLOSE on the wire); the next takes about 20 us.
         * Once per process, off the loop, and only on the JVM and Android ([preloadsCloseClasses]): Kotlin/Native has no class
         * loading to save.
         */
        internal fun loadCloseClasses() {
            // a reason, so the message's inner template is linked too (on the JVM each string template links on its first run)
            QuicException.ConnectionLost.ApplicationClosed(0, "-", io.kuicksilver.quic.Initiator.Local)
            QuicException.ConnectionLost.TransportClosed(0, 0, "-", ByteArray(0), io.kuicksilver.quic.Initiator.Local, null)
        }

        /** What a stream's input or output moves through [scratch] at a time. */
        const val STREAM_CHUNK: Int = 16_384

        /**
         * [scratch]: a stream's 16 KiB chunk. A received DATAGRAM payload fits too: it arrived in one of this runtime's
         * [SLOT_SIZE]-byte receive slots (`maxUdpPayloadSize` is capped at it), so it is shorter than that.
         */
        const val SCRATCH: Int = STREAM_CHUNK

        init {
            check(SLOT_SIZE <= SCRATCH) { "a received datagram must fit the loop's scratch" }
        }

        /** Forwarded datagrams handled before admission, flush and a yield. */
        const val FORWARD_BATCH: Int = 16

        @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
        internal fun ownDispatcher(): CoroutineDispatcher = LoopDispatcher(Dispatchers.Default.limitedParallelism(1))

        suspend fun bind(
            local: InetSocketAddress,
            config: QuicEndpointConfig,
            allocate: (Int) -> PacketBuffer = PacketBuffer::allocate,
            beforeStartForTest: () -> Unit = {},
        ): QuicEndpoint {
            config.server?.let { checkPayloadSize(it.quic) }
            val io =
                config.io?.invoke(local)
                    ?: io.kuicksilver.quic.openDatagramIo(local, io.kuicksilver.quic.IoPreference.Accelerated, config.logger)
            // a Native server needs the accelerated transport (the portable Native io is client-only, ADR-0006); a caller-supplied io is trusted
            if (config.server != null && config.io == null && !portableServerSupported &&
                io !is io.kuicksilver.quic.KslDatagramIo
            ) {
                io.close()
                throw UnsupportedOperationException(
                    "a QUIC server on Kotlin/Native needs the accelerated ksl socket (Linux, Apple, Windows), which is unavailable here",
                )
            }
            val preferred =
                try {
                    openPreferred(config, io.localAddress) { at ->
                        config.io?.invoke(at)
                            ?: openDatagramIo(at, IoPreference.Accelerated, config.logger)
                    }
                } catch (e: Throwable) {
                    io.close()
                    throw e
                }
            val loop =
                try {
                    EndpointLoop(config, io, config.dispatcher ?: ownDispatcher(), preferredIos = preferred, allocate = allocate)
                } catch (e: Throwable) {
                    val r = Releaser(e) // the loop freed its own part; the sockets are bind's
                    r.release { io.close() }
                    for (p in preferred) r.release { p.close() }
                    throw e
                }
            try {
                beforeStartForTest()
                loop.start()
            } catch (e: Throwable) {
                // whatever start launched goes with the loop: the close job frees the sockets, the core and the batches
                Releaser(e).release { withContext(kotlinx.coroutines.NonCancellable) { loop.closeAndJoin() } }
                throw e
            }
            return loop
        }

        /** The server's preferred-address sockets ([io.kuicksilver.quic.QuicServerConfig.preferredAddress]), opened with [open]; all or none. */
        internal suspend fun openPreferred(
            config: QuicEndpointConfig,
            main: InetSocketAddress,
            open: suspend (InetSocketAddress) -> DatagramIo,
        ): List<DatagramIo> {
            val pa = config.server?.preferredAddress ?: return emptyList()
            checkNotOwnAddress(pa, main)
            val out = ArrayList<DatagramIo>(2)
            try {
                for (a in listOfNotNull(pa.ipv4, pa.ipv6)) out += open(a)
            } catch (e: Throwable) {
                for (p in out) p.close()
                throw e
            }
            return out
        }

        /** One loop of a [LoopGroup]: its own dispatcher, the group's accept queue. */
        internal fun inGroup(
            config: QuicEndpointConfig,
            io: DatagramIo,
            index: Int,
            group: LoopGroup,
            acceptQueue: Channel<QuicConnection>,
            pendingAccept: AtomicInt,
            sessions: SessionCache,
            tokens: io.kuicksilver.quic.endpoint.AddressTokens,
            preferredIos: List<DatagramIo> = emptyList(),
            allocate: (Int) -> PacketBuffer = PacketBuffer::allocate,
            lb: io.kuicksilver.quic.endpoint.QuicLbState? = null,
        ): EndpointLoop =
            EndpointLoop(
                config,
                io,
                ownDispatcher(),
                index,
                group,
                pendingAccept,
                acceptQueue,
                sessions,
                tokens,
                lb,
                preferredIos,
                allocate,
            )

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

/**
 * Prepares [config] on `Dispatchers.IO` (the configuration's key copy, derived key and nonce space; a nonce reservation's
 * first `store` may fsync), commits it on [loop]'s dispatcher, and prepares again when another change retired the entry it
 * reused (`QuicLbState.StaleConfiguration`). A prepared configuration is discarded only when it was not committed: a caller
 * cancelled after the commit leaves it in force.
 */
internal suspend fun applyLoadBalancer(
    lb: io.kuicksilver.quic.endpoint.QuicLbState,
    config: io.kuicksilver.quic.QuicLbConfig?,
    loop: EndpointLoop,
    afterCommit: suspend () -> Unit = {},
) {
    var tries = 0
    while (true) {
        // not cancellable: a fresh entry made there is either committed or discarded below, never dropped on the floor
        val prepared = withContext(Dispatchers.IO + NonCancellable) { lb.prepare(config) }
        var committed = false
        try {
            currentCoroutineContext().ensureActive()
            loop.runOnLoop {
                loop.core.commitLoadBalancer(prepared)
                committed = true
                loop.afterLbCommitForTest?.invoke()
            }
            return
        } catch (e: io.kuicksilver.quic.endpoint.QuicLbState.StaleConfiguration) {
            // defensive: the update mutexes (EndpointLoop.lbLock, LoopGroup.lbLock) already rule this out
            if (++tries >= 3) throw e
        } catch (e: Throwable) {
            if (!committed) lb.discard(prepared)
            throw e
        } finally {
            // committed, whether the caller goes on or was cancelled right then: the rest of the change happens, once
            if (committed) withContext(NonCancellable) { afterCommit() }
        }
    }
}
