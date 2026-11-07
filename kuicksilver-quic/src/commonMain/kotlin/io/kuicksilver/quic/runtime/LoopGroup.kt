// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.EndpointStats
import io.kuicksilver.quic.KslDatagramIo
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.Releaser
import io.kuicksilver.quic.emit
import io.kuicksilver.quic.endpoint.SipKey
import io.kuicksilver.quic.withLiteralHost
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch

/**
 * `QuicEndpointConfig.loops` endpoint loops on one port (docs/guide/quic.md, "Several loops on one port"): each has its own
 * dispatcher, [io.kuicksilver.quic.EndpointCore] (so its own reset key; the Retry and NEW_TOKEN keys are shared) and the routing
 * byte `index` in every connection ID it issues. Two ways to share the port:
 *
 * - **Kernel** (Linux, Android: the socket is granted SO_REUSEPORT): each loop has its own accelerated socket bound with
 *   SO_REUSEPORT. The kernel hashes a client's flow onto one socket; a datagram that lands elsewhere after a rebind is copied to
 *   its owner ([EndpointLoop.forwarded]), never answered by a stranger (threat-model 3.4).
 * - **In process** (Apple, Windows, a caller-supplied [io.kuicksilver.quic.DatagramIo]: no balancing grant): one socket, whose
 *   receiver hands each datagram to the loop its connection ID names ([SocketDispatcher]); each loop sends through its own
 *   clone of the socket (`ksl_udp_sender`), or through the caller's socket under a lock. A migrated client needs no forwarding.
 *
 * Accepted connections of every loop reach one `accept()` queue; `connect` picks loops round-robin, and the client
 * connection's IDs carry its loop's routing byte, so its answers reach that loop either way.
 */
@OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class, InternalKuicksilverApi::class)
internal class LoopGroup private constructor(
    private val config: QuicEndpointConfig,
) : QuicEndpoint {
    private lateinit var loops: List<EndpointLoop>

    /** The in-process dispatchers of the shared socket and its preferred-address sockets; empty in kernel mode. */
    internal var dispatchers: List<SocketDispatcher> = emptyList()
        private set
    private val pendingAccept = AtomicInt(0)
    private val acceptQueue = EndpointLoop.acceptChannel(pendingAccept)

    /** The client's session tickets, shared by every loop: `connect` picks loops round-robin (ADR-0015). */
    private val sessions = io.kuicksilver.tls.SessionCache()
    private val next = AtomicInt(0)
    override val localAddress: InetSocketAddress get() = loops[0].localAddress

    override suspend fun connect(
        remote: InetSocketAddress,
        config: QuicClientConfig,
    ): QuicConnection =
        loops[
            (
                next.incrementAndFetch() and
                    0x7fffffff
            ) %
                loops.size,
        ].connect(remote, config)

    override suspend fun connectEarly(
        remote: InetSocketAddress,
        config: QuicClientConfig,
    ): QuicConnection = loops[(next.incrementAndFetch() and 0x7fffffff) % loops.size].connectEarly(remote, config)

    override suspend fun accept(): QuicConnection = loops[0].accept() // the queue is shared; loop 0 closes only with the group

    private val closingFlag = AtomicInt(0)

    /** Closes every loop and then the shared accept queue; a loop whose socket fails calls it too, so the group never runs half dead. */
    override fun close() = closeWith(0, "endpoint closed")

    internal fun closeWith(
        code: Long,
        reason: String,
    ) {
        if (!closingFlag.compareAndSet(0, 1)) return
        lbScope.cancel()
        for (l in loops) l.closeWith(code, reason)
        acceptQueue.close(
            io.kuicksilver.quic.QuicException
                .EndpointClosing(),
        )
    }

    override suspend fun closeAndJoin() {
        close()
        for (l in loops) l.closeAndJoin()
    }

    private val lbLock = kotlinx.coroutines.sync.Mutex()

    /** Where a configuration change's fan-out to loops 1..N runs: the caller of updateLoadBalancer does not wait for it. */
    private val lbScope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob() + kotlinx.coroutines.Dispatchers.Default)

    /** Test hooks: the last fan-out, and how long a loop has to take a change in it. */
    internal var fanOutForTest: kotlinx.coroutines.Job? = null
    internal var fanOutTimeout: kotlin.time.Duration = FAN_OUT_TIMEOUT

    /** What [updateLoadBalancer] would throw for [config], changing nothing. */
    internal suspend fun checkLoadBalancer(config: io.kuicksilver.quic.QuicLbConfig?) {
        val first = loops[0]
        first.runOnLoop { first.core.checkLoadBalancerUpdate(config) }
    }

    /**
     * One change of the shared QUIC-LB state, on loop 0 (whose core keeps the state alive while it runs), then every loop
     * moves its own server connections to it; one change at a time.
     */
    override suspend fun updateLoadBalancer(config: io.kuicksilver.quic.QuicLbConfig?) {
        lbLock.lock()
        try {
            val first = loops[0]
            // built off the loops (a nonce reservation's first store may fsync), switched to on loop 0
            val lb = first.core.lb ?: throw IllegalStateException("updateLoadBalancer needs an endpoint built with a loadBalancer")
            // once committed on loop 0, the other loops' connections move too, even if the caller is cancelled meanwhile
            // once committed on loop 0, the other loops move their connections: here as a fast path, launched in the group's
            // scope so the caller never waits on a stuck loop; a loop that misses it moves at its next receive batch anyway
            // (EndpointCore.reissueForLoadBalancer, by the configuration's generation)
            applyLoadBalancer(lb, config, first) {
                fanOutForTest =
                    lbScope.launch {
                        for (l in loops) {
                            if (l === first || l.closing) continue
                            // posted to the loop; given up after the timeout (the task then does nothing when it finally
                            // runs: that loop moves at its next receive batch). The wait is not on the loop's dispatcher,
                            // so a stuck loop cannot hold it past the timeout
                            val abandoned = kotlin.concurrent.atomics.AtomicInt(0)
                            val done = kotlinx.coroutines.CompletableDeferred<Unit>()
                            l.scope.launch {
                                if (abandoned.compareAndSet(0, 2)) l.core.reissueForLoadBalancer()
                                done.complete(Unit)
                            }
                            if (kotlinx.coroutines.withTimeoutOrNull(fanOutTimeout) { done.await() } == null &&
                                abandoned.compareAndSet(0, 1) &&
                                !l.closing &&
                                closingFlag.load() == 0 // a loop closing meanwhile never runs the task: no warning for it
                            ) {
                                l.observer.logger.emit(io.kuicksilver.quic.LogLevel.Warn) {
                                    "QUIC-LB: loop ${l.index} did not take the configuration change within $fanOutTimeout; " +
                                        "it moves its connections at its next receive batch"
                                }
                            }
                        }
                    }
            }
        } finally {
            lbLock.unlock()
        }
    }

    /** Every loop's counters, summed, and the datagrams the in-process dispatch dropped. */
    override val stats: EndpointStats
        get() {
            val s = loops.map { it.stats }.reduce { a, b -> a + b }
            if (dispatchers.isEmpty()) return s
            return s + EndpointStats(0, 0, 0, 0, 0, 0, 0, datagramsDispatchDropped = dispatchers.sumOf { it.dropped })
        }

    /** Every loop stops taking connections at once; one deadline for the whole group, then the group closes as one. */
    override suspend fun shutdown(
        grace: kotlin.time.Duration,
        code: Long,
        reason: String,
    ) {
        for (l in loops) l.beginShutdown()
        kotlinx.coroutines.withTimeoutOrNull(grace) { for (l in loops) l.awaitDrained() }
        closeWith(code, reason)
        for (l in loops) l.closeAndJoin()
    }

    /**
     * Copies one datagram of loop `from`'s socket to loop [to]; false when it was dropped because [to]'s queue is full or
     * closed (the peer retransmits; the caller counts it in `datagramsDroppedQueue`).
     */
    internal fun forward(
        to: Int,
        buf: PacketBuffer,
        length: Int,
        from: InetSocketAddress,
        ecn: Ecn,
        asReceived: Boolean,
        socket: io.kuicksilver.quic.PathId = io.kuicksilver.quic.PathId.Initial,
        local: InetSocketAddress? = null,
    ): Boolean {
        if (to >= loops.size || length > EndpointLoop.FORWARD_MAX) return true // not a queue drop: no loop takes it
        val bytes = ByteArray(length)
        buf.copyTo(bytes, 0, 0, length)
        return loops[to].forwarded.trySend(EndpointLoop.Forwarded(bytes, from, ecn, asReceived, socket, local)).isSuccess
    }

    private val preferredFailed = AtomicInt(0)

    /** True for the first loop whose preferred-address socket fails: it alone counts and logs the failure. */
    internal fun claimPreferredFailure(): Boolean = preferredFailed.compareAndSet(0, 1)

    /** The preferred address is served by every loop or by none: each loop takes its part down on its own dispatcher. */
    internal fun dropPreferred() {
        for (l in loops) l.scope.launch { l.dropPreferred() }
    }

    internal fun loopForTest(i: Int): EndpointLoop = loops[i]

    /** The in-process dispatcher of the main socket (tests); null in kernel mode. */
    internal fun dispatcherForTest(): SocketDispatcher? = dispatchers.firstOrNull()

    internal fun connectionsPerLoopForTest(): IntArray = IntArray(loops.size) { loops[it].core.connectionCount }

    internal fun forwardedForTest(loop: Int): Long = loops[loop].forwardedCount.load()

    internal fun statsForTest(): List<EndpointStats> = loops.map { it.core.stats }

    /** Hands every datagram of loop [from]'s socket to loop [to] first, as a kernel rehash would; `to = -1` stops it. */
    internal fun misrouteForTest(
        from: Int,
        to: Int,
    ) {
        loops[from].testMisrouteTo = to
    }

    /** One socket of the group and whether the system granted it SO_REUSEPORT (a test hook supplies its own). */
    internal class SharedPortSocket(
        val io: io.kuicksilver.quic.DatagramIo,
        val reusePort: Boolean,
    )

    companion object {
        /** How long a loop has to move its connections to a new QUIC-LB configuration before the update goes on without it. */
        private val FAN_OUT_TIMEOUT = kotlin.time.Duration.parse("5s")

        /** A preferred-address twin bound without the grant the main socket had (kernel mode needs it on every port). */
        internal const val NO_REUSEPORT = "loops > 1 needs SO_REUSEPORT, which this platform/socket does not grant"

        suspend fun bind(
            local: InetSocketAddress,
            config: QuicEndpointConfig,
        ): QuicEndpoint {
            val callerIo = config.io
            if (callerIo != null) {
                // the caller's socket balances nothing: one socket, dispatched in process, sends under a lock
                require(config.loops > 1 && config.server != null)
                EndpointLoop.checkPayloadSize(config.server.quic)
                return bindDispatched(config, callerIo(local)) { at -> callerIo(at) }
            }
            return bindWith(local, config) { at ->
                KslDatagramIo.open(at, reusePort = true)?.let { SharedPortSocket(it, it.reusePortGranted) }
            }
        }

        /**
         * [bind] over [open]. A first socket granted SO_REUSEPORT (Linux, Android) gets twins on its port, one per loop: the
         * kernel balances. Without the grant (Darwin hands every datagram to one socket, Windows binds exclusively, a Linux
         * seccomp filter refuses the option) no second socket is bound: the first one is shared in process ([bindDispatched]).
         */
        internal suspend fun bindWith(
            local: InetSocketAddress,
            config: QuicEndpointConfig,
            open: (InetSocketAddress) -> SharedPortSocket?,
        ): QuicEndpoint {
            require(config.loops > 1 && config.server != null)
            EndpointLoop.checkPayloadSize(config.server.quic)
            val first = open(local) ?: throw UnsupportedOperationException("loops > 1 needs the accelerated transport")
            if (!first.reusePort) {
                return bindDispatched(config, first.io) { at ->
                    open(at)?.io ?: throw UnsupportedOperationException("accelerated transport unavailable for the preferred address $at")
                }
            }
            val ios = ArrayList<io.kuicksilver.quic.DatagramIo>(config.loops)
            ios += first.io
            try {
                val port = first.io.localAddress.port
                while (ios.size <
                    config.loops
                ) {
                    ios += open(local.withLiteralHost(port))?.io ?: throw UnsupportedOperationException("accelerated transport unavailable")
                }
            } catch (e: Throwable) {
                for (io in ios) io.close()
                throw e
            }
            // every loop listens on the preferred addresses too, sharing each port as it shares the main one (SO_REUSEPORT): the kernel
            // hashes a moved client onto one of them, and a loop that does not own the connection copies the datagram to the one that does
            val preferred = ArrayList<List<io.kuicksilver.quic.DatagramIo>>(config.loops)
            try {
                repeat(config.loops) {
                    preferred +=
                        EndpointLoop.openPreferred(config, first.io.localAddress) { at ->
                            val s =
                                open(at)
                                    ?: throw UnsupportedOperationException(
                                        "accelerated transport unavailable for the preferred address $at",
                                    )
                            if (!s.reusePort) {
                                s.io.close()
                                throw UnsupportedOperationException(NO_REUSEPORT)
                            }
                            s.io
                        }
                }
            } catch (e: Throwable) {
                for (l in preferred) for (p in l) p.close()
                for (io in ios) io.close()
                throw e
            }
            return create(config, ios, preferred = preferred)
        }

        /**
         * The in-process mode over [io], bound already (the group owns it from here): the preferred-address sockets, opened
         * with [openOther], are shared the same way. Every loop gets a sender per socket ([sendersFor]).
         */
        private suspend fun bindDispatched(
            config: QuicEndpointConfig,
            socket: DatagramIo,
            openOther: suspend (InetSocketAddress) -> DatagramIo,
        ): QuicEndpoint {
            val preferred =
                try {
                    EndpointLoop.openPreferred(config, socket.localAddress, openOther)
                } catch (e: Throwable) {
                    Releaser(e).release { socket.close() }
                    throw e
                }
            val senders = ArrayList<List<DatagramIo>>(1 + preferred.size)
            try {
                senders += sendersFor(socket, config.loops)
                for (p in preferred) senders += sendersFor(p, config.loops)
            } catch (e: Throwable) {
                val r = Releaser(e)
                for (l in senders) for (s in l) r.release { s.close() }
                for (p in preferred) r.release { p.close() }
                r.release { socket.close() }
                throw e
            }
            return createDispatched(config, socket, senders[0], preferred, senders.drop(1))
        }

        /** One sender per loop on [socket]: a send-only clone of the accelerated socket, else [socket] itself under one lock. */
        private fun sendersFor(
            socket: DatagramIo,
            loops: Int,
        ): List<DatagramIo> {
            if (socket !is KslDatagramIo) {
                val lock = kotlinx.coroutines.sync.Mutex()
                return List(loops) { SerializedSender(socket, lock) }
            }
            val out = ArrayList<DatagramIo>(loops)
            try {
                repeat(loops) { out += socket.sender() }
            } catch (e: Throwable) {
                val r = Releaser(e)
                for (s in out) r.release { s.close() }
                throw e
            }
            return out
        }

        /**
         * A group sharing [socket] in process: [senders] (one per loop) send on it, [preferred] sockets with [preferredSenders] are
         * shared the same way. The sockets and senders are handed to the group, which closes them on any failure. [allocate]
         * and [afterBuild] are test hooks, as in [create].
         */
        internal suspend fun createDispatched(
            config: QuicEndpointConfig,
            socket: DatagramIo,
            senders: List<DatagramIo>,
            preferred: List<DatagramIo> = emptyList(),
            preferredSenders: List<List<DatagramIo>> = emptyList(),
            allocate: (Int) -> PacketBuffer = PacketBuffer::allocate,
            afterBuild: suspend () -> Unit = {},
        ): LoopGroup {
            require(senders.size == config.loops && preferredSenders.size == preferred.size)
            val random = KslRandom.newSource()
            val key = SipKey(random.nextLong(), random.nextLong())
            val main = SocketDispatcher(socket, senders, config.connectionIdLength, key, allocate)
            val others = preferred.mapIndexed { k, p -> SocketDispatcher(p, preferredSenders[k], config.connectionIdLength, key, allocate) }
            // the loops' views of the sockets: closing them (a failed build included) closes the senders, the last one each socket
            val g =
                create(
                    config,
                    main.inboxes,
                    preferred = List(config.loops) { i -> others.map { it.inboxes[i] } },
                    allocate = allocate,
                    afterBuild = afterBuild,
                )
            g.dispatchers = listOf(main) + others
            try {
                // every loop routes connection IDs alike: loop 0's route answers for the group, from the receivers' threads
                val route = g.loops[0].core.route
                for (d in g.dispatchers) {
                    d.start(route) { e ->
                        g.loops[0].observer.logger.emit(LogLevel.Error, e) {
                            "endpoint ${d.io.localAddress}: the shared socket failed; closing the endpoint"
                        }
                        g.close()
                    }
                }
            } catch (e: Throwable) {
                Releaser(e).release { withContext(NonCancellable) { g.closeAndJoin() } }
                throw e
            }
            return g
        }

        private fun closeSockets(
            r: Releaser,
            ios: List<io.kuicksilver.quic.DatagramIo>,
            preferred: List<List<io.kuicksilver.quic.DatagramIo>>,
        ) {
            for (io in ios) r.release { io.close() }
            for (l in preferred) for (p in l) r.release { p.close() }
        }

        /** Builds every loop first, then starts them: a loop that receives before its peers exist would forward into nothing. [afterBuild] is a test hook. */
        internal suspend fun create(
            config: QuicEndpointConfig,
            ios: List<io.kuicksilver.quic.DatagramIo>,
            preferred: List<List<io.kuicksilver.quic.DatagramIo>> = emptyList(),
            allocate: (Int) -> PacketBuffer = PacketBuffer::allocate,
            afterBuild: suspend () -> Unit = {},
        ): LoopGroup {
            val g = LoopGroup(config)
            // one set of Retry and NEW_TOKEN keys for every loop: the kernel may hash a client's next connection onto another
            // socket. The group holds one reference while it builds the loops, each loop's endpoint core takes its own, and the
            // last one to close frees the keys; a loop that fails to build leaves no reference behind
            val tokens =
                try {
                    io.kuicksilver.quic.endpoint.AddressTokens(
                        config.crypto,
                        KslRandom.newSource(),
                        newTokenLifetime = config.server!!.newTokenLifetime,
                        replayCapacity = config.server.newTokenReplayCapacity,
                    )
                } catch (e: Throwable) {
                    // no loop exists yet; the sockets were handed to this group
                    closeSockets(Releaser(e), ios, preferred)
                    throw e
                }
            // one QUIC-LB state for every loop: the IDs any loop issues hash onto the loops with one key and draw one nonce counter
            val lb =
                try {
                    config.loadBalancer?.let {
                        io.kuicksilver.quic.endpoint.QuicLbState(
                            config.crypto,
                            KslRandom.newSource(),
                            it,
                            config.loops,
                            config.connectionIdLength,
                        )
                    }
                } catch (e: Throwable) {
                    val r = Releaser(e)
                    r.release { tokens.close() }
                    closeSockets(r, ios, preferred)
                    throw e
                }
            val loops = ArrayList<EndpointLoop>(ios.size)
            try {
                for ((i, io) in ios.withIndex()) {
                    loops +=
                        EndpointLoop.inGroup(
                            config,
                            io,
                            i,
                            g,
                            g.acceptQueue,
                            g.pendingAccept,
                            g.sessions,
                            tokens,
                            preferred.getOrElse(i) { emptyList() },
                            allocate,
                            lb,
                        )
                }
                afterBuild()
            } catch (e: Throwable) {
                // never started: each built loop frees its core (its reference to the group's keys) and batches; the sockets
                // were handed to this group, so they close here too
                val r = Releaser(e)
                for (l in loops) r.release { l.discardUnstarted() }
                closeSockets(r, ios, preferred)
                throw e
            } finally {
                tokens.close() // the group's own reference
                lb?.close() // likewise
            }
            g.loops = loops
            try {
                for (l in loops) l.start()
            } catch (e: Throwable) {
                // a loop that started may already receive: the group's close takes every loop down, sockets included
                Releaser(e).release { withContext(NonCancellable) { g.closeAndJoin() } }
                throw e
            }
            return g
        }
    }
}
