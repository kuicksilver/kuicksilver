// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.EndpointStats
import io.kuicksilver.quic.KslDatagramIo
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.withLiteralHost
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch

/**
 * `QuicEndpointConfig.loops` endpoint loops on one port (docs/guide/quic.md, "Several loops on one port"): each has its own accelerated socket bound with
 * SO_REUSEPORT, its own dispatcher, [io.kuicksilver.quic.EndpointCore] (so its own Retry and reset keys) and the routing
 * byte `index` in every connection ID it issues. The kernel hashes a client's flow onto one socket; a datagram that lands
 * elsewhere after a rebind is copied to its owner ([EndpointLoop.forwarded]), never answered by a stranger (threat-model
 * 3.4). Accepted connections of every loop reach one `accept()` queue; `connect` picks loops round-robin, and the client
 * connection's IDs carry its loop's routing byte, so the answers the kernel hashes onto another loop's socket are copied back.
 */
@OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class, InternalKuicksilverApi::class)
internal class LoopGroup private constructor(
    private val config: QuicEndpointConfig,
) : QuicEndpoint {
    private lateinit var loops: List<EndpointLoop>
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

    /** Every loop's counters, summed. */
    override val stats: EndpointStats get() = loops.map { it.stats }.reduce { a, b -> a + b }

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
    ): Boolean {
        if (to >= loops.size || length > EndpointLoop.FORWARD_MAX) return true // not a queue drop: no loop takes it
        val bytes = ByteArray(length)
        buf.copyTo(bytes, 0, 0, length)
        return loops[to].forwarded.trySend(EndpointLoop.Forwarded(bytes, from, ecn, asReceived)).isSuccess
    }

    internal fun loopForTest(i: Int): EndpointLoop = loops[i]

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
        internal const val NO_REUSEPORT = "loops > 1 needs SO_REUSEPORT, which this platform/socket does not grant"

        suspend fun bind(
            local: InetSocketAddress,
            config: QuicEndpointConfig,
        ): QuicEndpoint =
            bindWith(local, config) { at ->
                KslDatagramIo.open(at, reusePort = true)?.let { SharedPortSocket(it, it.reusePortGranted) }
            }

        /**
         * [bind] over [open]. The first socket must come back with SO_REUSEPORT granted, else it is closed and `bind` throws
         * [UnsupportedOperationException]: without the grant the second bind on the port fails with a socket error (Windows'
         * exclusive bind, Darwin, Linux under a seccomp filter), which is not the documented refusal.
         */
        internal suspend fun bindWith(
            local: InetSocketAddress,
            config: QuicEndpointConfig,
            open: (InetSocketAddress) -> SharedPortSocket?,
        ): QuicEndpoint {
            require(config.loops > 1 && config.server != null)
            EndpointLoop.checkPayloadSize(config.server.quic)
            if (config.io !=
                null
            ) {
                throw UnsupportedOperationException(
                    "loops > 1 needs the accelerated transport with SO_REUSEPORT, not a caller-supplied DatagramIo",
                )
            }
            val first = open(local) ?: throw UnsupportedOperationException("loops > 1 needs the accelerated transport")
            if (!first.reusePort) {
                first.io.close()
                throw UnsupportedOperationException(NO_REUSEPORT)
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
            return create(config, ios)
        }

        /** Builds every loop first, then starts them: a loop that receives before its peers exist would forward into nothing. [afterBuild] is a test hook. */
        internal suspend fun create(
            config: QuicEndpointConfig,
            ios: List<io.kuicksilver.quic.DatagramIo>,
            afterBuild: suspend () -> Unit = {},
        ): LoopGroup {
            val g = LoopGroup(config)
            val loops = ios.mapIndexed { i, io -> EndpointLoop.inGroup(config, io, i, g, g.acceptQueue, g.pendingAccept, g.sessions) }
            afterBuild()
            g.loops = loops
            for (l in loops) l.start()
            return g
        }
    }
}
