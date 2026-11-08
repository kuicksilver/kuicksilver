// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.MemoryDatagramIo
import io.kuicksilver.quic.MemoryNetwork
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.endpoint.LbNullCrypto
import io.kuicksilver.quic.endpoint.QuicLbFixtures
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.QuicCrypto
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlinx.io.readByteArray
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * `loops > 1` on one socket with in-process routing by connection ID ([SocketDispatcher]): what Apple and Windows run (no
 * SO_REUSEPORT balancing), here over one in-memory socket shared by four loops, every platform.
 */
@OptIn(ExperimentalKuicksilverApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class DispatchedGroupTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val serverAddr = InetSocketAddress("10.0.0.2", 2222)

    private fun serverConfig(
        net: MemoryNetwork,
        loops: Int = 4,
        crypto: QuicCrypto = NullCryptoProvider,
        acceptQueue: Int = 1024,
        admission: ConnectionAdmission? = null,
        maxConnections: Int = 10_000,
        maxConnectionsPerIp: Int? = 256,
    ) = QuicEndpointConfig
        .Builder()
        .apply {
            server = QuicServerConfig.Builder(CoreFixtures.server()).build()
            this.crypto = crypto
            this.loops = loops
            this.acceptQueue = acceptQueue
            this.maxConnections = maxConnections
            this.maxConnectionsPerIp = maxConnectionsPerIp
            admission?.let { this.admission = it }
            io = { net.open(it) }
        }.build()

    private fun clientEndpointConfig(
        io: DatagramIo,
        crypto: QuicCrypto = NullCryptoProvider,
    ) = QuicEndpointConfig
        .Builder()
        .apply {
            this.crypto = crypto
            this.io = { io }
        }.build()

    private val clientConfig = QuicClientConfig.Builder(CoreFixtures.client()).build()

    private suspend fun clients(
        net: MemoryNetwork,
        n: Int,
        crypto: QuicCrypto = NullCryptoProvider,
    ): List<QuicEndpoint> =
        List(n) { i ->
            val io = net.open(InetSocketAddress("10.0.${1 + i / 200}.${1 + i % 200}", 1000 + i))
            QuicEndpoint.bind(io.localAddress, clientEndpointConfig(io, crypto))
        }

    private suspend fun group(cfg: QuicEndpointConfig): LoopGroup = QuicEndpoint.bind(serverAddr, cfg) as LoopGroup

    /**
     * Connects every one of [cs] with a 2 s handshake timeout and returns how many succeeded (the others were dropped by a
     * hard limit and time out); the connections stay open, so the server holds them.
     */
    private suspend fun connectedOf(cs: List<QuicEndpoint>): Int {
        val quick =
            QuicClientConfig
                .Builder(CoreFixtures.client())
                .apply { quic = io.kuicksilver.quic.quicConfig { handshakeTimeout = 2.seconds } }
                .build()
        return kotlinx.coroutines.coroutineScope {
            cs.map { async { runCatching { it.connect(serverAddr, quick) }.isSuccess } }.awaitAll().count { it }
        }
    }

    /**
     * `maxConnectionsPerIp` bounds the whole endpoint, not each loop: with four loops and a limit of 2, eight clients of one
     * address (eight ports, their Initials hashed over the loops) get two connections, and the rest are dropped and counted.
     */
    @Test fun negative_perIpLimitHoldsAcrossLoops() =
        runBlocking {
            withTimeout(60.seconds) {
                val net = MemoryNetwork()
                val g = group(serverConfig(net, maxConnectionsPerIp = 2))
                val cs =
                    List(8) { i ->
                        val io = net.open(InetSocketAddress("10.0.1.1", 1000 + i))
                        QuicEndpoint.bind(io.localAddress, clientEndpointConfig(io))
                    }
                try {
                    assertEquals(2, connectedOf(cs), "connections from one address over four loops: ${g.statsForTest()}")
                    assertTrue(g.stats.connectionsRefusedLimits >= 6, "${g.stats}")
                } finally {
                    cs.forEach { it.close() }
                    g.close()
                }
            }
        }

    /** `maxConnections` bounds the whole endpoint too: four loops with a limit of 2 hold two connections of eight clients. */
    @Test fun negative_maxConnectionsHoldsAcrossLoops() =
        runBlocking {
            withTimeout(60.seconds) {
                val net = MemoryNetwork()
                val g = group(serverConfig(net, maxConnections = 2, maxConnectionsPerIp = null))
                val cs = clients(net, 8)
                try {
                    assertEquals(2, connectedOf(cs), "connections over four loops: ${g.statsForTest()}")
                    assertTrue(g.stats.connectionsRefusedLimits >= 6, "${g.stats}")
                } finally {
                    cs.forEach { it.close() }
                    g.close()
                }
            }
        }

    /**
     * A slot comes back when its connection is gone: with a per-address limit of 1 over four loops, a second client of the
     * address (eight tries, eight ports: whatever loop each lands on) is dropped while the first connection lives, and connects
     * once the server removed it.
     */
    @Test fun negative_perIpSlotHeldUntilClose() =
        runBlocking {
            withTimeout(60.seconds) {
                val net = MemoryNetwork()
                val g = group(serverConfig(net, maxConnectionsPerIp = 1))
                val cs =
                    List(9) { i ->
                        val io = net.open(InetSocketAddress("10.0.1.1", 1000 + i))
                        QuicEndpoint.bind(io.localAddress, clientEndpointConfig(io))
                    }
                try {
                    val first = cs[0].connect(serverAddr, clientConfig)
                    val served = g.accept()
                    assertEquals(0, connectedOf(cs.subList(1, 9)), "a second connection of the address while the first lives")
                    served.close()
                    first.closed.await()
                    // the server removes its side after its closing period; a try before that is dropped and times out
                    var second = false
                    while (!second) second = connectedOf(cs.subList(1, 2)) == 1
                    assertEquals(1L, g.stats.connectionsActive, "${g.stats}")
                } finally {
                    cs.forEach { it.close() }
                    g.close()
                }
            }
        }

    /** New clients' Initials hash over every loop: 128 connections, each loop creates at least 8. One socket for the group. */
    @Test fun connectionsSpreadOverFourLoops() =
        runBlocking {
            withTimeout(60.seconds) {
                val net = MemoryNetwork()
                val g = group(serverConfig(net))
                val cs = clients(net, 128)
                try {
                    assertNotNull(g.dispatcherForTest(), "no SO_REUSEPORT on a caller's socket: dispatched in process")
                    cs.map { async { it.connect(serverAddr, clientConfig) } }.awaitAll()
                    val perLoop = g.statsForTest().map { it.connectionsCreated }
                    assertEquals(128L, perLoop.sum())
                    assertTrue(perLoop.all { it >= 8 }, "connections per loop: $perLoop")
                    assertEquals(0L, g.stats.datagramsDispatchDropped)
                    assertEquals(0L, (0 until 4).sumOf { g.forwardedForTest(it) }, "every datagram reached its owner directly")
                } finally {
                    cs.forEach { it.close() }
                    g.close()
                }
            }
        }

    /**
     * Every client gets a Retry; its second Initial carries the Retry's SCID, whose routing byte names the loop that issued it:
     * that loop validates the token and the handshakes complete (RFC 9000 section 8.1.2).
     */
    @Test fun retryTokenValidatedByIssuingLoop() =
        runBlocking {
            withTimeout(60.seconds) {
                val net = MemoryNetwork()
                val g = group(serverConfig(net, crypto = KslQuicCrypto, admission = ConnectionAdmission.AlwaysRetry))
                val cs = clients(net, 16, KslQuicCrypto)
                try {
                    val accepted = async { repeat(16) { g.accept() } }
                    cs.map { async { it.connect(serverAddr, clientConfig) } }.awaitAll()
                    accepted.await() // every server side completed its handshake
                    val s = g.stats
                    assertTrue(s.retriesSent >= 16, "retries: ${s.retriesSent}")
                    assertEquals(0L, s.invalidTokens)
                    assertEquals(16L, s.handshakesCompleted)
                    assertTrue(g.statsForTest().count { it.connectionsCreated > 0 } >= 2, "more than one loop served")
                } finally {
                    cs.forEach { it.close() }
                    g.close()
                }
            }
        }

    /** A client that moves to another address keeps its connection IDs: its datagrams go to the owner, nothing is forwarded. */
    @Test fun rebindNeedsNoForwarding() =
        runBlocking {
            withTimeout(60.seconds) {
                val net = MemoryNetwork()
                val g = group(serverConfig(net))
                val cs = clients(net, 1)
                try {
                    val accepted = async { g.accept() }
                    val c = cs[0].connect(serverAddr, clientConfig)
                    val s = accepted.await()
                    c.migrate(net.open(InetSocketAddress("10.0.9.9", 9999)))
                    val st = c.openBidi()
                    st.output.writeFully(ByteArray(50_000) { it.toByte() })
                    st.output.flushAndClose()
                    val got =
                        s
                            .acceptStream()
                            .input
                            .readBuffer()
                            .readByteArray()
                    assertEquals(50_000, got.size)
                    assertEquals(0L, (0 until 4).sumOf { g.forwardedForTest(it) }, "no loop forwarded")
                    assertEquals(0L, g.stats.statelessResets)
                    c.close()
                } finally {
                    cs.forEach { it.close() }
                    g.close()
                }
            }
        }

    /**
     * A client behind a NAT whose mapping changes: its datagrams arrive from a new address with the same connection ID. The
     * receiver hands them to the owner by that ID, nothing is forwarded, and the transfer completes on the new path.
     */
    @Test fun natRebindWithTheSameCidNeedsNoForwarding(): Unit =
        runBlocking {
            withTimeout(60.seconds) {
                val net = MemoryNetwork()
                val g = group(serverConfig(net))
                val nat = NatIo(net.open(InetSocketAddress("10.0.5.1", 5000)), net.open(InetSocketAddress("10.0.5.2", 6000)))
                val ep = QuicEndpoint.bind(nat.localAddress, clientEndpointConfig(nat))
                try {
                    val accepted = async { g.accept() }
                    val c = ep.connect(serverAddr, clientConfig)
                    val s = accepted.await()
                    val first = c.openBidi()
                    first.output.writeFully(ByteArray(10_000) { 1 })
                    first.output.flushAndClose()
                    assertEquals(
                        10_000,
                        s
                            .acceptStream()
                            .input
                            .readBuffer()
                            .readByteArray()
                            .size,
                    )
                    nat.rebound = true // the NAT maps the flow to a new public address; the connection ID stays
                    val st = c.openBidi()
                    st.output.writeFully(ByteArray(50_000) { 2 })
                    st.output.flushAndClose()
                    assertEquals(
                        50_000,
                        s
                            .acceptStream()
                            .input
                            .readBuffer()
                            .readByteArray()
                            .size,
                    )
                    assertTrue(g.stats.pathValidations >= 1, "the server validated the new address")
                    assertEquals(0L, (0 until 4).sumOf { g.forwardedForTest(it) }, "no loop forwarded")
                    assertEquals(0L, g.stats.statelessResets)
                } finally {
                    ep.close()
                    g.close()
                }
            }
        }

    /** Two sockets of one client behind a NAT: sends leave from [a] until [rebound], then from [b]; both deliver to the client. */
    private class NatIo(
        private val a: MemoryDatagramIo,
        private val b: MemoryDatagramIo,
    ) : DatagramIo {
        @kotlin.concurrent.Volatile var rebound = false
        override val localAddress: InetSocketAddress get() = a.localAddress
        override val capabilities: kotlinx.coroutines.flow.StateFlow<io.kuicksilver.quic.IoCapabilities> get() = a.capabilities

        override suspend fun receive(into: io.kuicksilver.quic.PacketBatch): Int {
            if (into.count >= into.capacity) return 0
            val (bytes, from) =
                kotlinx.coroutines.selects.select {
                    a.inbox.onReceive { it }
                    b.inbox.onReceive { it }
                }
            val i = into.count
            into.buffer(i).copyFrom(bytes, 0, 0, bytes.size)
            into.setLength(i, bytes.size)
            into.setAddress(i, from)
            return 1
        }

        override suspend fun send(batch: io.kuicksilver.quic.PacketBatch): Int = trySend(batch)

        override fun trySend(batch: io.kuicksilver.quic.PacketBatch): Int = (if (rebound) b else a).trySend(batch)

        override fun close() {
            a.close()
            b.close()
        }
    }

    /**
     * A Stateless Reset names no connection ID of ours: the receiver hands it to the loop whose connection holds the peer's
     * token (RFC 9000 section 10.3.1). The group's own client connection on loop 1 is reset by its server and ends at once
     * with the reset, not at its idle timeout.
     */
    @Test fun statelessResetReachesTheLoopHoldingTheToken(): Unit = runBlocking { resetReachesItsLoop { serverConfig(it) } }

    /** The same with QUIC-LB connection IDs, whose owner is a hash: a random reset DCID would name a random loop. */
    @Test fun statelessResetReachesTheLoopHoldingTheTokenWithQuicLb(): Unit =
        runBlocking {
            try {
                resetReachesItsLoop { net ->
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                            crypto = LbNullCrypto
                            loadBalancer = QuicLbFixtures.config()
                            loops = 4
                            io = { net.open(it) }
                        }.build()
                }
            } finally {
                io.kuicksilver.quic.endpoint.QuicLbNonceSpaces
                    .forgetForTest()
            }
        }

    private suspend fun resetReachesItsLoop(cfg: (MemoryNetwork) -> QuicEndpointConfig) =
        withTimeout(60.seconds) {
            val net = MemoryNetwork()
            val g = group(cfg(net))
            val remote = InetSocketAddress("10.0.7.7", 443)
            val server =
                QuicEndpoint.bind(
                    remote,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                            crypto = NullCryptoProvider
                            io = { net.open(it) }
                        }.build(),
                )
            try {
                val accepted = async { server.accept() }
                val c = g.connect(remote, clientConfig) // round-robin from loop 1
                val s = accepted.await()
                assertEquals(listOf(0, 1, 0, 0), g.connectionsPerLoopForTest().toList(), "the connection lives on loop 1")
                val token = assertNotNull((s as ConnectionRuntime).core.cids.localToken(0), "the server's reset token")
                // the server lost its state: a reset to the client, short-header shaped, a DCID that names no loop
                val reset = ByteArray(43) { (it * 37 + 11).toByte() }
                reset[0] = 0x4b
                token.copyInto(reset, reset.size - 16)
                net.deliver(remote, serverAddr, reset)
                val why = withTimeout(5.seconds) { c.closed.await() }
                assertIs<QuicException.ConnectionLost.StatelessReset>(why)
            } finally {
                server.close()
                g.close()
            }
        }

    /**
     * A failed preferred-address socket takes the preferred address down group-wide, as with a socket per loop: counted
     * once, the group goes on serving on its main socket.
     */
    @Test fun preferredSocketFailureDegradesTheGroup(): Unit =
        runBlocking {
            withTimeout(60.seconds) {
                val net = MemoryNetwork()
                val pref = InetSocketAddress("10.0.0.4", 4433)
                val cfg =
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            server =
                                QuicServerConfig
                                    .Builder(CoreFixtures.server())
                                    .apply { preferredAddress = io.kuicksilver.quic.PreferredAddress(pref, null) }
                                    .build()
                            crypto = NullCryptoProvider
                            loops = 4
                        }.build()
                val main = net.open(serverAddr)
                val prefIo = net.open(pref)
                val lock = kotlinx.coroutines.sync.Mutex()
                val prefLock = kotlinx.coroutines.sync.Mutex()
                val g =
                    LoopGroup.createDispatched(
                        cfg,
                        main,
                        List(4) { SerializedSender(main, lock) },
                        listOf(prefIo),
                        listOf(List(4) { SerializedSender(prefIo, prefLock) }),
                    )
                val cs = clients(net, 2)
                try {
                    val accepted = async { g.accept() }
                    cs[0].connect(serverAddr, clientConfig)
                    accepted.await()
                    prefIo.failWith(io.kuicksilver.quic.SocketDefunctException("gone", 9))
                    while (g.stats.preferredAddressFailures < 1L || !prefIo.closed) yield()
                    assertEquals(1L, g.stats.preferredAddressFailures, "one failure for the group")
                    assertTrue(!main.closed, "the main socket serves on")
                    val again = async { g.accept() }
                    cs[1].connect(serverAddr, clientConfig)
                    withTimeout(5.seconds) { again.await() }
                } finally {
                    cs.forEach { it.close() }
                    g.close()
                }
            }
        }

    /** The shared socket's ICMP Packet Too Big queue (Linux and Android with DF), faked here. */
    private class PtbIo(
        val inner: MemoryDatagramIo,
    ) : DatagramIo by inner,
        io.kuicksilver.quic.PacketTooBigSource {
        val queued = kotlinx.coroutines.channels.Channel<Triple<ByteArray, InetSocketAddress, Int>>(16)

        override fun drainPacketTooBig(sink: (quote: ByteArray, len: Int, dst: InetSocketAddress, mtu: Int) -> Unit) {
            while (true) {
                val (q, dst, mtu) = queued.tryReceive().getOrNull() ?: return
                sink(q, q.size, dst, mtu)
            }
        }
    }

    /**
     * A Packet Too Big the shared socket queued reaches the loops: the one whose connection sent the quoted datagram takes it
     * as a DPLPMTUD hint (RFC 8899 section 4.6), the others find no connection of theirs and ignore it.
     */
    @Test fun packetTooBigReachesTheLoopOfItsConnection(): Unit =
        runBlocking {
            withTimeout(60.seconds) {
                val net = MemoryNetwork()
                val io = PtbIo(net.open(serverAddr, df = true))
                val lock = kotlinx.coroutines.sync.Mutex()
                val g = LoopGroup.createDispatched(serverConfig(net), io, List(4) { SerializedSender(io, lock) })
                val clientIo = net.open(InetSocketAddress("10.0.3.1", 3000), df = true)
                val ep = QuicEndpoint.bind(clientIo.localAddress, clientEndpointConfig(clientIo))
                try {
                    val accepted = async { g.accept() }
                    val c = ep.connect(serverAddr, clientConfig)
                    val s = (accepted.await() as ConnectionRuntime).core
                    val st = c.openBidi()
                    while (s.stats.pathMtu < 1400) {
                        st.output.writeFully(ByteArray(1000))
                        st.output.flush()
                        yield()
                    }
                    // the start of a 1-RTT datagram the server sent the client: first byte, the client's ID, then anything
                    val quote = byteArrayOf(0x43) + s.remoteCid.toByteArray() + ByteArray(24) { 9 }
                    io.queued.trySend(Triple(quote, clientIo.localAddress, 1328))
                    while (g.stats.ptbAccepted < 1L || g.stats.ptbIgnored < 3L) {
                        st.output.writeFully(ByteArray(100))
                        st.output.flush()
                        yield()
                    }
                    assertEquals(1L, g.stats.ptbAccepted, "the owning loop took it")
                    assertEquals(3L, g.stats.ptbIgnored, "the other loops found no connection of theirs")
                } finally {
                    ep.close()
                    g.close()
                }
            }
        }

    /**
     * Loop 1 stops taking datagrams (a loop that fell behind) while a peer floods short headers whose routing byte names loop 1:
     * its ring fills and the rest is dropped and counted; the receiver never waits for it, and new clients still complete their
     * handshakes on loops 0, 2 and 3.
     */
    @Test fun negative_slowLoopDropsNotBlocksReceiver() =
        runBlocking {
            withTimeout(60.seconds) {
                val net = MemoryNetwork()
                val g = group(serverConfig(net))
                val d = assertNotNull(g.dispatcherForTest())
                val hold = CompletableDeferred<Unit>()
                d.inboxes[1].holdForTest = hold
                val server = d.io as MemoryDatagramIo
                val attacker = InetSocketAddress("10.9.9.9", 9999)
                val flood =
                    ByteArray(100).also {
                        it[0] = 0x40
                        it[1] = 0x01 // our format
                        it[2] = 0x01 // loop 1
                    }
                val cs = clients(net, 32)
                try {
                    var sent = 0
                    while (g.stats.datagramsDispatchDropped == 0L || sent < 10_000) {
                        if (server.inbox.trySend(flood to attacker).isSuccess) sent++ else yield()
                    }
                    // the receiver still runs: new clients on the other loops complete their handshakes meanwhile
                    val outcomes =
                        cs.map { ep -> async { withTimeoutOrNull(5.seconds) { ep.connect(serverAddr, clientConfig) } } }.awaitAll()
                    val perLoop = (0 until 4).map { g.loopForTest(it).stats.handshakesCompleted }
                    assertTrue(g.stats.datagramsDispatchDropped > 0, "the held loop's surplus was dropped")
                    assertEquals(0L, perLoop[1], "the held loop took nothing")
                    for (l in listOf(0, 2, 3)) assertTrue(perLoop[l] > 0, "loop $l completed handshakes: $perLoop")
                    for (l in listOf(0, 2, 3)) {
                        assertEquals(0L, g.loopForTest(l).stats.statelessResets, "loop $l answered loop 1's IDs with a reset")
                    }
                    assertTrue(outcomes.any { it != null }, "clients connected while loop 1 was held")
                } finally {
                    hold.complete(Unit)
                    d.inboxes[1].holdForTest = null
                    cs.forEach { it.close() }
                    g.close()
                }
            }
        }

    /** The accept queue bounds the group, not each loop: 8 clients, a queue of 4, nobody accepting: 4 wait, 4 are refused. */
    @Test fun sharedAcceptQueueRefusesGroupWide() =
        runBlocking {
            withTimeout(60.seconds) {
                val net = MemoryNetwork()
                val g = group(serverConfig(net, acceptQueue = 4))
                val cs = clients(net, 8)
                try {
                    val outcomes =
                        cs
                            .map { ep ->
                                async {
                                    try {
                                        val c = ep.connect(serverAddr, clientConfig)
                                        withTimeoutOrNull(3.seconds) { c.closed.await() }
                                    } catch (e: QuicException.ConnectionLost) {
                                        e
                                    }
                                }
                            }.awaitAll()
                    val refused = outcomes.filterIsInstance<QuicException.ConnectionLost.TransportClosed>()
                    assertEquals(4, g.loopForTest(0).pendingAcceptForTest, "connections waiting for accept() across the loops")
                    assertEquals(4, refused.size, "outcomes: $outcomes")
                    assertTrue(refused.all { it.code == TransportError.CONNECTION_REFUSED }, "refusals: $refused")
                } finally {
                    cs.forEach { it.close() }
                    g.close()
                }
            }
        }

    /** Closing the group closes the shared socket once every loop let go of it, which ends the receiver. */
    @Test fun closeWakesTheReceiver() =
        runBlocking {
            withTimeout(30.seconds) {
                val net = MemoryNetwork()
                val g = group(serverConfig(net))
                val d = assertNotNull(g.dispatcherForTest())
                val server = assertIs<MemoryDatagramIo>(d.io)
                g.closeAndJoin()
                assertNotNull(d.receiverForTest).join()
                assertTrue(server.closed, "the shared socket closed with the group")
            }
        }
}
