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
    ) = QuicEndpointConfig
        .Builder()
        .apply {
            server = QuicServerConfig.Builder(CoreFixtures.server()).build()
            this.crypto = crypto
            this.loops = loops
            this.acceptQueue = acceptQueue
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
     * Loop 1 stops taking datagrams (a loop that fell behind) while a peer floods short headers whose routing byte names loop 1:
     * its batches fill and the rest is dropped and counted; the receiver never waits for it, and new clients still complete their
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
