// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.MemoryDatagramIo
import io.kuicksilver.quic.MemoryNetwork
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException
import kotlin.concurrent.Volatile
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** A [LoopGroup] over in-memory sockets (all platforms): it comes up whole and goes down whole. */
@OptIn(
    ExperimentalKuicksilverApi::class,
    DelicateKuicksilverApi::class,
    kotlin.concurrent.atomics.ExperimentalAtomicApi::class,
    kotlinx.coroutines.ExperimentalCoroutinesApi::class,
)
class LoopGroupTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private class FailingIo(
        val inner: MemoryDatagramIo,
    ) : DatagramIo by inner {
        @Volatile var fail = false

        override suspend fun receive(into: PacketBatch): Int {
            val n = inner.receive(into)
            if (fail) throw IOException("recvmsg: EBADF")
            return n
        }
    }

    private val serverAddr = InetSocketAddress("10.0.0.2", 2222)
    private val otherAddr = InetSocketAddress("10.0.0.3", 2222)
    private val clientAddr = InetSocketAddress("10.0.0.1", 1111)
    private val config =
        QuicEndpointConfig
            .Builder()
            .apply {
                server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                crypto =
                    NullCryptoProvider
                loops = 2
            }.build()

    private fun client(io: DatagramIo) =
        QuicEndpointConfig
            .Builder()
            .apply {
                crypto = NullCryptoProvider
                this.io = { io }
            }.build()

    private val clientConfig = QuicClientConfig.Builder(CoreFixtures.client()).build()

    @Test fun aDatagramForAnotherLoopBeforeStartupDoesNotKillTheGroup() =
        runBlocking {
            withTimeout(30.seconds) {
                val net = MemoryNetwork()
                val io0 = net.open(serverAddr)
                val io1 = net.open(otherAddr)
                // a short-header datagram whose connection ID names loop 1 is already waiting on loop 0's socket
                val dgram = ByteArray(100)
                dgram[0] = 0x40
                dgram[1] = 0x01
                dgram[2] = 0x01
                io0.inbox.trySend(dgram to InetSocketAddress("10.0.0.9", 9999))
                val group =
                    LoopGroup.create(config, listOf(io0, io1)) {
                        withTimeoutOrNull(500.milliseconds) { while (!io0.inbox.isEmpty) delay(5) }
                        delay(100)
                    } // give a loop that runs too early the time to take it
                val client = QuicEndpoint.bind(clientAddr, client(net.open(clientAddr)))
                try {
                    val accepted = async { group.accept() }
                    client.connect(serverAddr, clientConfig)
                    withTimeout(5.seconds) { accepted.await() }
                    Unit
                } finally {
                    client.close()
                    group.close()
                }
            }
        }

    @Test fun forwardedBurstDoesNotMonopoliseTheLoop() =
        runBlocking {
            withTimeout(30.seconds) {
                // forwarded datagrams are processed in batches with admission, flush and a yield between them
                val net = MemoryNetwork()
                val group = LoopGroup.create(config, listOf(net.open(serverAddr), net.open(otherAddr)))
                try {
                    val loop = group.loopForTest(0)
                    val before = loop.afterReceiveCount
                    kotlinx.coroutines.withContext(loop.dispatcher) {
                        repeat(1000) {
                            loop.forwarded.trySend(
                                EndpointLoop.Forwarded(
                                    ByteArray(30) {
                                        0x40
                                    },
                                    clientAddr,
                                    io.kuicksilver.quic.Ecn.NotEct,
                                    asReceived = false,
                                ),
                            )
                        }
                    } // queued while the loop is busy: all 1000 wait at once
                    withTimeout(10.seconds) { while (loop.forwardedCount.load() < 1000) delay(10) }
                    val rounds = loop.afterReceiveCount - before
                    assertTrue(
                        rounds >= 1000 / EndpointLoop.FORWARD_BATCH,
                        "admission + flush ran after every batch of forwarded datagrams: $rounds rounds for 1000",
                    )
                } finally {
                    group.close()
                }
            }
        }

    @Test fun oneFailedLoopClosesTheWholeGroup() =
        runBlocking {
            withTimeout(30.seconds) {
                val net = MemoryNetwork()
                val io0 = net.open(serverAddr)
                val io1 = FailingIo(net.open(otherAddr))
                val group = LoopGroup.create(config, listOf(io0, io1))
                try {
                    io1.fail = true
                    io1.inner.inbox.trySend(ByteArray(10) to clientAddr) // loop 1's socket dies
                    assertFailsWith<QuicException.EndpointClosing> { withTimeout(5.seconds) { group.accept() } }
                    repeat(2) {
                        assertFailsWith<QuicException.EndpointClosing>("connect $it (round-robin over both loops)") {
                            withTimeout(2.seconds) { group.connect(clientAddr, clientConfig) }
                        }
                    }
                } finally {
                    group.close()
                }
            }
        }

    @Test fun ticketsAreSharedByTheGroupsLoops() =
        runBlocking {
            withTimeout(30.seconds) {
                // connect picks loops round-robin: a ticket one loop received must serve a 0-RTT connect on another
                val net = MemoryNetwork()
                val server =
                    QuicEndpoint.bind(
                        serverAddr,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                this.server = QuicServerConfig.Builder(CoreFixtures.server()).apply { earlyData = true }.build()
                                crypto = KslQuicCrypto
                                io = { net.open(serverAddr) }
                            }.build(),
                    )
                val clients =
                    LoopGroup.create(
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                this.server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                                crypto = KslQuicCrypto
                                loops = 2
                            }.build(),
                        listOf(net.open(clientAddr), net.open(InetSocketAddress("10.0.0.1", 1112))),
                    )
                val early = QuicClientConfig.Builder(CoreFixtures.client()).apply { earlyData = EarlyDataState.Allowed }.build()
                try {
                    val accepted = async { repeat(2) { server.accept() } }
                    val first = clients.connect(serverAddr, early)
                    while (clients.loopForTest(0).sessions.size() + clients.loopForTest(1).sessions.size() == 0) kotlinx.coroutines.yield()
                    first.close()
                    val second = clients.connectEarly(serverAddr, early)
                    second.awaitHandshake()
                    kotlin.test.assertEquals(true, second.earlyDataAccepted, "the other loop found the ticket")
                    accepted.await()
                } finally {
                    clients.close()
                    server.close()
                }
            }
        }
}
