// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

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
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.runtime.EndpointLoop
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** Endpoint-level lifecycle of the runtime. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class EndpointLifecycleTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun closeAndJoinReturnsOnceTheSocketIsClosed() =
        runBlocking {
            val p = ApiPair.open()
            withTimeout(30.seconds) {
                // close() is asynchronous (CONNECTION_CLOSE and the socket close happen on the loop); closeAndJoin() waits for them (early user feedback)
                val (c, s) = p.connect()
                p.client.closeAndJoin()
                assertTrue(p.clientIo.closed, "the socket is closed when closeAndJoin returns")
                assertTrue(c.closed.isCompleted, "and so is the connection")
                assertFailsWith<QuicException.EndpointClosing> {
                    p.client.connect(p.server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                }
                p.server.closeAndJoin()
                assertTrue(s.closed.isCompleted)
            }
        }

    @Test fun cancelledConnectClosesTheConnection() =
        runBlocking {
            ApiPair.open(serverAnswers = false).use { p ->
                withTimeout(30.seconds) {
                    // a cancelled connect leaves nothing behind; the connection closes (one closing period, 3 PTO) instead of retrying until the handshake timeout
                    val loop = p.client as EndpointLoop
                    val job = launch { p.client.connect(p.server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build()) }
                    delay(200)
                    assertEquals(1, loop.core.connectionCount)
                    job.cancel()
                    job.join()
                    withTimeoutOrNull(5.seconds) { while (loop.core.connectionCount > 0) delay(20) }
                    assertEquals(0, loop.core.connectionCount, "the cancelled connection was retired")
                }
            }
        }

    @Test fun connectCancelledRightAfterAdoptionClosesTheConnection() =
        runBlocking {
            ApiPair.open(serverAnswers = false).use { p ->
                withTimeout(30.seconds) {
                    // cancellation at the withContext exit (after the loop adopted the connection) must not lose it either
                    val loop = p.client as EndpointLoop
                    repeat(5) {
                        val job =
                            launch(start = CoroutineStart.UNDISPATCHED) {
                                p.client.connect(p.server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                            }
                        job.cancel()
                        job.join()
                    }
                    withTimeoutOrNull(5.seconds) { while (loop.core.connectionCount > 0) delay(20) }
                    assertEquals(0, loop.core.connectionCount, "no cancelled connection was kept")
                }
            }
        }

    @Test fun acceptAfterCloseThrowsEvenWithQueuedConnections() =
        runBlocking {
            val p = ApiPair.open()
            withTimeout(30.seconds) {
                // close() makes accept() throw from then on, also when handshaken connections were still waiting in the queue
                p.client.connect(p.server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                delay(200) // the server side is queued, never accepted
                p.server.close()
                assertFailsWith<QuicException.EndpointClosing> { p.server.accept() }
                p.client.close()
            }
        }

    @Test fun payloadSizeAboveTheRuntimeSlotIsRefused() =
        runBlocking {
            // the loop's datagram slots hold 1500 bytes; advertising more would let peers send datagrams the runtime truncates
            assertFailsWith<IllegalArgumentException> { ApiPair.open(serverQuic = quicConfig { maxUdpPayloadSize = 9000 }) }
            ApiPair.open().use { p ->
                assertFailsWith<IllegalArgumentException> {
                    p.client.connect(
                        p.server.localAddress,
                        QuicClientConfig
                            .Builder(CoreFixtures.client())
                            .apply {
                                quic =
                                    quicConfig { maxUdpPayloadSize = 9000 }
                            }.build(),
                    )
                }
                assertEquals(0, (p.client as EndpointLoop).core.connectionCount)
            }
        }

    /** The server's socket: its first receive waits until [held] datagrams are queued and returns them in one batch, so they reach one admission round. */
    private class HoldIo(
        private val inner: MemoryDatagramIo,
        private val held: Int,
    ) : DatagramIo by inner {
        private var released = false

        override suspend fun receive(into: PacketBatch): Int {
            if (released) return inner.receive(into)
            while (inner.received < held) delay(5)
            released = true
            var n = 0
            repeat(held) { n += inner.receive(into) }
            return n
        }
    }

    /** A client socket that sends but never hears back: its Initials stand for spoofed-source ones (the server's replies go nowhere). */
    private class DeafIo(
        private val inner: MemoryDatagramIo,
    ) : DatagramIo by inner {
        override suspend fun receive(into: PacketBatch): Int = kotlinx.coroutines.awaitCancellation()
    }

    @Test fun negative_spoofedInitialsDoNotLockOutAdmission() =
        runBlocking {
            withTimeout(30.seconds) {
                // acceptQueue half-open handshakes from sources that never answer must not refuse a real client until they time out
                val net = MemoryNetwork()
                val serverAddr = InetSocketAddress("10.0.0.2", 2222)
                val server =
                    QuicEndpoint.bind(
                        serverAddr,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                this.server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                                crypto = NullCryptoProvider
                                acceptQueue = 2
                                io = { net.open(serverAddr) }
                            }.build(),
                    )
                val loop = server as EndpointLoop

                suspend fun client(io: DatagramIo) =
                    QuicEndpoint.bind(
                        io.localAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                crypto = NullCryptoProvider
                                this.io = { io }
                            }.build(),
                    )
                val spoofed = (1..2).map { i -> client(DeafIo(net.open(InetSocketAddress("10.0.9.$i", 4000 + i)))) }
                val honest = client(net.open(InetSocketAddress("10.0.1.1", 1001)))
                try {
                    spoofed.forEach { ep ->
                        launch { runCatching { ep.connect(serverAddr, QuicClientConfig.Builder(CoreFixtures.client()).build()) } }
                    }
                    while (loop.handshakingForTest < 2) delay(5)
                    val c =
                        withTimeoutOrNull(5.seconds) {
                            honest.connect(serverAddr, QuicClientConfig.Builder(CoreFixtures.client()).build())
                        }
                    assertTrue(c != null, "a real client is admitted while ${loop.handshakingForTest} spoofed handshakes are in flight")
                } finally {
                    spoofed.forEach { it.close() }
                    honest.close()
                    server.close()
                }
            }
        }

    @Test fun cancelledAcceptReleasesItsSlot() =
        runBlocking {
            withTimeout(30.seconds) {
                // an accept() cancelled just after the queue handed it a connection must not keep its slot (nor the connection)
                val net = MemoryNetwork()
                val serverAddr = InetSocketAddress("10.0.0.2", 2222)
                val server =
                    QuicEndpoint.bind(
                        serverAddr,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                this.server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                                crypto = NullCryptoProvider
                                acceptQueue = 2
                                io = { net.open(serverAddr) }
                            }.build(),
                    )
                val clientIo = net.open(InetSocketAddress("10.0.1.1", 1001))
                val client =
                    QuicEndpoint.bind(
                        clientIo.localAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                crypto = NullCryptoProvider
                                io = { clientIo }
                            }.build(),
                    )
                val loop = server as EndpointLoop
                try {
                    repeat(3) {
                        val handed = loop.acceptHandOffsForTest
                        val waiter = launch(start = CoroutineStart.UNDISPATCHED) { server.accept() }
                        launch(kotlinx.coroutines.Dispatchers.Default) {
                            runCatching { client.connect(serverAddr, QuicClientConfig.Builder(CoreFixtures.client()).build()) }
                        }
                        // spin without suspending: the queue resumes the waiter, which cannot run on this thread before the cancel
                        val spin =
                            kotlin.time.TimeSource.Monotonic
                                .markNow()
                        while (loop.acceptHandOffsForTest == handed) {
                            // a leaked slot refuses the handshake instead: fail rather than spin past withTimeout
                            if (spin.elapsedNow() >
                                10.seconds
                            ) {
                                kotlin.test.fail(
                                    "handshake ${it + 1} never reached the accept queue (pending ${loop.pendingAcceptForTest})",
                                )
                            }
                        }
                        waiter.cancel()
                        waiter.join()
                    }
                    while (loop.pendingAcceptForTest != 0) delay(5)
                    val accepted = async { server.accept() }
                    client.connect(serverAddr, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    accepted.await()
                    assertEquals(0, loop.pendingAcceptForTest)
                } finally {
                    client.close()
                    server.close()
                }
            }
        }

    @Test fun refusedClientHearsTheClosePromptly() =
        runBlocking {
            withTimeout(30.seconds) {
                // the CONNECTION_CLOSE of a refused handshake leaves in the flush that refused it, not with the next event
                val net = MemoryNetwork()
                val serverAddr = InetSocketAddress("10.0.0.2", 2222)
                val sio = HoldIo(net.open(serverAddr), held = 2) // both Initials in one admission round: both handshakes complete
                val server =
                    QuicEndpoint.bind(
                        serverAddr,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                this.server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                                crypto = NullCryptoProvider
                                acceptQueue = 1
                                io = { sio }
                            }.build(),
                    )
                val clients =
                    (1..2).map { i ->
                        val io = net.open(InetSocketAddress("10.0.1.$i", 1000 + i))
                        QuicEndpoint.bind(
                            io.localAddress,
                            QuicEndpointConfig
                                .Builder()
                                .apply {
                                    crypto = NullCryptoProvider
                                    this.io = { io }
                                }.build(),
                        )
                    }
                val loop = server as EndpointLoop
                try {
                    val outcomes =
                        clients
                            .map { ep ->
                                async {
                                    try {
                                        val c = ep.connect(serverAddr, QuicClientConfig.Builder(CoreFixtures.client()).build())
                                        withTimeoutOrNull(2.seconds) { c.closed.await() }
                                    } catch (e: QuicException.ConnectionLost) {
                                        e
                                    }
                                }
                            }.awaitAll()
                    val refused = outcomes.filterIsInstance<QuicException.ConnectionLost.TransportClosed>()
                    assertEquals(1, refused.size, "outcomes within 2 s: $outcomes")
                    assertEquals(TransportError.CONNECTION_REFUSED, refused.single().code)
                    assertEquals(0L, loop.flushesEndingDirtyForTest, "flushes that left a connection dirty")
                } finally {
                    clients.forEach { it.close() }
                    server.close()
                }
            }
        }

    @Test fun acceptBacklogNeverExceedsAcceptQueue() =
        runBlocking {
            withTimeout(30.seconds) {
                // nobody calls accept(): admission lets all six in (none waits yet), so this exercises the completion-time bound
                // alone: no more than acceptQueue wait, the connections that complete above it are refused with CONNECTION_REFUSED
                val net = MemoryNetwork()
                val serverAddr = InetSocketAddress("10.0.0.2", 2222)
                val sio = HoldIo(net.open(serverAddr), held = 6)
                val server =
                    QuicEndpoint.bind(
                        serverAddr,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                this.server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                                crypto = NullCryptoProvider
                                acceptQueue = 2
                                io = { sio }
                            }.build(),
                    )
                val clients =
                    (1..6).map { i ->
                        val io = net.open(InetSocketAddress("10.0.1.$i", 1000 + i))
                        QuicEndpoint.bind(
                            io.localAddress,
                            QuicEndpointConfig
                                .Builder()
                                .apply {
                                    crypto = NullCryptoProvider
                                    this.io = { io }
                                }.build(),
                        )
                    }
                try {
                    val outcomes =
                        clients
                            .map { ep ->
                                async {
                                    try {
                                        val c: QuicConnection =
                                            ep.connect(
                                                serverAddr,
                                                QuicClientConfig.Builder(CoreFixtures.client()).build(),
                                            )
                                        withTimeoutOrNull(3.seconds) { c.closed.await() }
                                    } catch (e: QuicException.ConnectionLost) {
                                        e
                                    }
                                }
                            }.awaitAll()
                    val loop = server as EndpointLoop
                    assertTrue(loop.pendingAcceptForTest <= 2, "waiting for accept(): ${loop.pendingAcceptForTest}")
                    val refused = outcomes.filterIsInstance<QuicException.ConnectionLost.TransportClosed>()
                    assertEquals(4, refused.size, "outcomes: $outcomes")
                    assertTrue(refused.all { it.code == TransportError.CONNECTION_REFUSED }, "refusals: $refused")
                } finally {
                    clients.forEach { it.close() }
                    server.close()
                }
            }
        }
}
