// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.readFully
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CapturingLogger
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.MemoryDatagramIo
import io.kuicksilver.quic.MemoryNetwork
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicLbConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.endpoint.LbNullCrypto
import io.kuicksilver.quic.endpoint.QuicLbFixtures
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException
import kotlinx.io.readByteArray
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
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

    /** Each test starts with no nonce space of an earlier one (and frees their plaintext keys). */
    @kotlin.test.AfterTest fun forgetNonceSpaces() =
        io.kuicksilver.quic.endpoint.QuicLbNonceSpaces
            .forgetForTest()

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

    private fun configWith(log: KuicksilverLogger? = null) =
        QuicEndpointConfig
            .Builder()
            .apply {
                server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                crypto =
                    NullCryptoProvider
                loops = 2
                log?.let { logger = it }
            }.build()

    private val config = configWith()

    private fun client(io: DatagramIo) =
        QuicEndpointConfig
            .Builder()
            .apply {
                crypto = NullCryptoProvider
                this.io = { io }
            }.build()

    private val clientConfig = QuicClientConfig.Builder(CoreFixtures.client()).build()

    @Test fun loopsAboveOneWithoutReusePortGrantIsUnsupported() =
        runBlocking {
            val net = MemoryNetwork()
            val first = net.open(serverAddr)
            var opened = 0
            val e =
                assertFailsWith<UnsupportedOperationException> {
                    LoopGroup.bindWith(serverAddr, config) { at ->
                        opened++
                        LoopGroup.SharedPortSocket(if (opened == 1) first else net.open(at), reusePort = false)
                    }
                }
            assertEquals(LoopGroup.NO_REUSEPORT, e.message)
            assertEquals(1, opened, "no second bind without the grant")
            assertTrue(first.closed, "the first socket is closed")
        }

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

    /** The second socket on a port shared with SO_REUSEPORT: it sends with [real]'s address and receives nothing (the kernel hashed the flow onto [real]). */
    private class SharedPortTwin(
        val real: MemoryDatagramIo,
    ) : DatagramIo by real {
        private val failure = kotlinx.coroutines.CompletableDeferred<Throwable>()

        override suspend fun receive(into: PacketBatch): Int = throw failure.await()

        /** The twin's receive fails with [e], as a socket error would. */
        fun failWith(e: Throwable) {
            failure.complete(e)
        }

        override fun close() {}
    }

    /** A loops=2 group of [net] whose preferred address [pref] is [real] on loop [owner] and a [SharedPortTwin] of it on the other loop. */
    private suspend fun groupWithPreferred(
        net: MemoryNetwork,
        pref: InetSocketAddress,
        real: MemoryDatagramIo,
        twin: SharedPortTwin,
        owner: Int,
        log: KuicksilverLogger? = null,
    ): LoopGroup {
        val withPreferred =
            QuicEndpointConfig
                .Builder()
                .apply {
                    server =
                        QuicServerConfig
                            .Builder(CoreFixtures.server())
                            .apply { preferredAddress = io.kuicksilver.quic.PreferredAddress(pref, null) }
                            .build()
                    crypto = NullCryptoProvider
                    loops = 2
                    log?.let { logger = it }
                }.build()
        val preferred = if (owner == 0) listOf(listOf<DatagramIo>(real), listOf(twin)) else listOf(listOf(twin), listOf(real))
        return LoopGroup.create(withPreferred, listOf(net.open(serverAddr), net.open(otherAddr)), preferred = preferred)
    }

    @Test fun preferredFailureOnOneLoopTakesThePreferredAddressDownGroupWide() =
        runBlocking {
            withTimeout(30.seconds) {
                // the connection is loop 0's; its client's probe toward the preferred address is held back. Loop 0's preferred socket fails:
                // the whole group stops serving the address, so loop 1's preferred socket (where the kernel hashes the probes) no longer
                // forwards them for loop 0 to answer from its main socket (a validation the client could never use, RFC 9000 section 9.6.1).
                // The probe fails and the connection stays on the original address
                val net = MemoryNetwork()
                val pref = InetSocketAddress("10.0.0.4", 4433)
                val real = net.open(pref)
                val twin = SharedPortTwin(real)
                val log = CapturingLogger()
                val group = groupWithPreferred(net, pref, real, twin, owner = 1, log = log)

                val released = kotlinx.coroutines.CompletableDeferred<Unit>()
                val probed = kotlinx.coroutines.CompletableDeferred<Unit>()
                net.lose = { _, to, _ ->
                    val held = !released.isCompleted && to == pref
                    if (held) probed.complete(Unit)
                    held
                }
                val client = QuicEndpoint.bind(clientAddr, client(net.open(clientAddr)))
                try {
                    val accepted = async { group.accept() }
                    val c = client.connect(serverAddr, clientConfig) // loop 0's socket: the connection is loop 0's
                    val events =
                        kotlinx.coroutines.channels.Channel<io.kuicksilver.quic.PathEvent>(
                            kotlinx.coroutines.channels.Channel.UNLIMITED,
                        )
                    val collector =
                        launch(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { c.pathEvents.collect { events.send(it) } }
                    val s = accepted.await()
                    probed.await() // the client probes the preferred address; held back
                    twin.failWith(io.kuicksilver.quic.SocketDefunctException("gone", 9))
                    while (group.stats.preferredAddressFailures < 1 || !real.closed) delay(5)
                    assertEquals(1L, group.stats.preferredAddressFailures, "one failure for the group")
                    log.assertLogged(LogLevel.Warn, "the preferred-address socket", "no longer offering the preferred address")
                    released.complete(Unit)
                    val failed =
                        withTimeout(20.seconds) {
                            var e: io.kuicksilver.quic.PathEvent
                            do e = events.receive() while (e !is io.kuicksilver.quic.PathEvent.Failed)
                            e
                        }
                    assertEquals(pref, failed.path.remoteAddress, "the preferred probe failed, not the original path")
                    val st = c.openBidi()
                    st.output.writeFully(ByteArray(20_000) { 7 })
                    st.output.flushAndClose()
                    val got =
                        s
                            .acceptStream()
                            .input
                            .readBuffer()
                            .readByteArray()
                    assertEquals(20_000, got.size, "data over the original path")
                    assertEquals(serverAddr, (c as ConnectionRuntime).core.path.remote, "still on the original address")
                    collector.cancel()
                    c.close()
                } finally {
                    client.close()
                    group.close()
                }
            }
        }

    @Test fun preferredFailureOnOneLoopClosesConnectionsMovedThereOnTheOtherLoop() =
        runBlocking {
            withTimeout(30.seconds) {
                // the connection is loop 1's and moved to the preferred address, which the kernel hashes onto loop 0's socket; that
                // socket fails: the group-wide degrade closes the moved connection on the healthy loop 1 as well
                val net = MemoryNetwork()
                val pref = InetSocketAddress("10.0.0.4", 4433)
                val real = net.open(pref)
                val twin = SharedPortTwin(real)
                val log = CapturingLogger()
                val group = groupWithPreferred(net, pref, real, twin, owner = 0, log = log)
                val client = QuicEndpoint.bind(clientAddr, client(net.open(clientAddr)))
                try {
                    val accepted = async { group.accept() }
                    val c = client.connect(otherAddr, clientConfig) // loop 1's socket: the connection is loop 1's
                    val s = accepted.await()
                    val loop1 = group.loopForTest(1).core
                    while (loop1
                            .connections()
                            .single()
                            .path.socket != io.kuicksilver.quic.PREFERRED_SOCKET
                    ) {
                        delay(5)
                    }
                    real.failWith(io.kuicksilver.quic.SocketDefunctException("gone", 9))
                    withTimeout(10.seconds) { s.closed.await() }
                    assertEquals(1L, group.stats.preferredAddressFailures)
                    log.assertLogged(LogLevel.Warn, "the preferred-address socket", "no longer offering the preferred address")
                    c.close()
                } finally {
                    client.close()
                    group.close()
                }
            }
        }

    @Test fun movedConnectionOnAnotherLoopsPreferredSocketIsForwardedAsPreferred() =
        runBlocking {
            withTimeout(30.seconds) {
                // the connection lives on loop 1; its client moves to the preferred address, which the kernel hashes onto loop 0's
                // preferred socket: loop 0 forwards the datagrams with their socket kind, loop 1 handles them as the preferred path
                val net = MemoryNetwork()
                val pref = InetSocketAddress("10.0.0.4", 4433)
                val pref0 = net.open(pref)
                val withPreferred =
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            server =
                                QuicServerConfig
                                    .Builder(CoreFixtures.server())
                                    .apply { preferredAddress = io.kuicksilver.quic.PreferredAddress(pref, null) }
                                    .build()
                            crypto = NullCryptoProvider
                            loops = 2
                        }.build()
                val group =
                    LoopGroup.create(
                        withPreferred,
                        listOf(net.open(serverAddr), net.open(otherAddr)),
                        preferred = listOf(listOf(pref0), listOf(SharedPortTwin(pref0))),
                    )
                val client = QuicEndpoint.bind(clientAddr, client(net.open(clientAddr)))
                try {
                    val accepted = async { group.accept() }
                    val c = client.connect(otherAddr, clientConfig) // loop 1's socket: the connection is loop 1's
                    val s = accepted.await()
                    while (c.paths.singleOrNull()?.let {
                            it.remoteAddress == pref &&
                                it.state.value == io.kuicksilver.quic.PathState.Validated
                        } !=
                        true
                    ) {
                        kotlinx.coroutines.yield()
                    }
                    val st = c.openBidi()
                    st.output.writeFully(ByteArray(20_000) { 7 })
                    st.output.flushAndClose()
                    val got =
                        s
                            .acceptStream()
                            .input
                            .readBuffer()
                            .readByteArray()
                    assertEquals(20_000, got.size, "data over the forwarded preferred path")
                    assertTrue(group.forwardedForTest(1) > 0, "loop 0 forwarded the preferred-socket datagrams to loop 1")
                    assertEquals(1, group.connectionsPerLoopForTest()[1])
                    assertEquals(
                        io.kuicksilver.quic.PREFERRED_SOCKET,
                        group
                            .loopForTest(1)
                            .core
                            .connections()
                            .single()
                            .path.socket,
                        "handled as the preferred path",
                    )
                    c.close()
                } finally {
                    client.close()
                    group.close()
                }
            }
        }

    @Test fun forwardedPreferredDatagramIsDroppedOnceThePreferredAddressIsDown() =
        runBlocking {
            withTimeout(30.seconds) {
                // a datagram another loop forwarded from its preferred socket before the address went down: no preferred socket is left
                // to answer from, and the main one must not (the client would validate a path it can never use); dropped and counted
                val net = MemoryNetwork()
                val group = LoopGroup.create(config, listOf(net.open(serverAddr), net.open(otherAddr)))
                try {
                    val loop = group.loopForTest(0)
                    loop.forwarded.trySend(
                        EndpointLoop.Forwarded(
                            ByteArray(30) { 0x40 },
                            clientAddr,
                            io.kuicksilver.quic.Ecn.NotEct,
                            asReceived = false,
                            socket = io.kuicksilver.quic.PREFERRED_SOCKET,
                        ),
                    )
                    withTimeout(10.seconds) { while (loop.forwardedCount.load() < 1) delay(10) }
                    val dropped = kotlinx.coroutines.withContext(loop.dispatcher) { loop.core.droppedPreferredDown }
                    assertEquals(1L, dropped)
                } finally {
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

    /** A datagram for another loop whose queue does not take it (full, or closed under a closing loop) counts as a queue drop. */
    @Test fun aForwardedDatagramTheOwnerCannotTakeCountsAsAQueueDrop() =
        runBlocking {
            withTimeout(30.seconds) {
                val net = MemoryNetwork()
                val io1 = net.open(otherAddr)
                val group = LoopGroup.create(config, listOf(net.open(serverAddr), io1))
                try {
                    group.loopForTest(0).forwarded.close()
                    group.misrouteForTest(from = 1, to = 0) // every datagram of loop 1's socket goes to loop 0's queue
                    repeat(10) { io1.inbox.trySend(ByteArray(100) { 0x40 } to clientAddr) }
                    withTimeout(5.seconds) { while (group.stats.datagramsDroppedQueue < 10L) delay(10) }
                    assertEquals(10L, group.stats.datagramsDroppedQueue, "${group.stats}")
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
                val log = CapturingLogger()
                val group = LoopGroup.create(configWith(log), listOf(io0, io1))
                try {
                    io1.fail = true
                    io1.inner.inbox.trySend(ByteArray(10) to clientAddr) // loop 1's socket dies
                    assertFailsWith<QuicException.EndpointClosing> { withTimeout(5.seconds) { group.accept() } }
                    repeat(2) {
                        assertFailsWith<QuicException.EndpointClosing>("connect $it (round-robin over both loops)") {
                            withTimeout(2.seconds) { group.connect(clientAddr, clientConfig) }
                        }
                    }
                    log.assertLogged(LogLevel.Error, "loop 1: transport failed; closing the endpoint", "recvmsg: EBADF")
                } finally {
                    group.close()
                }
            }
        }

    /** Holds a loop's first datagrams until [held] have arrived, then hands them over in one receive round: every Initial is admitted before any handshake completes. */
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

    /**
     * [perLoop] clients on each of the group's two sockets handshake at once while nobody calls accept() (as a busy
     * application's accept loop lags behind a burst): returns the clients' outcomes (a connection still open, or the
     * error that closed it) and the group-wide count of connections waiting for accept().
     */
    private suspend fun burst(
        acceptQueue: Int,
        perLoop: Int,
        afterBurst: suspend (LoopGroup, MemoryNetwork) -> Unit = { _, _ -> },
    ): Pair<List<Any?>, Int> =
        kotlinx.coroutines.coroutineScope {
            val net = MemoryNetwork()
            val cfg =
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                        crypto = NullCryptoProvider
                        loops = 2
                        this.acceptQueue = acceptQueue
                    }.build()
            val group = LoopGroup.create(cfg, listOf(HoldIo(net.open(serverAddr), perLoop), HoldIo(net.open(otherAddr), perLoop)))
            val clients =
                (1..2 * perLoop).map { i ->
                    val io = net.open(InetSocketAddress("10.0.1.$i", 1000 + i))
                    QuicEndpoint.bind(io.localAddress, client(io))
                }
            try {
                val outcomes =
                    clients
                        .mapIndexed { i, ep ->
                            async {
                                try {
                                    val c = ep.connect(if (i % 2 == 0) serverAddr else otherAddr, clientConfig)
                                    withTimeoutOrNull(3.seconds) { c.closed.await() }
                                } catch (e: QuicException.ConnectionLost) {
                                    e
                                }
                            }
                        }.awaitAll()
                val waiting = group.loopForTest(0).pendingAcceptForTest
                afterBurst(group, net)
                outcomes to waiting
            } finally {
                clients.forEach { it.close() }
                group.close()
            }
        }

    @Test fun burstAboveTheSharedAcceptQueueIsRefusedGroupWide() =
        runBlocking {
            withTimeout(30.seconds) {
                // run 38297127699 (MultiLoopTest.fourLoopsShareOnePort): 100 concurrent clients against the default acceptQueue
                // of 32 got CONNECTION_REFUSED "accept queue full"; the bound is the group's, not each loop's. When one loop's
                // handshakes fill the queue before the other loop admits its held Initials, those clients are refused at the
                // Initial (once a silent drop that left them to the 10 s handshake timeout); otherwise at completion: either
                // way every excess client learns CONNECTION_REFUSED promptly
                val (outcomes, waiting) = burst(acceptQueue = 4, perLoop = 4)
                val refused = outcomes.filterIsInstance<QuicException.ConnectionLost.TransportClosed>()
                assertEquals(4, waiting, "connections waiting for accept() across both loops")
                assertEquals(4, refused.size, "outcomes: $outcomes")
                assertTrue(refused.all { it.code == TransportError.CONNECTION_REFUSED }, "refusals: $refused")
            }
        }

    @Test fun initialWhileTheSharedAcceptQueueIsFullIsRefusedStatelessly() =
        runBlocking {
            withTimeout(30.seconds) {
                // the group's queue is full (one connection waits on each loop): a new client of loop 1 is refused at its
                // first Initial with CONNECTION_REFUSED, before any connection state or TLS handshake, and its connect fails
                // within a round trip rather than at the handshake timeout
                var lost: Any? = null
                var created = -1L
                var refusals = -1L
                var overflows = -1L
                val (outcomes, waiting) =
                    burst(acceptQueue = 2, perLoop = 1) { g, net ->
                        val before =
                            g
                                .loopForTest(1)
                                .core.stats.connectionsCreated
                        val io = net.open(InetSocketAddress("10.0.2.1", 2001))
                        val ep = QuicEndpoint.bind(io.localAddress, client(io))
                        try {
                            lost =
                                try {
                                    withTimeout(2.seconds) { ep.connect(otherAddr, clientConfig) }
                                } catch (e: QuicException.ConnectionLost) {
                                    e
                                }
                        } finally {
                            ep.close()
                        }
                        created = g
                            .loopForTest(1)
                            .core.stats.connectionsCreated - before
                        refusals = g.loopForTest(0).core.acceptQueueRefusals + g.loopForTest(1).core.acceptQueueRefusals
                        overflows = g.loopForTest(0).acceptOverflows + g.loopForTest(1).acceptOverflows
                    }
                assertEquals(2, waiting)
                assertTrue(outcomes.none { it is QuicException }, "outcomes: $outcomes")
                val refused = assertIs<QuicException.ConnectionLost.TransportClosed>(lost, "connect: $lost")
                assertEquals(TransportError.CONNECTION_REFUSED, refused.code)
                assertEquals(0L, created, "no connection state for the refused client")
                assertEquals(1L, refusals)
                assertEquals(0L, overflows, "refused at the Initial, not at handshake completion")
            }
        }

    @Test fun burstWithinTheSharedAcceptQueueIsAcceptedWhole() =
        runBlocking {
            withTimeout(30.seconds) {
                // the same burst with acceptQueue covering it (what MultiLoopTest needs): nothing is refused, every
                // connection reaches accept() and each accept() returns its slot
                var after = -1
                val (outcomes, waiting) =
                    burst(acceptQueue = 8, perLoop = 4) { g, _ ->
                        repeat(8) { withTimeout(5.seconds) { g.accept() } }
                        after = g.loopForTest(0).pendingAcceptForTest
                    }
                assertEquals(8, waiting)
                assertTrue(outcomes.none { it is QuicException }, "outcomes: $outcomes")
                assertEquals(0, after, "every accept() released its slot")
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

    /**
     * QUIC-LB IDs name no loop in clear: the owner is the loop they hash to. A live connection's datagrams that the kernel
     * hands to another loop (every datagram of loop 0's socket goes to loop 1 first) still reach the connection on loop 0.
     */
    @Test fun quicLbForwardedToOwner() =
        runBlocking {
            withTimeout(30.seconds) {
                val net = MemoryNetwork()
                // 9-byte IDs: the client's 8-byte Initial DCID is never taken for one of ours, so the connection stays where its
                // Initial lands (loop 0, whose address the client dialled), whatever the client's random bytes
                val lbConfig =
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            server =
                                QuicServerConfig
                                    .Builder(CoreFixtures.server())
                                    .apply { quic = quicConfig { connectionIdLength = 9 } }
                                    .build()
                            connectionIdLength = 9
                            crypto = LbNullCrypto
                            loops = 4
                            loadBalancer = QuicLbConfig(2, byteArrayOf(1, 2, 3, 4), 4, QuicLbFixtures.key())
                        }.build()
                val ios = List(4) { net.open(if (it == 0) serverAddr else InetSocketAddress("10.0.0.${10 + it}", 2222)) }
                val group = LoopGroup.create(lbConfig, ios)
                val client = QuicEndpoint.bind(clientAddr, client(net.open(clientAddr)))
                try {
                    val accepted = async { group.accept() }
                    val c = client.connect(serverAddr, clientConfig) // loop 0's socket: the connection is loop 0's
                    val s = accepted.await()
                    group.misrouteForTest(from = 0, to = 1)
                    val st = c.openBidi()
                    st.output.writeFully(ByteArray(20_000) { 7 })
                    st.output.flushAndClose()
                    val got =
                        s
                            .acceptStream()
                            .input
                            .readBuffer()
                            .readByteArray()
                    assertEquals(20_000, got.size, "every datagram reached the owner")
                    assertTrue(group.forwardedForTest(0) > 0, "loop 1 forwarded them to loop 0")
                    assertEquals(0L, group.stats.statelessResets, "no loop answered a stranger's ID")
                    c.close()
                } finally {
                    client.close()
                    group.close()
                }
            }
        }

    private fun lbEndpointConfig(net: MemoryNetwork) =
        QuicEndpointConfig
            .Builder()
            .apply {
                server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                crypto = LbNullCrypto
                loadBalancer = QuicLbFixtures.config(configId = 1)
                io = { net.open(serverAddr) }
            }.build()

    /** A caller cancelled right after its configuration was committed does not undo it: the endpoint still issues routable IDs. */
    @Test fun quicLbCancelledUpdateKeepsTheCommittedConfiguration() =
        runBlocking {
            withTimeout(30.seconds) {
                val ep = QuicEndpoint.bind(serverAddr, lbEndpointConfig(MemoryNetwork())) as EndpointLoop
                try {
                    val caller = kotlinx.coroutines.CompletableDeferred<kotlinx.coroutines.Job>()
                    ep.afterLbCommitForTest = { caller.getCompleted().cancel() }
                    val job = launch { ep.updateLoadBalancer(QuicLbFixtures.config(configId = 3)) }
                    caller.complete(job)
                    job.join()
                    assertTrue(job.isCancelled)
                    ep.afterLbCommitForTest = null
                    val cid = ep.runOnLoop { ep.core.route.newCid(kotlin.random.Random(1), client = false) }
                    assertEquals(3, (cid[0].toInt() and 0xff) ushr 5, "the committed configuration is in force")
                } finally {
                    ep.closeAndJoin()
                }
            }
        }

    /** Concurrent changes on one endpoint are serialised: whatever wins, the configuration in force is a live one. */
    @Test fun quicLbConcurrentUpdatesNeverInstallARetiredConfiguration() =
        runBlocking {
            withTimeout(30.seconds) {
                val ep = QuicEndpoint.bind(serverAddr, lbEndpointConfig(MemoryNetwork())) as EndpointLoop
                try {
                    val configs = List(4) { QuicLbFixtures.config(configId = it + 2) }
                    repeat(10) { round ->
                        (0 until 4)
                            .map { i -> async(Dispatchers.Default) { ep.updateLoadBalancer(configs[(i + round) % 4]) } }
                            .awaitAll()
                        val cid = ep.runOnLoop { ep.core.route.newCid(kotlin.random.Random(round), client = false) }
                        val cr = (cid[0].toInt() and 0xff) ushr 5
                        assertTrue(cr in 2..5, "round $round: a routable ID of one of the configurations, not $cr")
                        assertTrue(
                            ep.core.lb!!
                                .routes.current
                                ?.retired == false,
                        )
                    }
                } finally {
                    ep.closeAndJoin()
                }
            }
        }

    private class FlakyReservation : io.kuicksilver.quic.QuicLbNonceReservation {
        @Volatile var mark = 0L

        @Volatile var fail = false

        override fun load(): Long = mark

        override fun store(mark: Long) {
            if (fail) throw IOException("disk full")
            this.mark = mark
        }

        override fun secret(): ByteArray = ByteArray(16)
    }

    /** Two loops, 9-byte QUIC-LB IDs (an 8-byte client DCID is never one of ours: a connection stays where its Initial lands). */
    private suspend fun lbGroup(
        net: MemoryNetwork,
        lb: QuicLbConfig,
    ): LoopGroup =
        LoopGroup.create(
            QuicEndpointConfig
                .Builder()
                .apply {
                    server =
                        QuicServerConfig
                            .Builder(CoreFixtures.server())
                            .apply { quic = quicConfig { connectionIdLength = 9 } }
                            .build()
                    connectionIdLength = 9
                    crypto = LbNullCrypto
                    loops = 2
                    loadBalancer = lb
                }.build(),
            listOf(net.open(serverAddr), net.open(otherAddr)),
        )

    private suspend fun serverConnectionOf(loop: EndpointLoop): io.kuicksilver.quic.ConnectionCore =
        loop.runOnLoop { loop.core.connections().single { it.role == io.kuicksilver.tls.TlsRole.Server } }

    /** A group caller cancelled right after loop 0 committed still moves the other loops' connections to the new configuration. */
    @Test fun quicLbCancelledGroupUpdateStillMovesEveryLoop() =
        runBlocking {
            withTimeout(30.seconds) {
                val net = MemoryNetwork()
                val group = lbGroup(net, QuicLbConfig(2, byteArrayOf(1, 2, 3, 4), 4, QuicLbFixtures.key()))
                val client = QuicEndpoint.bind(clientAddr, client(net.open(clientAddr)))
                try {
                    val accepted = async { group.accept() }
                    val c = client.connect(otherAddr, clientConfig) // loop 1's socket: the connection is loop 1's
                    accepted.await()
                    val loop0 = group.loopForTest(0)
                    val caller = kotlinx.coroutines.CompletableDeferred<kotlinx.coroutines.Job>()
                    loop0.afterLbCommitForTest = { caller.getCompleted().cancel() }
                    val job = launch { group.updateLoadBalancer(QuicLbConfig(3, byteArrayOf(1, 2, 3, 4), 4, QuicLbFixtures.key())) }
                    caller.complete(job)
                    job.join()
                    group.fanOutForTest?.join()
                    assertTrue(job.isCancelled)
                    loop0.afterLbCommitForTest = null
                    val s = serverConnectionOf(group.loopForTest(1))
                    val moved = group.loopForTest(1).runOnLoop { (0L..10L).mapNotNull { s.cids.localForTest(it)?.cid } }
                    assertTrue(moved.any { (it[0].toInt() and 0xff) ushr 5 == 3 }, "loop 1's connection got an ID of the new configuration")
                    c.close()
                } finally {
                    client.close()
                    group.close()
                }
            }
        }

    /**
     * After a failed reservation store, a group whose loop 0 gets no traffic still retries it (every loop ticks): the
     * change waiting on loop 1 goes out once the store works again.
     */
    @Test fun quicLbStoreRetriedWithoutTrafficOnLoopZero() =
        runBlocking {
            withTimeout(30.seconds) {
                val net = MemoryNetwork()
                val reservation = FlakyReservation()
                val key = QuicLbFixtures.key("0f0e0d0c0b0a0908070605040302010c")
                val group = lbGroup(net, QuicLbConfig(2, byteArrayOf(1, 2, 3, 4), 4, key, reservation))
                val client = QuicEndpoint.bind(clientAddr, client(net.open(clientAddr)))
                try {
                    val accepted = async { group.accept() }
                    val c = client.connect(otherAddr, clientConfig)
                    val sc = accepted.await()
                    val loop1 = group.loopForTest(1)
                    reservation.fail = true
                    loop1.core.lb!!
                        .routes.current!!
                        .space
                        .useUpReservationForTest()
                    group.updateLoadBalancer(QuicLbConfig(3, byteArrayOf(1, 2, 3, 4), 4, key, reservation))
                    group.fanOutForTest?.join()
                    reservation.fail = false // right away: the back-off stays at its first step
                    val s = serverConnectionOf(loop1)
                    val reissued = kotlinx.coroutines.CompletableDeferred<Unit>()
                    val pending =
                        loop1.runOnLoop {
                            s.cids.reissuedForTest = { reissued.complete(Unit) }
                            s.cids.reissuePendingForTest
                        }
                    assertTrue(pending, "the change waits for a nonce")
                    val st = c.openBidi()
                    val input = sc.acceptStreamAfter(st)
                    var rounds = 0
                    while (!reissued.isCompleted) {
                        // one round trip to loop 1 only: its receive batches tick the reservation
                        st.output.writeFully(ByteArray(100) { 1 })
                        st.output.flush()
                        input.readFully(ByteArray(100))
                        rounds++
                    }
                    assertTrue(rounds < 100, "$rounds round trips")
                    assertEquals(0L, group.loopForTest(0).stats.datagramsReceived, "loop 0 saw no traffic")
                    c.close()
                } finally {
                    client.close()
                    group.close()
                }
            }
        }

    /**
     * Section 3.1: a loop that misses the group's fan-out (blocked past its timeout) moves its connections at its next
     * receive batch, by the configuration's generation.
     */
    @Test fun quicLbLoopMissingTheFanOutMovesAtItsNextBatch() =
        runBlocking {
            withTimeout(30.seconds) {
                val net = MemoryNetwork()
                val group = lbGroup(net, QuicLbConfig(2, byteArrayOf(1, 2, 3, 4), 4, QuicLbFixtures.key()))
                val client = QuicEndpoint.bind(clientAddr, client(net.open(clientAddr)))
                val release = kotlinx.coroutines.CompletableDeferred<Unit>()
                try {
                    val accepted = async { group.accept() }
                    val c = client.connect(otherAddr, clientConfig) // loop 1's connection
                    val sc = accepted.await()
                    val st = c.openBidi()
                    val input = sc.acceptStreamAfter(st)
                    val loop1 = group.loopForTest(1)
                    val s = serverConnectionOf(loop1)
                    val moved = kotlinx.coroutines.CompletableDeferred<Unit>()
                    val reissues = kotlin.concurrent.atomics.AtomicInt(0)
                    loop1.runOnLoop {
                        s.cids.reissuedForTest = {
                            reissues.incrementAndFetch()
                            moved.complete(Unit)
                        }
                    }
                    group.fanOutTimeout = kotlin.time.Duration.parse("50ms")
                    val blocked = kotlinx.coroutines.CompletableDeferred<Unit>()
                    // loop 1's thread busy past the fan-out's timeout
                    loop1.scope.launch {
                        blocked.complete(Unit)
                        while (!release.isCompleted) { /* busy */ }
                    }
                    blocked.await()
                    // returns while loop 1 is stuck: the fan-out runs in the group's scope, not in the caller
                    group.updateLoadBalancer(QuicLbConfig(3, byteArrayOf(1, 2, 3, 4), 4, QuicLbFixtures.key()))
                    // the fan-out gives loop 1 up after its timeout, though loop 1 is still stuck (it waits off the loop)
                    assertNotNull(group.fanOutForTest).join()
                    assertTrue(!moved.isCompleted, "loop 1 has not moved yet")
                    release.complete(Unit)
                    var rounds = 0
                    while (!moved.isCompleted) {
                        // round trips to loop 1: its next receive batch sees the new generation
                        st.output.writeFully(ByteArray(100) { 1 })
                        st.output.flush()
                        input.readFully(ByteArray(100))
                        rounds++
                    }
                    val ids = loop1.runOnLoop { (0L..10L).mapNotNull { s.cids.localForTest(it)?.cid } }
                    assertTrue(ids.any { (it[0].toInt() and 0xff) ushr 5 == 3 }, "loop 1's connection got an ID of the new configuration")
                    assertTrue(rounds <= 3, "at its next batch: $rounds round trips")
                    assertEquals(1, reissues.load(), "moved once: the generation keeps the fan-out and the batch from both moving it")
                    c.close()
                } finally {
                    release.complete(Unit) // a failed assertion must not leave loop 1 spinning, or close would hang
                    client.close()
                    group.close()
                }
            }
        }

    /** The server side of [st]: its first bytes make the stream known to the server. */
    private suspend fun QuicConnection.acceptStreamAfter(st: io.kuicksilver.quic.QuicStream): io.ktor.utils.io.ByteReadChannel {
        st.output.writeFully(ByteArray(1))
        st.output.flush()
        val input = acceptStream().input
        input.readFully(ByteArray(1))
        return input
    }
}
