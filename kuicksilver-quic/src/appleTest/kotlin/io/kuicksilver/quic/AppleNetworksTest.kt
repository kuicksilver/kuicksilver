// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, ExperimentalForeignApi::class, ExperimentalAtomicApi::class)

package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.api.readExactly
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import platform.posix.AF_INET
import platform.posix.EBADF
import platform.posix.ENOTCONN
import platform.posix.SOCK_STREAM
import platform.posix.close
import platform.posix.dup2
import platform.posix.if_nametoindex
import platform.posix.socket
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** iOS and macOS network following: NWPathMonitor, sockets bound to an interface, migration over them, and a socket the system takes away. */
class AppleNetworksTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val lo0 = if_nametoindex("lo0").toInt()

    @Test fun pathUpdatesShareOneMonitorPerProcess() =
        runBlocking<Unit> {
            withTimeout(30.seconds) {
                val before = pathMonitorsStarted.load()
                val first = List(2) { CompletableDeferred<NwPathKey?>() }
                val collectors = List(2) { i -> launch { nwPathUpdates().collect { first[i].complete(it) } } }
                // the monitor reports the current path at once (null only on a machine without any network)
                first.forEach { it.await() }
                assertEquals(before + 1, pathMonitorsStarted.load(), "two collectors, one monitor")
                assertEquals(first[0].await(), first[1].await())
                collectors.forEach { it.cancelAndJoin() }
                // the last collector left: the monitor was cancelled, the next collector starts a new one
                nwPathUpdates().first()
                assertEquals(before + 2, pathMonitorsStarted.load())
            }
        }

    @Test fun openBindsTheSocketToTheInterface() =
        runBlocking<Unit> {
            // a wildcard address is a dual-stack IPv6 socket: bound with IPV6_BOUND_IF
            for ((host, v6) in listOf("127.0.0.1" to false, "::1" to true, "0.0.0.0" to true)) {
                val io = DatagramIo.open(InetSocketAddress(host, 0), lo0)
                try {
                    assertEquals(lo0, boundInterfaceOf(assertIs<KslDatagramIo>(io).fdForTest, v6), host)
                } finally {
                    io.close()
                }
            }
        }

    @Test fun negative_anIndexThatNamesNoInterfaceIsRefused() =
        runBlocking<Unit> {
            kotlin.test.assertFailsWith<kotlinx.io.IOException> { DatagramIo.open(InetSocketAddress("127.0.0.1", 0), 999_999) }
        }

    private class Loopback(
        val server: QuicEndpoint,
        val client: QuicEndpoint,
        val clientIo: KslDatagramIo,
    ) {
        suspend fun connect(): Pair<QuicConnection, QuicConnection> =
            coroutineScope {
                val accepted = async { server.accept() }
                client.connect(server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build()) to accepted.await()
            }

        fun close() {
            client.close()
            server.close()
        }

        companion object {
            suspend fun open(): Loopback {
                val lo = InetSocketAddress("127.0.0.1", 0)
                val server =
                    QuicEndpoint.bind(
                        lo,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                this.server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                                crypto = KslQuicCrypto
                            }.build(),
                    )
                val io = assertIs<KslDatagramIo>(DatagramIo.open(lo))
                val client =
                    QuicEndpoint.bind(
                        io.localAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                crypto = KslQuicCrypto
                                this.io = { io }
                            }.build(),
                    )
                return Loopback(server, client, io)
            }
        }
    }

    private suspend fun ping(
        c: QuicConnection,
        s: QuicConnection,
    ) = coroutineScope {
        val server =
            launch {
                val st = s.acceptStream()
                val got = st.input.readExactly(4)
                st.output.writeFully(got, 0, 4)
                st.output.flushAndClose()
            }
        val st = c.openBidi()
        st.output.writeFully(byteArrayOf(1, 2, 3, 4), 0, 4)
        st.output.flushAndClose()
        assertTrue(st.input.readExactly(4).contentEquals(byteArrayOf(1, 2, 3, 4)))
        server.join()
    }

    private fun CoroutineScope.pathEventsOf(c: QuicConnection): Pair<Channel<PathEvent>, Job> {
        val ch = Channel<PathEvent>(Channel.UNLIMITED)
        val job = launch(start = CoroutineStart.UNDISPATCHED) { c.pathEvents.collect { ch.send(it) } }
        return ch to job
    }

    /** The iOS/macOS sample of docs/guide/quic.md: following the default network starts at once and stops on close. */
    @Test fun followDefaultNetworkSample() =
        runBlocking<Unit> {
            val l = Loopback.open()
            try {
                withTimeout(60.seconds) {
                    val (connection, _) = l.connect()
                    val scope = this
                    // guide:quic:apple-follow
                    val migrator = connection.followDefaultNetwork(scope) // started; migrator.close() stops it
                    val log = scope.launch { migrator.events.collect { println("quic: $it") } }
                    migrator.close()
                    log.cancel()
                    connection.close()
                }
            } finally {
                l.close()
            }
        }

    @Test fun followingMovesTheConnectionToASocketBoundToTheNewInterface() =
        runBlocking<Unit> {
            val l = Loopback.open()
            try {
                withTimeout(60.seconds) {
                    val (c, s) = l.connect()
                    ping(c, s)
                    val keys = MutableStateFlow<NwPathKey?>(NwPathKey(lo0, NwInterfaceType.Loopback, "lo0"))
                    val m = c.followNetworks(keys, this, null, IoPreference.Accelerated)
                    val events = Channel<MigrationEvent<NwPathKey>>(Channel.UNLIMITED)
                    val collector = launch(start = CoroutineStart.UNDISPATCHED) { m.events.collect { events.send(it) } }
                    m.network.first { it != null }
                    io.kuicksilver.quic.api
                        .awaitSpareConnectionId(c)
                    // another network (a different key) on the same interface: a new socket bound to lo0
                    keys.value = NwPathKey(lo0, NwInterfaceType.Other, "lo0")
                    val e = assertIs<MigrationEvent.Migrated<NwPathKey>>(events.receive())
                    assertEquals(NwInterfaceType.Other, e.new.interfaceType)
                    assertNotEquals(l.clientIo.localAddress.port, c.activePath!!.localAddress.port)
                    ping(c, s)
                    m.close()
                    collector.cancel()
                    c.close()
                }
            } finally {
                l.close()
            }
        }

    @Test fun aSocketTheSystemTakesAwayIsALostPathAndRebindRecovers() =
        runBlocking<Unit> {
            val l = Loopback.open()
            try {
                withTimeout(60.seconds) {
                    val (c, s) = l.connect()
                    ping(c, s)
                    io.kuicksilver.quic.api
                        .awaitSpareConnectionId(c) // a move needs an unused ID of the server
                    val (events, collector) = pathEventsOf(c)
                    // fault injection: the descriptor now names an unconnected TCP socket, so sendmsg and recvmsg fail with
                    // ENOTCONN, what iOS reports for the socket of an app it suspended
                    val tcp = socket(AF_INET, SOCK_STREAM, 0)
                    check(tcp >= 0 && dup2(tcp, l.clientIo.fdForTest) >= 0)
                    close(tcp)
                    // something to send: the first write after the swap hits the dead socket
                    val trigger =
                        launch {
                            val st = c.openBidi()
                            st.output.writeFully(byteArrayOf(9), 0, 1)
                            st.output.flushAndClose()
                        }
                    var lost: PathEvent.SocketLost? = null
                    while (lost == null) lost = events.receive() as? PathEvent.SocketLost
                    assertEquals(PathId.Initial, lost.path.id)
                    // ENOTCONN from the swapped-in socket, or EBADF when a receive on either path (on the loop's thread via
                    // BatchReceiver, or in a Dispatchers.IO slice) looks the descriptor up while dup2 is replacing it: Darwin
                    // answers EBADF in that window (2 of 15 runs with an earlier receive path, 0 of 15 with this one; both are
                    // a lost socket)
                    assertTrue(lost.cause.errno == ENOTCONN || lost.cause.errno == EBADF, "errno ${lost.cause.errno}")
                    assertFalse(c.closed.isCompleted)
                    val changed = c.rebind(InetSocketAddress("127.0.0.1", 0))
                    assertEquals(PathId.Initial, changed.old.id)
                    assertNotEquals(l.clientIo.localAddress.port, c.activePath!!.localAddress.port)
                    // what was written while the socket was dead arrives over the new one
                    assertTrue(
                        s
                            .acceptStream()
                            .input
                            .readExactly(1)
                            .contentEquals(byteArrayOf(9)),
                    )
                    trigger.join()
                    ping(c, s)
                    collector.cancel()
                    c.close()
                }
            } finally {
                l.close()
            }
        }
}
