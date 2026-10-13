// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.MemoryDatagramIo
import io.kuicksilver.quic.MigrationEvent
import io.kuicksilver.quic.NetworkMigrator
import io.kuicksilver.quic.PathFailureReason
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.PathValidationException
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.activePath
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.runtime.EndpointLoop
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** [NetworkMigrator] over the in-memory network: network `n` is the local address 10.0.n.1 (all platforms). */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class NetworkMigratorTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun addr(n: Int) = InetSocketAddress("10.0.$n.1", 5000 + n)

    /** The sockets a migrator opened, by network; networks in [deaf] never deliver (a dead network). */
    private class Opener(
        val p: ApiPair,
        val deaf: Set<Int> = emptySet(),
    ) {
        val opened = mutableListOf<Pair<Int, MemoryDatagramIo>>()
        val openedDeaf = CompletableDeferred<Unit>()

        fun open(n: Int): MemoryDatagramIo =
            p.net.open(InetSocketAddress("10.0.$n.1", 5000 + n), deaf = n in deaf).also {
                opened += n to it
                if (n in deaf) openedDeaf.complete(Unit)
            }
    }

    /** Every event of [m] from now on, in order. */
    private fun CoroutineScope.eventsOf(m: NetworkMigrator<Int>): Pair<Channel<MigrationEvent<Int>>, Job> {
        val ch = Channel<MigrationEvent<Int>>(Channel.UNLIMITED)
        val job = launch(start = CoroutineStart.UNDISPATCHED) { m.events.collect { ch.send(it) } }
        return ch to job
    }

    /** One small echo through [c]/[s]: the connection is alive on whatever path it is on. */
    private suspend fun ping(
        c: QuicConnection,
        s: QuicConnection,
    ) = kotlinx.coroutines.coroutineScope {
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

    private suspend fun waitClosed(io: MemoryDatagramIo) {
        withTimeout(10.seconds) { while (!io.closed) yield() }
    }

    @Test fun migratesWhenNetworkChangesAndClosesOldPath() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (c, s) = p.connect()
                    val nets = MutableStateFlow<Int?>(1)
                    val o = Opener(p)
                    val m = NetworkMigrator(c, nets, { o.open(it) }, this)
                    val (events, collector) = eventsOf(m)
                    val original = c.activePath!!
                    m.start()
                    m.network.first { it == 1 }
                    nets.value = 2
                    val e = assertIs<MigrationEvent.Migrated<Int>>(events.receive())
                    assertEquals(1, e.old)
                    assertEquals(2, e.new)
                    assertEquals(addr(2), e.path.localAddress)
                    assertEquals(addr(2), c.activePath!!.localAddress)
                    original.state.first { it == PathState.Closed }
                    // and again: the path of network 2 is the old one now, its socket is released
                    nets.value = 3
                    val e2 = assertIs<MigrationEvent.Migrated<Int>>(events.receive())
                    assertEquals(2 to 3, e2.old to e2.new)
                    e.path.state.first { it == PathState.Closed }
                    assertTrue(
                        o.opened
                            .single { it.first == 2 }
                            .second.closed,
                    )
                    assertEquals(listOf(addr(3)), c.paths.map { it.localAddress })
                    ping(c, s)
                    m.close()
                    collector.cancel()
                    c.close()
                }
            }
        }

    @Test fun ignoresSameNetworkRepeats() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (c, _) = p.connect()
                    val source = Channel<Int?>(Channel.UNLIMITED)
                    val o = Opener(p)
                    val m = NetworkMigrator(c, source.receiveAsFlow(), { o.open(it) }, this)
                    val (events, collector) = eventsOf(m)
                    m.start()
                    for (n in listOf(1, 1, 1, 2, 2)) source.send(n)
                    assertEquals(1 to 2, assertIs<MigrationEvent.Migrated<Int>>(events.receive()).let { it.old to it.new })
                    // lost and back on the same network: nothing to do; a repeat after that is still nothing
                    for (n in listOf(null, null, 2, 2, 3)) source.send(n)
                    assertIs<MigrationEvent.NetworkLost>(events.receive())
                    assertEquals(2 to 3, assertIs<MigrationEvent.Migrated<Int>>(events.receive()).let { it.old to it.new })
                    assertEquals(listOf(2, 3), o.opened.map { it.first }, "one socket per real change")
                    m.close()
                    collector.cancel()
                    c.close()
                }
            }
        }

    @Test fun negative_migrationFailureKeepsOldPath() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (c, s) = p.connect()
                    val nets = MutableStateFlow<Int?>(1)
                    val o = Opener(p, deaf = setOf(2))
                    val m = NetworkMigrator(c, nets, { o.open(it) }, this)
                    val (events, collector) = eventsOf(m)
                    val original = c.activePath!!
                    m.start()
                    m.network.first { it == 1 }
                    nets.value = 2
                    val f = assertIs<MigrationEvent.Failed<Int>>(events.receive())
                    assertEquals(2, f.network)
                    assertEquals(original.id, c.activePath!!.id, "the connection stays on the old path")
                    assertTrue(original.state.value != PathState.Closed, "the old path stays open")
                    assertFalse(c.closed.isCompleted, "no ConnectionLost")
                    waitClosed(o.opened.single().second)
                    ping(c, s)
                    m.close()
                    collector.cancel()
                    c.close()
                }
            }
        }

    @Test fun negative_disableActiveMigrationIsRespected() =
        runBlocking {
            // RFC 9000 section 18.2: a server that sent disable_active_migration is never migrated to
            ApiPair.open(serverQuic = quicConfig { allowMigration = false }).use { p ->
                withTimeout(60.seconds) {
                    val (c, s) = p.connect()
                    val nets = MutableStateFlow<Int?>(1)
                    val o = Opener(p)
                    val m = NetworkMigrator(c, nets, { o.open(it) }, this)
                    val (events, collector) = eventsOf(m)
                    val original = c.activePath!!
                    m.start()
                    m.network.first { it == 1 }
                    nets.value = 2
                    val f = assertIs<MigrationEvent.Failed<Int>>(events.receive())
                    assertTrue(f.cause.message!!.contains("disable_active_migration"), f.cause.message)
                    assertEquals(original.id, c.activePath!!.id)
                    assertTrue(o.opened.all { it.second.closed }, "no socket left open")
                    ping(c, s)
                    m.close()
                    collector.cancel()
                    c.close()
                }
            }
        }

    @Test fun rapidChangesKeepOnlyTheLatest() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (c, s) = p.connect()
                    val nets = MutableStateFlow<Int?>(1)
                    val o = Opener(p, deaf = setOf(2))
                    val m = NetworkMigrator(c, nets, { o.open(it) }, this)
                    val (events, collector) = eventsOf(m)
                    m.start()
                    m.network.first { it == 1 }
                    nets.value = 2 // a network whose validation never ends on its own before ...
                    o.openedDeaf.await()
                    nets.value = 3 // ... the next change supersedes it
                    val e = assertIs<MigrationEvent.Migrated<Int>>(events.receive(), "the superseded migration reports nothing")
                    assertEquals(1 to 3, e.old to e.new)
                    assertEquals(addr(3), c.activePath!!.localAddress)
                    waitClosed(o.opened.single { it.first == 2 }.second)
                    withTimeout(10.seconds) { while (c.paths.any { it.localAddress == addr(2) }) yield() } // the superseded path is gone
                    ping(c, s)
                    m.close()
                    collector.cancel()
                    c.close()
                }
            }
        }

    @Test fun closeReleasesEveryIo() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (c, _) = p.connect()
                    val nets = MutableStateFlow<Int?>(1)
                    val o = Opener(p, deaf = setOf(3))
                    var calls = 0
                    val m =
                        NetworkMigrator(c, nets, {
                            calls++
                            o.open(it)
                        }, this)
                    val (events, collector) = eventsOf(m)
                    val job = m.start()
                    m.network.first { it == 1 }
                    nets.value = 2
                    assertIs<MigrationEvent.Migrated<Int>>(events.receive())
                    nets.value = 3
                    o.openedDeaf.await()
                    m.close() // mid-validation
                    nets.value = 4 // before the job ended: a closed migrator must not start another migration
                    job.join()
                    assertEquals(2, calls, "no openIo after close()")
                    waitClosed(o.opened.single { it.first == 3 }.second)
                    assertFalse(
                        o.opened
                            .single { it.first == 2 }
                            .second.closed,
                        "the active path's socket belongs to the connection",
                    )
                    assertEquals(addr(2), c.activePath!!.localAddress)
                    collector.cancel()
                    c.close()
                }
            }
        }

    @Test fun supersededDuringOpenIoClosesTheSocket() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (c, s) = p.connect()
                    val nets = MutableStateFlow<Int?>(1)
                    val o = Opener(p)
                    val opening = CompletableDeferred<Unit>()
                    val gate = CompletableDeferred<Unit>()
                    // like DatagramIo.open on Android: the socket exists before openIo returns (withContext(Dispatchers.IO))
                    val m =
                        NetworkMigrator(c, nets, { n ->
                            val io = o.open(n)
                            if (n == 2) {
                                opening.complete(Unit)
                                gate.await()
                            }
                            io
                        }, this)
                    val (events, collector) = eventsOf(m)
                    m.start()
                    m.network.first { it == 1 }
                    nets.value = 2
                    opening.await()
                    nets.value = 3 // supersedes the migration while openIo runs
                    yield()
                    gate.complete(Unit)
                    val e = assertIs<MigrationEvent.Migrated<Int>>(events.receive())
                    assertEquals(1 to 3, e.old to e.new)
                    waitClosed(o.opened.single { it.first == 2 }.second)
                    assertEquals(listOf(2, 3), o.opened.map { it.first })
                    assertEquals(
                        listOf(addr(3)),
                        o.opened.filter { !it.second.closed }.map { it.second.localAddress },
                        "only the active socket is open",
                    )
                    ping(c, s)
                    m.close()
                    collector.cancel()
                    c.close()
                }
            }
        }

    @Test fun closeBeforeSwitchAbandonsTheMigration() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (c, s) = p.connect()
                    val nets = MutableStateFlow<Int?>(1)
                    val o = Opener(p)
                    val m = NetworkMigrator(c, nets, { o.open(it) }, this)
                    m.beforeSwitch = { m.close() } // close() lands between a successful probe and switchTo
                    val (events, collector) = eventsOf(m)
                    val original = c.activePath!!
                    val job = m.start()
                    m.network.first { it == 1 }
                    nets.value = 2
                    job.join()
                    assertEquals(original.id, c.activePath!!.id, "a closed migrator does not switch")
                    waitClosed(o.opened.single().second)
                    assertEquals(1, m.network.value)
                    assertTrue(events.tryReceive().isFailure, "nothing to report")
                    ping(c, s)
                    collector.cancel()
                    c.close()
                }
            }
        }

    @Test fun noFailedEventForAClosedConnection() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (c, _) = p.connect()
                    val nets = MutableStateFlow<Int?>(1)
                    val o = Opener(p, deaf = setOf(2))
                    val m = NetworkMigrator(c, nets, { o.open(it) }, this)
                    val (events, collector) = eventsOf(m)
                    val job = m.start()
                    m.network.first { it == 1 }
                    nets.value = 2
                    o.openedDeaf.await()
                    c.close() // mid-validation: the connection is gone, nothing failed
                    job.join()
                    yield()
                    assertTrue(events.tryReceive().isFailure, "no event for a dead connection")
                    waitClosed(o.opened.single().second)
                    collector.cancel()
                }
            }
        }

    @Test fun closesTheActualPreviousPathAfterAnOutsideSwitch() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (c, s) = p.connect()
                    val nets = MutableStateFlow<Int?>(1)
                    val o = Opener(p)
                    val m = NetworkMigrator(c, nets, { o.open(it) }, this)
                    val (events, collector) = eventsOf(m)
                    m.start()
                    m.network.first { it == 1 }
                    nets.value = 2
                    val e2 = assertIs<MigrationEvent.Migrated<Int>>(events.receive())
                    // the connection moves without the migrator (as a core fallback would): it is on path 9 now
                    val p9 = c.addPath(p.net.open(addr(9)))
                    assertTrue(p9.probe())
                    p9.switchTo()
                    nets.value = 3
                    val e3 = assertIs<MigrationEvent.Migrated<Int>>(events.receive())
                    assertEquals(2 to 3, e3.old to e3.new)
                    p9.state.first { it == PathState.Closed } // the path the connection really left
                    nets.value = 4
                    assertIs<MigrationEvent.Migrated<Int>>(events.receive())
                    e3.path.state.first { it == PathState.Closed }
                    assertEquals(addr(4), c.activePath!!.localAddress)
                    assertTrue(c.paths.size <= 2, "paths stay bounded: ${c.paths.map { it.localAddress }}")
                    ping(c, s)
                    m.close()
                    collector.cancel()
                    c.close()
                }
            }
        }

    @Test fun networkSourceFailureDoesNotCancelCallerScope() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (c, s) = p.connect()
                    val caller = CoroutineScope(coroutineContext + Job()) // the application's scope
                    // like registerDefaultNetworkCallback throwing TooManyRequestsException
                    val source =
                        flow<Int?> {
                            emit(1)
                            throw IllegalStateException("too many requests")
                        }
                    val m = NetworkMigrator(c, source, { error("no network change") }, caller)
                    val (events, collector) = eventsOf(m)
                    val job = m.start()
                    val e = assertIs<MigrationEvent.SourceFailed>(events.receive())
                    assertEquals("too many requests", e.cause.message)
                    job.join()
                    assertTrue(caller.isActive, "the caller's scope survives")
                    assertFalse(job.isCancelled, "the migrator ended normally")
                    ping(c, s)
                    caller.cancel()
                    collector.cancel()
                    c.close()
                }
            }
        }

    @Test fun negative_serverConnectionIsRejected() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (c, s) = p.connect()
                    // RFC 9000 section 9: only the client initiates migration
                    assertFailsWith<IllegalArgumentException> {
                        NetworkMigrator(
                            s,
                            MutableStateFlow<Int?>(1),
                            { p.net.open(addr(it)) },
                            this,
                        )
                    }
                    c.close()
                }
            }
        }

    /** Holds (or with [hold] false, releases) the server's NEW_CONNECTION_ID frames, on its loop; a release sends them at once. */
    private suspend fun holdServerCids(
        p: ApiPair,
        s: QuicConnection,
        hold: Boolean,
    ) {
        val loop = p.server as EndpointLoop
        withContext(loop.dispatcher) {
            s.core.cids.holdNewCidsForTest = hold
            loop.flush(s.core)
        }
    }

    @Test fun networkChangeRightAfterConnectMigrates() =
        runBlocking {
            // the network changes 0 ms after connect(): the server's spare connection IDs may still be in flight (its first 1-RTT
            // flight, RFC 9000 section 5.1.1), and the probe waits for one instead of failing (iOS library report, 0.2.0 bug 1)
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    (p.server as EndpointLoop).core.testHoldNewConnectionIds = true
                    val (c, s) = p.connect()
                    val nets = MutableStateFlow<Int?>(1)
                    val o = Opener(p)
                    val m = NetworkMigrator(c, nets, { o.open(it) }, this)
                    val (events, collector) = eventsOf(m)
                    m.start()
                    m.network.first { it == 1 }
                    nets.value = 2
                    // the new path exists and waits for an ID; then the server's NEW_CONNECTION_ID frames arrive
                    while (c.paths.size < 2) yield()
                    holdServerCids(p, s, hold = false)
                    val e = assertIs<MigrationEvent.Migrated<Int>>(events.receive())
                    assertEquals(1 to 2, e.old to e.new)
                    assertEquals(addr(2), c.activePath!!.localAddress)
                    ping(c, s)
                    m.close()
                    collector.cancel()
                    c.close()
                }
            }
        }

    @Test fun noSpareConnectionIdFailsDistinctlyAndRetriesWhenOneArrives() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    (p.server as EndpointLoop).core.testHoldNewConnectionIds = true
                    // a short initial RTT keeps the validation timeout, max(3 x PTO, 6 x initial RTT), short in real time
                    val (c, s) = p.connect(quicConfig { initialRtt = 10.milliseconds })
                    val nets = MutableStateFlow<Int?>(1)
                    val o = Opener(p)
                    val m = NetworkMigrator(c, nets, { o.open(it) }, this)
                    val (events, collector) = eventsOf(m)
                    val original = c.activePath!!
                    m.start()
                    m.network.first { it == 1 }
                    nets.value = 2
                    val f = assertIs<MigrationEvent.Failed<Int>>(events.receive())
                    assertEquals(2, f.network)
                    val cause = assertIs<PathValidationException>(f.cause)
                    assertEquals(PathFailureReason.NoSpareConnectionId, cause.reason)
                    assertEquals(original.id, c.activePath!!.id, "the connection stays where it was meanwhile")
                    // the migrator did not give up on network 2: the next spare ID moves the connection there
                    holdServerCids(p, s, hold = false)
                    val e = assertIs<MigrationEvent.Migrated<Int>>(events.receive())
                    assertEquals(1 to 2, e.old to e.new)
                    assertEquals(addr(2), c.activePath!!.localAddress)
                    ping(c, s)
                    m.close()
                    collector.cancel()
                    c.close()
                }
            }
        }

    @Test fun migrateWithoutSpareConnectionIdThrowsNoSpareConnectionId() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    (p.server as EndpointLoop).core.testHoldNewConnectionIds = true
                    val (c, s) = p.connect(quicConfig { initialRtt = 10.milliseconds })
                    val io = p.net.open(addr(2))
                    val e = assertFailsWith<PathValidationException> { c.migrate(io) }
                    assertEquals(PathFailureReason.NoSpareConnectionId, e.reason)
                    assertTrue(io.closed, "the new socket is closed")
                    ping(c, s)
                    c.close()
                }
            }
        }
}
