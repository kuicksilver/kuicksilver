// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionInfo
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.MemoryNetwork
import io.kuicksilver.quic.PathChangeReason
import io.kuicksilver.quic.PathEvent
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.PathInfo
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.PreferredAddress
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicLimits
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.update
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * `ConnectionInfo.paths` and `ConnectionListener.onPathsUpdated` (docs/guide/quic.md, "Observability"): the connection IDs
 * each path carries, as both sides see them, across a migration and a rotation, over the in-memory network (all platforms).
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class, ExperimentalAtomicApi::class)
class PathInfoTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val newAddr = InetSocketAddress("10.0.0.3", 3333)

    /** What a listener heard, in order: `opened`, `paths` (with the lists), `closed`. */
    private class Heard : ConnectionListener {
        val events = AtomicReference(emptyList<String>())
        val lists = Channel<Pair<ConnectionInfo, List<PathInfo>>>(Channel.UNLIMITED)
        val infos = AtomicReference(emptyList<ConnectionInfo>())

        override fun onOpened(connection: ConnectionInfo) {
            infos.update { it + connection }
            events.update { it + "opened" }
        }

        override fun onPathsUpdated(
            connection: ConnectionInfo,
            paths: List<PathInfo>,
        ) {
            events.update { it + "paths" }
            lists.trySend(connection to paths)
        }

        override fun onClosed(
            connection: ConnectionInfo,
            reason: QuicException.ConnectionLost,
        ) {
            events.update { it + "closed" }
        }

        /** The next list heard for which [cond] holds. */
        suspend fun next(cond: (List<PathInfo>) -> Boolean): List<PathInfo> =
            withTimeout(20.seconds) {
                while (true) {
                    val (_, l) = lists.receive()
                    if (cond(l)) return@withTimeout l
                }
                @Suppress("UNREACHABLE_CODE")
                error("unreachable")
            }
    }

    /** Sends [size] bytes each way on a new stream: both sides then sent 1-RTT packets on the active path. */
    private suspend fun exchange(
        c: QuicConnection,
        s: QuicConnection,
        size: Int = 4096,
    ) = coroutineScope {
        launch {
            val st = s.acceptStream()
            val b = ByteArray(16384)
            while (true) {
                val n = st.input.readAvailable(b, 0, b.size)
                if (n < 0) break
                st.output.writeFully(b, 0, n)
                st.output.flush()
            }
            st.output.flushAndClose()
        }
        val st = c.openBidi()
        launch {
            st.output.writeFully(ByteArray(size), 0, size)
            st.output.flushAndClose()
        }
        val b = ByteArray(16384)
        var got = 0
        while (got < size) {
            val n = st.input.readAvailable(b, 0, b.size)
            if (n < 0) break
            got += n
        }
        assertEquals(size, got)
    }

    /** Waits until [c]'s active path shows a local and a remote ID that [s]'s active path shows the other way round. */
    private suspend fun agreed(
        c: QuicConnection,
        s: QuicConnection,
    ): Pair<PathInfo, PathInfo> =
        withTimeout(20.seconds) {
            while (true) {
                val ca = c.info!!.paths.firstOrNull()
                val sa = s.info!!.paths.firstOrNull()
                if (ca != null && sa != null && ca.localConnectionId != null && ca.localConnectionId == sa.remoteConnectionId &&
                    ca.remoteConnectionId == sa.localConnectionId
                ) {
                    return@withTimeout ca to sa
                }
                yield()
            }
            @Suppress("UNREACHABLE_CODE")
            error("unreachable")
        }

    @Test fun pathsShowTheIdsBothSidesUse() =
        runBlocking {
            val heard = Heard()
            ApiPair.open(clientListener = heard).use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    exchange(c, s)
                    val (ca, sa) = agreed(c, s)
                    // one path each, active, validated, with the addresses of the in-memory sockets
                    assertEquals(1, c.info!!.paths.size)
                    assertEquals(PathId.Initial, ca.id)
                    assertTrue(ca.active && sa.active)
                    assertEquals(PathState.Validated, ca.state)
                    assertEquals(p.clientIo.localAddress, ca.localAddress)
                    assertEquals(p.serverIo.localAddress, ca.remoteAddress)
                    assertEquals(p.clientIo.localAddress, sa.remoteAddress)
                    assertTrue(ca.localConnectionId!!.isNotEmpty() && ca.remoteConnectionId!!.isNotEmpty(), "$ca")
                    assertTrue(ca.localConnectionIdSequence >= 0 && ca.remoteConnectionIdSequence >= 0, "$ca")
                    assertEquals(ca.localConnectionIdSequence, sa.remoteConnectionIdSequence)
                    assertEquals(ca.remoteConnectionIdSequence, sa.localConnectionIdSequence)
                    // the listener's handle is the connection's
                    assertSame(heard.infos.load().single(), c.info)
                    assertEquals(TlsRole.Client, c.info!!.role)
                    assertEquals(0, c.info!!.pathChanges)
                    c.close()
                    s.closed.await()
                    withTimeout(10.seconds) { while ("closed" !in heard.events.load()) yield() }
                    val events = heard.events.load()
                    assertEquals("opened", events.first(), "$events")
                    assertTrue("paths" in events, "$events")
                    // after the end the last list stays readable
                    assertEquals(
                        ca.localConnectionId,
                        c.info!!
                            .paths
                            .first()
                            .localConnectionId,
                    )
                }
            }
        }

    @Test fun aMigrationShowsTheNewPathWithFreshIds() =
        runBlocking {
            val heard = Heard()
            ApiPair.open(clientListener = heard).use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    exchange(c, s)
                    val (before, _) = agreed(c, s)
                    awaitSpareConnectionId(c)
                    val change = c.migrate(p.net.open(newAddr))
                    assertEquals(PathChangeReason.ActiveMigration, change.reason)
                    exchange(c, s)
                    val (after, sAfter) = agreed(c, s)
                    assertEquals(change.new.id, after.id, "the active path comes first")
                    assertEquals(newAddr, after.localAddress)
                    assertEquals(newAddr, sAfter.remoteAddress)
                    // RFC 9000 section 9.5: the new path carries IDs the old one never did, in both directions
                    assertNotEquals(before.remoteConnectionId, after.remoteConnectionId)
                    assertNotEquals(before.localConnectionId, after.localConnectionId)
                    assertTrue(after.remoteConnectionIdSequence > before.remoteConnectionIdSequence, "$before -> $after")
                    val old = c.info!!.paths.firstOrNull { it.id == before.id }
                    if (old != null) assertFalse(old.active, "$old")
                    assertEquals(1, c.info!!.pathChanges)
                    withTimeout(10.seconds) { while (s.info!!.pathChanges != 1) yield() }
                    // the listener heard a list with the new path active
                    val l = heard.next { it.first().id == change.new.id && it.first().localConnectionId == after.localConnectionId }
                    assertEquals(1, l.count { it.active })
                    c.close()
                }
            }
        }

    @Test fun aRotationShowsOnBothSides() =
        runBlocking {
            val heard = Heard()
            // the server moves to a new ID of the client every 50 packets it sends (RFC 9000 section 9.5, here sooner)
            val serverQuic = QuicConfig.Builder().apply { limits = QuicLimits(cidRotationPackets = 50) }.build()
            ApiPair.open(serverQuic = serverQuic, clientListener = heard).use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    exchange(c, s)
                    val (before, sBefore) = agreed(c, s)
                    exchange(c, s, 400_000)
                    val (after, sAfter) = agreed(c, s)
                    // the server sends to another ID of ours now, and the client sees its packets carry it
                    assertTrue(sAfter.remoteConnectionIdSequence > sBefore.remoteConnectionIdSequence, "$sBefore -> $sAfter")
                    assertTrue(after.localConnectionIdSequence > before.localConnectionIdSequence, "$before -> $after")
                    assertNotEquals(before.localConnectionId, after.localConnectionId)
                    assertEquals(0, c.info!!.pathChanges, "a rotation is no path change")
                    heard.next { it.first().localConnectionIdSequence == after.localConnectionIdSequence }
                    c.close()
                }
            }
        }

    /** Attack: a reader on another thread during rotations and a migration always sees a whole list. */
    @Test fun aReaderOnAnotherThreadSeesWholeLists() =
        runBlocking {
            val serverQuic = QuicConfig.Builder().apply { limits = QuicLimits(cidRotationPackets = 20) }.build()
            ApiPair.open(serverQuic = serverQuic).use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    val info = assertNotNull(c.info)
                    val seen = AtomicReference(0)
                    val reader =
                        launch(Dispatchers.Default) {
                            while (isActive) {
                                val l = info.paths
                                if (l.isNotEmpty()) {
                                    assertTrue(l.first().active, "$l")
                                    assertEquals(1, l.count { it.active }, "$l")
                                    assertEquals(l.size, l.map { it.id }.toSet().size, "$l")
                                    seen.update { it + 1 }
                                }
                                yield()
                            }
                        }
                    exchange(c, s, 200_000)
                    awaitSpareConnectionId(c)
                    c.migrate(p.net.open(newAddr))
                    exchange(c, s, 200_000)
                    reader.cancel()
                    reader.join()
                    assertTrue(seen.load() > 0)
                    c.close()
                }
            }
        }

    /**
     * The list is there from the connection's creation: inside onOpened (before any drain of the connection) the client
     * sees its first path with its handshake ID (sequence 0) and the random ID it sends to before the server's Initial
     * (sequence -1).
     */
    @Test fun pathsAreThereFromOnOpened() =
        runBlocking {
            val atOpen = AtomicReference<List<PathInfo>?>(null)
            val listener =
                object : ConnectionListener {
                    override fun onOpened(connection: ConnectionInfo) {
                        atOpen.store(connection.paths)
                    }
                }
            ApiPair.open(clientListener = listener).use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    val first = assertNotNull(atOpen.load()).single()
                    assertTrue(first.active)
                    assertEquals(PathId.Initial, first.id)
                    assertEquals(0L, first.localConnectionIdSequence)
                    assertNotNull(first.localConnectionId)
                    assertEquals(-1L, first.remoteConnectionIdSequence, "the client's own random ID, not one of the server's")
                    assertNotNull(first.remoteConnectionId)
                    // once the server answered, its handshake ID (sequence 0) replaces it
                    exchange(c, s)
                    val (now, _) = agreed(c, s)
                    assertNotEquals(first.remoteConnectionId, now.remoteConnectionId)
                    assertTrue(now.remoteConnectionIdSequence >= 0, "$now")
                    c.close()
                }
            }
        }

    /**
     * The probe of the server's preferred address leaves from the active path's socket: the server's packets from that
     * address must be credited to the preferred path, never to the one the connection started on (which keeps the
     * handshake's ID, sequence 0, while it lives); once the client moved, its active path and the server's agree.
     */
    @Test fun aPreferredAddressProbeIsCreditedToItsOwnPath() =
        runBlocking {
            val net = MemoryNetwork()
            val a = net.open(InetSocketAddress("10.0.0.1", 1111))
            val b = net.open(InetSocketAddress("10.0.0.2", 2222))
            val pref = InetSocketAddress("10.0.0.3", 4433)
            val lists = AtomicReference(emptyList<List<PathInfo>>())
            val heard =
                object : ConnectionListener {
                    override fun onPathsUpdated(
                        connection: ConnectionInfo,
                        paths: List<PathInfo>,
                    ) {
                        lists.update { it + listOf(paths) }
                    }
                }
            val server =
                QuicEndpoint.bind(
                    b.localAddress,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig
                                    .Builder(CoreFixtures.server())
                                    .apply { preferredAddress = PreferredAddress(pref, null) }
                                    .build()
                            runtime { crypto = KslQuicCrypto }
                            runtime { io = { at -> if (at == pref) net.open(pref) else b } }
                        }.build(),
                )
            val client =
                QuicEndpoint.bind(
                    a.localAddress,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            runtime { crypto = KslQuicCrypto }
                            runtime { io = { a } }
                            observability { connectionListener = heard }
                        }.build(),
                )
            try {
                withTimeout(30.seconds) {
                    val accepted = async { server.accept() }
                    val c = client.connect(server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    val s = accepted.await()
                    withTimeout(10.seconds) {
                        while (c.info!!
                                .paths
                                .singleOrNull()
                                ?.remoteAddress
                                ?.port != 4433
                        ) {
                            yield()
                        }
                    }
                    exchange(c, s)
                    val (ca, _) = agreed(c, s)
                    assertEquals(4433, ca.remoteAddress.port)
                    for (l in lists.load()) {
                        val original = l.firstOrNull { it.remoteAddress.port == 2222 } ?: continue
                        assertTrue(original.localConnectionIdSequence <= 0, "the original path credited with another path's ID: $l")
                    }
                    assertTrue(
                        lists.load().any { l ->
                            l.any { it.remoteAddress.port == 4433 && it.localConnectionIdSequence > 0 }
                        },
                        "${lists.load()}",
                    )
                    c.close()
                }
            } finally {
                client.close()
                server.close()
            }
        }

    /** Nothing follows onClosed: the list stays as it was, and no onPathsUpdated comes after the end (a migrated connection). */
    @Test fun noPathsUpdateAfterClosed() =
        runBlocking {
            val events = AtomicReference(emptyList<Pair<ConnectionInfo, String>>())
            val atClose = AtomicReference<List<PathInfo>?>(null)
            val listener =
                object : ConnectionListener {
                    override fun onPathsUpdated(
                        connection: ConnectionInfo,
                        paths: List<PathInfo>,
                    ) {
                        events.update { it + (connection to "paths") }
                    }

                    override fun onClosed(
                        connection: ConnectionInfo,
                        reason: QuicException.ConnectionLost,
                    ) {
                        if (atClose.load() == null) atClose.store(connection.paths)
                        events.update { it + (connection to "closed") }
                    }
                }
            ApiPair.open(clientListener = listener).use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    exchange(c, s)
                    awaitSpareConnectionId(c)
                    c.migrate(p.net.open(newAddr))
                    exchange(c, s)
                    val info = c.info!!
                    c.close()
                    s.close()
                    withTimeout(10.seconds) { while (events.load().none { it.first === info && it.second == "closed" }) yield() }
                    // the loop goes on with the closing period (the CONNECTION_CLOSE repeated, the paths released)
                    repeat(3) { exchangeWithNewPair(p) }
                    // and a change the core still makes after the end (a path's state) is drained: no event follows either
                    val rt = c as io.kuicksilver.quic.runtime.ConnectionRuntime
                    kotlinx.coroutines.withContext(rt.loopDispatcher) {
                        rt.core.paths.active.state = PathState.Failed
                        rt.drainEvents()
                    }
                    val mine = events.load().filter { it.first === info }.map { it.second }
                    assertEquals("closed", mine.last(), "$mine")
                    assertEquals(1, mine.count { it == "closed" })
                    assertSame(atClose.load(), info.paths, "the last list stays")
                }
            }
        }

    /** A new connection on the pair: the endpoint loop runs (drains, timers) while the closed one is gone. */
    private suspend fun exchangeWithNewPair(p: ApiPair) {
        val (c, s) = p.connect()
        exchange(c, s, 256)
        c.close()
        s.close()
    }

    @Test fun negative_pathInfoToStringHasNoConnectionId() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    exchange(c, s)
                    val (ca, _) = agreed(c, s)
                    val text = ca.toString()
                    assertFalse(ca.localConnectionId!! in text, text)
                    assertFalse(ca.remoteConnectionId!! in text, text)
                    assertTrue("#0 active" in text, text)
                    c.close()
                }
            }
        }

    /** The change events stay what they were: [PathEvent.Changed] still reports the move the list shows. */
    @Test fun pathEventsAndListAgree() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    exchange(c, s)
                    awaitSpareConnectionId(c)
                    val change = c.migrate(p.net.open(newAddr))
                    assertEquals(
                        change.new.id,
                        c.info!!
                            .paths
                            .first()
                            .id,
                    )
                    assertEquals(
                        change.new.localAddress,
                        c.info!!
                            .paths
                            .first()
                            .localAddress,
                    )
                    c.close()
                }
            }
        }
}
