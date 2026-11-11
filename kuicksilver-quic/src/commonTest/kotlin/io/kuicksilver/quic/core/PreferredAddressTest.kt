// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.PathChangeReason
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.PreferredAddress
import io.kuicksilver.quic.endpoint.EndpointPair
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.KslQuicCrypto
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The client follows the server's preferred address after confirmation and validation (RFC 9000 sections 9.6 and 18.2). */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class PreferredAddressTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val v4 = InetSocketAddress("10.0.0.3", 4433)

    private fun EndpointPair.changes(c: ConnectionCore) = events[c]!!.filterIsInstance<ConnectionEvent.PathChanged>()

    /** The client's path to [to], if it has one. */
    private fun pathTo(
        c: ConnectionCore,
        to: InetSocketAddress,
    ): Path? = c.paths.all.firstOrNull { it.isRemote(to) }

    @Test fun clientMovesAfterConfirmationAndValidation() {
        val p = EndpointPair(crypto = KslQuicCrypto, serverPreferred = PreferredAddress(v4, null))
        try {
            val c = p.connect()
            var early = false
            var nonProbingEarly = false
            assertTrue(
                p.runUntil(10.seconds) {
                    val pp = pathTo(c, v4)
                    if (pp != null && c.state != io.kuicksilver.quic.ConnectionState.Confirmed) early = true
                    if (c.path.isRemote(v4) && pp?.state != PathState.Validated) nonProbingEarly = true
                    p.changes(c).any { it.reason == PathChangeReason.PreferredAddress }
                },
                "the client never moved: ${p.events[c]}",
            )
            assertTrue(!early, "no PATH_CHALLENGE to the preferred address before the handshake is confirmed")
            assertTrue(!nonProbingEarly, "the active path moved before the preferred one was validated")
            assertTrue(c.remoteAddressForTest.let { it.port == 4433 && it.hostname == "10.0.0.3" }, "${c.remoteAddressForTest}")
            assertEquals(c.peerTp!!.preferredAddressCid, c.remoteCid, "the preferred path uses the sequence-1 ID")
            assertTrue(p.runUntil(5.seconds) { 0L !in c.cids.peerSeqsForTest() }, "sequence 0 retired: ${c.cids.peerSeqsForTest()}")
            assertEquals(1, c.pathCountForTest, "the original path is closed")
            val id = c.openStream(true)
            c.writeStream(id, ByteArray(20_000), 0, 20_000, true)
            assertTrue(
                p.runUntil(5.seconds) { c.stats.bytesInFlight == 0L && !c.streams.hasStreamData() },
                "data flows on the preferred path",
            )
            assertNull(p.closed(c))
        } finally {
            p.close()
        }
    }

    @Test fun sameFamilyOnly() {
        // an IPv4 connection and only an IPv6 preferred address: the client stays where it is
        val p = EndpointPair(crypto = KslQuicCrypto, serverPreferred = PreferredAddress(null, InetSocketAddress("fd00::3", 4433)))
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c))
            p.runUntil(3.seconds) { false }
            assertEquals(1, c.pathCountForTest)
            assertTrue(p.changes(c).isEmpty())
        } finally {
            p.close()
        }
    }

    @Test fun negative_failedValidationStaysOnOriginal() {
        // RFC 9000 section 9.6.1: a client that cannot validate the preferred address MUST go on sending to the original one
        val p = EndpointPair(crypto = KslQuicCrypto, serverPreferred = PreferredAddress(v4, null))
        p.dropToPreferred = true
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c))
            assertTrue(
                p.runUntil(15.seconds) { p.events[c]!!.any { it is ConnectionEvent.PathFailed } },
                "the preferred path's validation fails: ${p.events[c]}",
            )
            assertTrue(p.changes(c).isEmpty(), "never moved")
            assertTrue(c.path.isRemote(p.serverAddr))
            assertEquals(1, c.pathCountForTest, "the failed preferred path is closed")
            assertTrue(p.runUntil(5.seconds) { 1L !in c.cids.peerSeqsForTest() }, "its sequence-1 ID retired: ${c.cids.peerSeqsForTest()}")
            val id = c.openStream(true)
            c.writeStream(id, ByteArray(5000), 0, 5000, true)
            assertTrue(p.runUntil(5.seconds) { c.stats.bytesInFlight == 0L && !c.streams.hasStreamData() }, "the connection lives on")
            assertNull(p.closed(c))
        } finally {
            p.close()
        }
    }

    @Test fun negative_preferredAddressToLoopbackFromPublicServerIgnored() {
        // threat-model 3.14 (the rule of AltSvcDestination): a public server cannot point the client into its own host or network
        for (target in listOf(
            InetSocketAddress("127.0.0.1", 4433),
            InetSocketAddress("192.168.1.10", 4433),
            InetSocketAddress("169.254.1.1", 4433),
        )) {
            val p =
                EndpointPair(
                    crypto = KslQuicCrypto,
                    serverPreferred = PreferredAddress(target, null),
                    serverAddr = InetSocketAddress("203.0.113.2", 443),
                )
            try {
                val c = p.connect()
                assertTrue(p.confirmed(c), "$target: ${p.closed(c)}")
                p.runUntil(2.seconds) { false }
                assertEquals(1, c.pathCountForTest, "$target: not followed")
                assertTrue(p.toServerSockets.none { it == io.kuicksilver.quic.PREFERRED_SOCKET }, "$target: nothing sent there")
            } finally {
                p.close()
            }
        }
    }

    @Test fun negative_preferredAddressUnspecifiedOrMulticastIgnored() {
        // the configuration refuses them; a hostile server's transport parameters can still carry them: never followed
        assertFailsWith<IllegalArgumentException> { PreferredAddress(InetSocketAddress("0.0.0.0", 4433), null) }
        assertFailsWith<IllegalArgumentException> { PreferredAddress(InetSocketAddress("224.0.0.1", 4433), null) }
        assertFailsWith<IllegalArgumentException> { PreferredAddress(InetSocketAddress("255.255.255.255", 4433), null) }
        for (target in listOf(
            InetSocketAddress("224.0.0.1", 4433),
            InetSocketAddress("255.255.255.255", 4433),
            InetSocketAddress("0.0.0.0", 4433),
        )) {
            val p = EndpointPair(crypto = KslQuicCrypto, serverPreferred = PreferredAddress(target, null, check = false))
            try {
                val c = p.connect()
                assertTrue(p.confirmed(c), "$target: ${p.closed(c)}")
                p.runUntil(2.seconds) { false }
                assertEquals(1, c.pathCountForTest, "$target: not followed")
                assertTrue(p.changes(c).isEmpty(), target.toString())
            } finally {
                p.close()
            }
        }
    }

    @Test fun negative_preferredAddressOnReflectionPortIgnored() {
        // a server must not aim the client's probes at a DNS, NTP, SSDP, mDNS or memcached port (threat-model 3.1, 3.14)
        assertFailsWith<IllegalArgumentException> { PreferredAddress(InetSocketAddress("10.0.0.3", 53), null) }
        val p =
            EndpointPair(
                crypto = KslQuicCrypto,
                serverPreferred = PreferredAddress(InetSocketAddress("10.0.0.3", 123), null, check = false),
            )
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c))
            p.runUntil(2.seconds) { false }
            assertEquals(1, c.pathCountForTest)
            assertTrue(p.toServerSockets.none { it == io.kuicksilver.quic.PREFERRED_SOCKET })
        } finally {
            p.close()
        }
    }

    @Test fun negative_noNonProbingToPreferredBeforeValidation() {
        // RFC 9000 sections 9.6.2 and 21.5.3: until the preferred path is validated only probing packets go there, so an
        // unvalidated preferred address (one the server's attacker chose) gets nothing an application sent
        val p = EndpointPair(crypto = KslQuicCrypto, serverPreferred = PreferredAddress(v4, null))
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c))
            val id = c.openStream(true)
            var w = 0
            var violated = false
            assertTrue(
                p.runUntil(10.seconds) {
                    if (w < 100_000) w += c.writeStream(id, ByteArray(4096), 0, 4096, false)
                    val pp = pathTo(c, v4)
                    if (c.path.isRemote(v4) && pp?.state != PathState.Validated) violated = true
                    p.changes(c).isNotEmpty()
                },
            )
            assertTrue(!violated)
        } finally {
            p.close()
        }
    }

    @Test fun followsDespiteDisableActiveMigrationAndThenMayMigrate() {
        // RFC 9000 section 18.2: disable_active_migration does not cover the preferred address; once there, the client may migrate
        val p =
            EndpointPair(
                crypto = KslQuicCrypto,
                serverPreferred = PreferredAddress(v4, null),
                serverQuic = quicConfig { allowMigration = false },
            )
        try {
            val c = p.connect()
            assertTrue(p.runUntil(10.seconds) { c.state == io.kuicksilver.quic.ConnectionState.Confirmed })
            assertTrue(c.peerTp!!.disableActiveMigration)
            assertFailsWith<IllegalStateException>(
                "active migration before the move",
            ) { c.addPath(InetSocketAddress("10.0.0.9", 1), p.now) }
            assertTrue(p.runUntil(10.seconds) { p.changes(c).any { it.reason == PathChangeReason.PreferredAddress } }, "${p.events[c]}")
            val id = c.addPath(InetSocketAddress("10.0.0.3", 4433), p.now, PathId.Initial).also { c.closePath(it) }
            assertTrue(id != PathId.Initial, "after the move addPath is allowed")
        } finally {
            p.close()
        }
    }

    @Test fun userMigrationAbandonsPendingPreferredProbe() {
        // an application that migrates on the same socket while the preferred address is still being validated wins: that probe is
        // closed and not tried again (ngtcp2 refuses the application instead)
        val p = EndpointPair(crypto = KslQuicCrypto, serverPreferred = PreferredAddress(v4, null))
        p.dropToPreferred = true
        try {
            val c = p.connect()
            assertTrue(p.runUntil(10.seconds) { pathTo(c, v4) != null }, "the preferred probe started")
            val mine = InetSocketAddress("10.0.0.2", 443)
            val id = c.addPath(mine, p.now, PathId.Initial).also { assertTrue(it != PathId.Initial) }
            assertNull(pathTo(c, v4), "the preferred path is gone")
            p.runUntil(10.seconds) { false }
            assertNull(pathTo(c, v4), "and not tried again")
            assertTrue(p.changes(c).none { it.reason == PathChangeReason.PreferredAddress })
            c.closePath(id)
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 9.6.3: "the client SHOULD perform path validation to both the original and preferred server address from the
     * client's new address concurrently", and "If path validation of the server's preferred address succeeds, the client MUST abandon
     * validation of the original address and migrate to using the server's preferred address". An application migration from a new
     * socket used to close the pending preferred probe for good (0.3.0 cross-review); the preferred address is now probed from the new
     * socket too, and when it validates the application's path takes it.
     */
    @Test fun migrationDuringPreferredValidationValidatesBothFromTheNewSocket() {
        val p = EndpointPair(crypto = KslQuicCrypto, serverPreferred = PreferredAddress(v4, null))
        val newSocket = PathId(9)
        val newSource = InetSocketAddress("10.0.0.7", 50000)
        p.clientSocketSources[newSocket] = newSource
        p.clientListens += newSource
        p.dropToPreferred = true // the first probe, from the old socket, gets no answer
        try {
            val c = p.connect()
            assertTrue(p.runUntil(10.seconds) { pathTo(c, v4) != null }, "the preferred probe started")
            val id = c.addPath(p.serverAddr, p.now, newSocket)
            val fromNew = c.paths.all.firstOrNull { it.preferred && it.socket == newSocket }
            assertTrue(fromNew != null && fromNew.state == PathState.Validating, "the preferred address is probed from the new socket")
            c.probePath(id, p.now)
            p.dropToPreferred = false
            assertTrue(
                p.runUntil(10.seconds) { p.events[c]!!.any { it is ConnectionEvent.PathValidated && it.path == id } },
                "the application's path validated: ${p.events[c]}",
            )
            val mine = c.paths.byId(id)!!
            assertTrue(mine.isRemote(v4), "the application's path took the preferred address: ${mine.remote}")
            assertTrue(
                p.events[c]!!.none { it is ConnectionEvent.PathValidated && it.path == fromNew.id },
                "no event names the probe the application never created: ${p.events[c]}",
            )
            assertNull(c.paths.all.firstOrNull { it !== mine && it.socket == newSocket }, "no other path on the new socket")
            c.switchPath(id, p.now)
            assertTrue(c.path.isRemote(v4) && c.path.socket == newSocket)
            val sid = c.openStream(true)
            c.writeStream(sid, ByteArray(5000), 0, 5000, true)
            assertTrue(p.runUntil(5.seconds) { c.stats.bytesInFlight == 0L && !c.streams.hasStreamData() }, "data flows there")
            assertNull(p.closed(c))
        } finally {
            p.close()
        }
    }

    /** The original address validated first and the application moved there: the preferred address validating later still wins. */
    @Test fun preferredAddressValidatedAfterTheMigrationMovesTheActivePath() {
        val p = EndpointPair(crypto = KslQuicCrypto, serverPreferred = PreferredAddress(v4, null))
        val newSocket = PathId(9)
        val newSource = InetSocketAddress("10.0.0.7", 50000)
        p.clientSocketSources[newSocket] = newSource
        p.clientListens += newSource
        p.dropToPreferred = true
        try {
            val c = p.connect()
            assertTrue(p.runUntil(10.seconds) { pathTo(c, v4) != null }, "the preferred probe started")
            val id = c.addPath(p.serverAddr, p.now, newSocket)
            c.probePath(id, p.now)
            assertTrue(p.runUntil(10.seconds) { p.events[c]!!.any { it is ConnectionEvent.PathValidated && it.path == id } })
            assertTrue(c.paths.byId(id)!!.isRemote(p.serverAddr), "the original address validated first")
            c.switchPath(id, p.now)
            p.dropToPreferred = false
            assertTrue(
                p.runUntil(15.seconds) { p.changes(c).any { it.reason == PathChangeReason.PreferredAddress } },
                "the move to the preferred address: ${p.events[c]}",
            )
            assertTrue(c.path.id == id && c.path.isRemote(v4) && c.path.socket == newSocket, "${c.path}")
            val sid = c.openStream(true)
            c.writeStream(sid, ByteArray(5000), 0, 5000, true)
            assertTrue(p.runUntil(5.seconds) { c.stats.bytesInFlight == 0L && !c.streams.hasStreamData() }, "data flows there")
            assertNull(p.closed(c))
        } finally {
            p.close()
        }
    }
}
