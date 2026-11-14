// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.util.PlatformUtils
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.PathChangeReason
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.PreferredAddress
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.endpoint.EndpointPair
import io.kuicksilver.quic.ipBytesNoDns
import io.kuicksilver.quic.ipLiteral
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.KslQuicCrypto
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
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
            assertTrue(c.remoteAddressForTest.let { it.port == 4433 && it.ipLiteral() == "10.0.0.3" }, "${c.remoteAddressForTest}")
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

    /**
     * An address of the wrong family is refused naming its literal: read through `hostname` it was a reverse DNS lookup on
     * the JVM and Android (::1 and 127.0.0.1 read "localhost"). The loopback has a name on every usual host, so the old
     * code fails here; the fixed one passes whatever the host's resolver says.
     */
    @Test fun negative_wrongFamilyNamesTheLiteral() {
        val v6 = assertFailsWith<IllegalArgumentException> { PreferredAddress(InetSocketAddress("::1", 4433), null) }
        assertEquals("ipv4 is not an IPv4 literal: ::1", v6.message)
        val v4 = assertFailsWith<IllegalArgumentException> { PreferredAddress(null, InetSocketAddress("127.0.0.1", 4433)) }
        assertEquals("ipv6 is not an IPv6 literal: 127.0.0.1", v4.message)
    }

    /**
     * A host name is refused naming that name, on every platform, and never looked up for the message: on Kotlin/Native
     * the literal was built with `resolveAddress()`, a `getaddrinfo` call that failed for a name that does not resolve.
     * On the JVM and Android java.net resolves a name when the address is built (a real DNS query), so this test does not
     * run there: `PreferredAddressJvmTest` builds an unresolved address instead. Where a Kotlin/Native resolver still made
     * the name an address, the test says so and stops.
     */
    @Test fun negative_nameIsRefusedByItsName() {
        if (PlatformUtils.IS_JVM) {
            println("negative_nameIsRefusedByItsName skipped on the JVM: PreferredAddressJvmTest covers it without a lookup")
            return
        }
        val name = InetSocketAddress("preferred.invalid", 4433)
        if (name.ipBytesNoDns() != null) {
            println("negative_nameIsRefusedByItsName skipped: this host's resolver answers for preferred.invalid")
            return
        }
        val v4 = assertFailsWith<IllegalArgumentException> { PreferredAddress(name, null) }
        assertEquals("ipv4 is not an IPv4 literal: preferred.invalid", v4.message)
        val v6 = assertFailsWith<IllegalArgumentException> { PreferredAddress(null, name) }
        assertEquals("ipv6 is not an IPv6 literal: preferred.invalid", v6.message)
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

    @Test fun statelessResetFromThePreferredAddressUnderValidationIsDetected() {
        // RFC 9000 section 10.3.1: "An endpoint remembers all stateless reset tokens associated with the connection IDs and remote
        // addresses for datagrams it has recently sent" and compares a datagram "with all stateless reset tokens associated with the
        // remote address on which the datagram was received". The client sends PATH_CHALLENGEs to the preferred address under
        // validation, so a Stateless Reset from there ends the connection; only the active path's address was looked at, and the reset
        // was dropped as an unknown packet
        val p = EndpointPair(crypto = KslQuicCrypto, serverPreferred = PreferredAddress(v4, null))
        p.dropToPreferred = true
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c))
            assertTrue(p.runUntil(5.seconds) { pathTo(c, v4)?.state == PathState.Validating }, "the preferred probe started")
            p.step()
            val token = c.peerTp!!.preferredAddressToken!!
            val reset = ByteArray(64) { (it * 37 + 11).toByte() }
            reset[0] = 0x45 // a short header with a connection ID the client does not know
            token.copyInto(reset, reset.size - 16)
            val b = PacketBuffer.of(reset)
            try {
                p.client.handleDatagram(b, reset.size, v4, Ecn.NotEct, p.now)
            } finally {
                b.close()
            }
            p.client.processPending(p.now)
            p.drain(c)
            assertIs<QuicException.ConnectionLost.StatelessReset>(p.closed(c), "${p.events[c]}")
        } finally {
            p.close()
        }
    }

    /** The server connection of [p], once it moved to its preferred-address socket (RFC 9000 section 9.6.2). */
    private fun movedServer(p: EndpointPair): ConnectionCore? =
        p.server.connections().firstOrNull { it.path.socket == io.kuicksilver.quic.PREFERRED_SOCKET }

    /**
     * Connects [p] and holds back the client's 1-RTT datagrams to the original address (its stream data goes there until it moves)
     * until the server moved to its preferred address: what was held arrives late. Returns the client, the moved server connection and
     * the held datagrams.
     */
    private fun moveHoldingOriginal(p: EndpointPair): Triple<ConnectionCore, ConnectionCore, List<ByteArray>> {
        val c = p.connect()
        assertTrue(p.runUntil(5.seconds) { c.state == io.kuicksilver.quic.ConnectionState.Confirmed })
        assertTrue(c.path.isRemote(p.serverAddr), "not moved yet")
        val held = ArrayList<ByteArray>()
        p.filterToServer = { _, bytes ->
            val delay = p.toServerDest == p.serverAddr && (bytes[0].toInt() and 0x80) == 0
            if (delay) held += bytes
            !delay
        }
        val sid = c.openStream(true)
        c.writeStream(sid, ByteArray(100), 0, 100, true)
        assertTrue(p.runUntil(10.seconds) { movedServer(p) != null }, "the server moved to its preferred address")
        p.filterToServer = { _, _ -> true }
        assertTrue(held.isNotEmpty(), "the client sent to the original address before it moved")
        return Triple(c, movedServer(p)!!, held)
    }

    @Test fun negative_delayedPacketOnTheOriginalAddressAfterTheMoveSendsNothingThere() {
        // RFC 9000 section 9.6.2: once moved, the server "begins sending non-probing packets to the client exclusively from its
        // preferred IP address" and "MAY continue to process delayed packets that are received on the old IP address". A packet the
        // client sent to the original address before it moved, overtaken by its first one to the preferred address (two sockets,
        // two receive loops: no order between them), opened a new path on the original socket and challenged it from there, so the
        // client saw a stranger. The original address is closed for the connection once it moved
        val qlog = ArrayList<String>()
        val sink =
            object : io.kuicksilver.quic.QlogSink {
                override fun open(
                    odcidHex: String,
                    role: io.kuicksilver.tls.TlsRole,
                ) = object : io.kuicksilver.quic.QlogTrace {
                    override fun write(record: String) {
                        qlog += record
                    }

                    override fun close() {}
                }
            }
        val p =
            EndpointPair(
                crypto = KslQuicCrypto,
                serverQuic = io.kuicksilver.quic.quicConfig { this.qlog = sink },
                serverPreferred = PreferredAddress(v4, null),
            )
        try {
            val (c, s, held) = moveHoldingOriginal(p)
            val sentBefore = p.serverSent.size
            val invalidResets = s.stats.invalidResets
            for (d in held) p.feed(p.server, d, p.clientAddr)
            assertEquals(held.size.toLong(), s.leftAddressDropped, "each one dropped and counted as such")
            // authenticated, so no Stateless Reset of the client's (section 10.3.1) can hide behind it: not checked as one
            assertEquals(invalidResets, s.stats.invalidResets, "not taken for an invalid Stateless Reset")
            val dropped = qlog.filter { "transport:packet_dropped" in it }
            assertEquals(held.size, dropped.size, "a qlog packet_dropped for each: $dropped")
            assertTrue(dropped.all { "\"details\":\"left_address\"" in it }, "$dropped")
            p.runUntil(2.seconds) { false }
            val fromOriginal = p.serverSentFrom.drop(sentBefore).count { it == p.serverAddr }
            assertEquals(0, fromOriginal, "nothing of the moved connection leaves the original address")
            assertEquals(io.kuicksilver.quic.PREFERRED_SOCKET, s.path.socket, "the connection stays on the preferred address")
            assertTrue(s.paths.all.none { it.socket == PathId.Initial }, "no path on the original socket: ${s.paths.all}")
            assertTrue(p.runUntil(5.seconds) { c.stats.bytesInFlight == 0L && !c.streams.hasStreamData() }, "the data arrives")
            assertNull(p.closed(c))
        } finally {
            p.close()
        }
    }

    @Test fun negative_reservedBitsOnAPacketToTheLeftAddressAreAProtocolViolation() {
        // RFC 9000 section 17.3.1: "An endpoint MUST treat receipt of a packet that has a non-zero value for these bits, after removing
        // both packet and header protection, as a connection error of type PROTOCOL_VIOLATION": the drop on the address the
        // connection left comes after that check. Null crypto (header protection the identity, no AEAD over the header) lets the test
        // set the bits the client "sent"
        val p = EndpointPair(serverPreferred = PreferredAddress(v4, null))
        try {
            val (_, s, held) = moveHoldingOriginal(p)
            val d = held.first().copyOf()
            d[0] = (d[0].toInt() or 0x08).toByte()
            p.feed(p.server, d, p.clientAddr)
            p.drain(s)
            val r = p.closed(s)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r, "${p.events[s]}")
            assertEquals(io.kuicksilver.quic.TransportError.PROTOCOL_VIOLATION, r.code, "$r")
        } finally {
            p.close()
        }
    }

    @Test fun negative_noStatelessResetFromTheLeftAddressForTheMovedConnectionsIds() {
        // RFC 9000 sections 9.6.2 and 9.5: nothing of the moved connection leaves the original address, nothing links the two. The
        // client retires the ID it used there; the server routes it for 3 x PTO more (section 5.1.2), then a datagram with it is an
        // unknown short header, which a Stateless Reset may answer (a MAY, section 10.3). From the original address it would be one
        // more datagram the moved connection makes leave there: none is sent
        val p = EndpointPair(crypto = KslQuicCrypto, serverPreferred = PreferredAddress(v4, null))
        try {
            val (c, _, held) = moveHoldingOriginal(p)
            val seq0 = held.first().copyOfRange(1, 1 + c.peerTp!!.preferredAddressCid!!.length)
            val seq0Id =
                io.kuicksilver.quic.wire
                    .ConnectionId(seq0)
            assertTrue(p.runUntil(10.seconds) { p.server.registry.owner(seq0Id) == null }, "seq 0 stops routing")
            val sentBefore = p.serverSent.size
            for (d in held) p.feed(p.server, d, p.clientAddr)
            assertTrue(p.stateless(p.server).isEmpty(), "no Stateless Reset queued")
            p.runUntil(1.seconds) { false }
            assertEquals(0, p.serverSentFrom.drop(sentBefore).count { it == p.serverAddr }, "nothing leaves the original address")
            assertNull(p.closed(c))
        } finally {
            p.close()
        }
    }

    @Test fun negative_staleMoveToThePreferredAddressIsNotMade() {
        // RFC 9000 sections 9.6.2 and 9.3: the server moves once the preferred path is validated and the newest non-probing packet
        // came there. A non-probing packet on the preferred address left the move pending until the validation; a newer one on the
        // original address since (a client whose own validation of the preferred address failed carries on there, section 9.6.1)
        // makes that packet stale, and the move with it: the server must stay where the client is, not drop its packets there
        val p = EndpointPair(serverPreferred = PreferredAddress(v4, null))
        try {
            val c = p.connect(io.kuicksilver.quic.quicConfig { followPreferredAddress = false })
            assertTrue(p.confirmed(c))
            assertTrue(p.runUntil(1.seconds) { c.stats.bytesInFlight == 0L })
            val s = p.server.connections().single()
            s.now = p.now
            val pn = s.largestNonProbingPn
            // a non-probing packet of the client on the preferred address: a path there under validation, the move pending
            s.onPathPacket(io.kuicksilver.quic.PREFERRED_SOCKET, p.clientAddr, pn + 1, nonProbing = true, datagramBytes = 1200)
            val pp = s.paths.all.single { it.socket == io.kuicksilver.quic.PREFERRED_SOCKET }
            assertTrue(pp.preferredMovePending && pp.state == PathState.Validating, "$pp")
            // a newer one on the original address
            s.onPathPacket(PathId.Initial, p.clientAddr, pn + 2, nonProbing = true, datagramBytes = 100)
            // the server's challenge on the preferred path goes out, and is answered
            p.batch.clear()
            s.poll(p.batch, p.now)
            assertTrue(pp.challenge != 0L, "challenged")
            s.onPathResponse(pp.challenge)
            assertEquals(PathState.Validated, pp.state)
            assertEquals(PathId.Initial, s.path.socket, "the connection stays on the original address")
            assertTrue(!s.leftOriginalAddress)
        } finally {
            p.close()
        }
    }

    @Test fun negative_newerPacketOnTheOriginalAddressAfterTheMoveIsDropped() {
        // RFC 9000 section 9.6.2: "The server SHOULD drop newer packets for this connection that are received on the old IP address";
        // one with a new largest packet number used to move the connection back there, a migration to an address the client gave up
        val p = EndpointPair(crypto = KslQuicCrypto, serverPreferred = PreferredAddress(v4, null))
        try {
            val c = p.connect()
            assertTrue(p.runUntil(10.seconds) { movedServer(p) != null }, "the server moved to its preferred address")
            val s = movedServer(p)!!
            assertTrue(p.runUntil(2.seconds) { c.path.isRemote(v4) && c.pathCountForTest == 1 })
            var diverted: ByteArray? = null
            p.filterToServer = { _, bytes ->
                if (diverted == null && p.toServerDest == v4) {
                    diverted = bytes
                    false
                } else {
                    true
                }
            }
            val sid = c.openStream(true)
            c.writeStream(sid, ByteArray(100), 0, 100, true)
            assertTrue(p.runUntil(1.seconds) { diverted != null }, "the client sent to the preferred address")
            p.filterToServer = { _, _ -> true }
            val received = s.packetsReceived
            val sentBefore = p.serverSent.size
            p.feed(p.server, diverted!!, p.clientAddr)
            assertEquals(received, s.packetsReceived, "the newer packet from the original address is dropped")
            p.runUntil(2.seconds) { false }
            assertEquals(0, p.serverSentFrom.drop(sentBefore).count { it == p.serverAddr }, "nothing leaves the original address")
            assertEquals(io.kuicksilver.quic.PREFERRED_SOCKET, s.path.socket, "the connection stays on the preferred address")
            assertTrue(p.runUntil(5.seconds) { c.stats.bytesInFlight == 0L && !c.streams.hasStreamData() }, "the data arrives again")
            assertNull(p.closed(c))
        } finally {
            p.close()
        }
    }
}
