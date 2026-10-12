// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.NewReno
import io.kuicksilver.quic.PathChangeReason
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicLimits
import io.kuicksilver.quic.endpoint.EndpointPair
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.KslQuicCrypto
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** RFC 9000 sections 8.2 and 9: path validation, passive migration, NAT rebinding, connection ID rotation. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class PathTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val other = InetSocketAddress("10.0.0.7", 40000)

    private fun EndpointPair.server(): ConnectionCore = server.connections().single()

    private fun EndpointPair.settle(steps: Int = 30) {
        repeat(steps) { step() }
    }

    private fun EndpointPair.changes(c: ConnectionCore) = events[c]!!.filterIsInstance<ConnectionEvent.PathChanged>()

    /** A connected pair with a few idle rounds behind it, so no ACK is pending when a test injects a frame. */
    private fun connected(
        crypto: io.kuicksilver.tls.QuicCrypto = io.kuicksilver.quic.NullCryptoProvider,
        serverQuic: QuicConfig = QuicConfig.Default,
        clientQuic: QuicConfig = QuicConfig.Default,
    ): Pair<EndpointPair, ConnectionCore> {
        val p = EndpointPair(crypto = crypto, serverQuic = serverQuic)
        val c = p.connect(clientQuic)
        assertTrue(p.confirmed(c))
        p.settle()
        return p to
            c
    }

    private fun send(
        c: ConnectionCore,
        bytes: Int = 100,
    ) {
        val id = c.openStream(true)
        c.writeStream(id, ByteArray(bytes) { 0x41 }, 0, bytes, true)
    }

    private fun bytesTo(
        p: EndpointPair,
        a: InetSocketAddress,
    ): Long = p.serverSent.filter { it.first == a }.sumOf { it.second.size.toLong() }

    @Test fun pathResponseGoesToChallengeSource() {
        // RFC 9000 section 8.2.2: the response goes back to where the challenge came from, expanded to 1200 bytes; a probing-only packet migrates nothing
        val (p, c) = connected()
        try {
            p.clientListensOnSource = false
            c.testInjectPathChallenges = 1
            p.clientSource = other
            p.step()
            p.clientSource = p.clientAddr
            p.settle(5)
            val toOther = p.sentElsewhere.filter { it.first == other }
            assertEquals(1, toOther.size, "one PATH_RESPONSE datagram to the challenge source")
            assertTrue(toOther[0].second.size >= 1200, "expanded: ${toOther[0].second.size}")
            assertEquals(p.clientAddr, p.server().remoteAddressForTest)
            assertTrue(
                p.changes(p.server()).isEmpty(),
                "a probing-only packet migrates nothing: ${p.changes(p.server()).map { it.reason }}",
            )
        } finally {
            p.close()
        }
    }

    @Test fun negative_pathChallengeQueueCap() {
        val (p, c) = connected()
        try {
            c.testInjectPathChallenges = 10
            p.settle(5)
            val s = p.server()
            assertEquals(3, s.pathResponsesSentForTest, "at most 3 PATH_RESPONSE queued (spec 4.7)")
            assertEquals(7L, s.stats.glitchTokensSpent)
            assertNull(p.closed(s))
        } finally {
            p.close()
        }
    }

    @Test fun pathResponseWithUnknownDataIgnored() {
        val (p, c) = connected()
        try {
            c.testInjectPathResponse = 0x1234L
            p.settle(5)
            val s = p.server()
            assertNull(p.closed(s))
            assertEquals(PathState.Validated, s.pathState(PathId.Initial))
            assertTrue(p.changes(s).isEmpty())
        } finally {
            p.close()
        }
    }

    @Test fun addressChangeResetsCongestionAndRtt() {
        val (p, c) = connected()
        try {
            send(c, 20_000)
            p.settle(40)
            val s = p.server()
            val before = s.stats
            assertTrue(before.smoothedRtt < 100.milliseconds, "the handshake measured the 20 ms RTT: ${before.smoothedRtt}")
            p.clientSource = other
            p.clientListens += other
            send(c)
            p.step() // one round: the switch happened, no ACK from the new address yet
            assertEquals(other, s.remoteAddressForTest)
            val ch = p.changes(s)
            assertEquals(1, ch.size)
            assertEquals(PathChangeReason.PeerMigration, ch[0].reason)
            assertEquals(PathId.Initial, ch[0].old)
            assertNotEquals(ch[0].old, ch[0].new)
            assertEquals(NewReno().cwnd, s.stats.cwnd, "a new address starts with the initial window")
            assertEquals(333.milliseconds, s.stats.smoothedRtt, "and the initial RTT")
            p.settle(20)
            assertEquals(PathState.Validated, s.pathState(ch[0].new), "PATH_CHALLENGE answered")
            assertTrue(
                p.events[s]!!.any {
                    it is ConnectionEvent.PathValidated &&
                        it.path == ch[0].new
                },
            )
        } finally {
            p.close()
        }
    }

    @Test fun natRebindKeepsCongestionAndRtt() {
        val (p, c) = connected()
        try {
            send(c, 20_000)
            p.settle(40)
            val s = p.server()
            val rtt = s.stats.smoothedRtt
            val cwndBefore = s.stats.cwnd
            val lostBefore = s.stats.lostPackets
            p.clientSource = InetSocketAddress("10.0.0.1", 40001)
            p.clientListens += p.clientSource
            send(c)
            p.settle(5)
            val ch = p.changes(s)
            assertEquals(1, ch.size)
            assertEquals(PathChangeReason.NatRebinding, ch[0].reason)
            assertTrue(
                s.stats.smoothedRtt < 50.milliseconds,
                "same IP, new port: RTT kept (was $rtt, now ${s.stats.smoothedRtt}, not reset to 333 ms)",
            )
            assertTrue(
                s.stats.cwnd >= cwndBefore,
                "cwnd kept: before $cwndBefore (lost $lostBefore) after ${s.stats.cwnd} (lost ${s.stats.lostPackets})",
            )
        } finally {
            p.close()
        }
    }

    @Test fun newPathAmplificationLimit3x() {
        // RFC 9000 section 9.3.1: until the new address answers a PATH_CHALLENGE, the server sends it at most three times what it received from there
        val (p, c) = connected()
        try {
            p.clientListensOnSource = false
            send(c, 60_000)
            p.clientSource = other
            var fromOther = 0L
            p.filterToServer = { _, b ->
                if (p.clientSource == other && fromOther < 3000) {
                    fromOther += b.size
                    true
                } else {
                    false
                }
            } // a couple of datagrams from the new address, then silence
            p.runUntil(3.seconds) { false }
            val toOther = bytesTo(p, other)
            assertTrue(toOther > 0, "the server did answer the new address")
            assertTrue(toOther <= 3 * fromOther, "sent $toOther to the unvalidated address after receiving $fromOther")
        } finally {
            p.close()
        }
    }

    @Test fun negative_offPathForwardRevalidatesOldPath() {
        // RFC 9000 section 9.3.3: a copy of the client's packet arriving first from an attacker's address moves the server there; it challenges both the new and the old
        // address, the client's next (higher-numbered) packet from the old address brings the server back, and the attacker's path fails validation
        val attacker = InetSocketAddress("10.0.0.66", 6666)
        val (p, c) = connected()
        try {
            var copied = false
            p.filterToServer = { _, b ->
                if (!copied && b[0].toInt() and 0x80 == 0) {
                    copied = true
                    p.feed(p.server, b, attacker)
                }
                true
            }
            send(c)
            p.step()
            val s = p.server()
            assertEquals(attacker, s.remoteAddressForTest, "the forged copy arrived first")
            val first = p.changes(s)
            assertEquals(1, first.size)
            assertEquals(PathChangeReason.PeerMigration, first[0].reason)
            assertTrue(
                s.challengedAddressesForTest.contains(attacker) && s.challengedAddressesForTest.contains(p.clientAddr),
                "both paths challenged: ${s.challengedAddressesForTest}",
            )
            send(c)
            p.settle(5)
            assertEquals(p.clientAddr, s.remoteAddressForTest, "the client's next non-probing packet from the old address wins")
            assertEquals(2, p.changes(s).size)
            assertTrue(
                p.runUntil(5.seconds) {
                    p.events[s]!!.any { it is ConnectionEvent.PathFailed && it.path == first[0].new }
                },
                "the attacker never answers: its path fails",
            )
            assertEquals(PathState.Failed, s.pathState(first[0].new))
            assertNull(p.closed(s))
            assertNull(p.closed(c))
        } finally {
            p.close()
        }
    }

    @Test fun failedValidationFallsBackToLastValidated() {
        // RFC 9000 section 9.3.2: the new path never delivers the server's packets; after the validation timeout the server returns to the last validated path
        val (p, c) = connected()
        try {
            p.clientListensOnSource = false
            val s = p.server()
            p.clientSource = other
            send(c)
            p.step()
            assertEquals(other, s.remoteAddressForTest)
            assertTrue(p.runUntil(5.seconds) { p.changes(s).any { it.reason == PathChangeReason.ValidationFailed } })
            val back = p.changes(s).last()
            assertEquals(PathChangeReason.ValidationFailed, back.reason)
            assertEquals(PathId.Initial, back.new)
            assertEquals(p.clientAddr, s.remoteAddressForTest)
            assertEquals(PathState.Failed, s.pathState(back.old))
            assertNull(p.closed(s))
        } finally {
            p.close()
        }
    }

    @Test fun validationTimeoutUsesRfcFloor() {
        // RFC 9000 section 8.2.4: max(3 x PTO, 6 x initial RTT) — with a 20 ms RTT the floor of 2 s applies
        val (p, c) = connected()
        try {
            p.clientListensOnSource = false
            val s = p.server()
            p.clientSource = other
            send(c)
            p.step()
            val t0 = p.now
            assertTrue(p.runUntil(5.seconds) { p.events[s]!!.any { it is ConnectionEvent.PathFailed } })
            val took = p.now - t0
            assertTrue(took >= 1990.milliseconds && took <= 2500.milliseconds, "validation failed after $took")
        } finally {
            p.close()
        }
    }

    @Test fun pathChallengeRepeatsBackOff() {
        // RFC 9000 section 8.2.1 and RFC 9002 section 6.2.1: an unanswered PATH_CHALLENGE is repeated with an exponentially growing gap, not once per PTO
        val (p, c) = connected()
        try {
            val id = c.addPath(p.serverAddr, p.now)
            c.probePath(id, p.now)
            val path = c.paths.byId(id)!!
            val g1 = path.nextChallengeAt - p.now
            assertTrue(g1 > Duration.ZERO)
            val t1 = path.nextChallengeAt
            c.onTimeout(t1)
            val g2 = path.nextChallengeAt - t1
            assertTrue(g2 >= g1 * 2, "second gap $g2 is at least twice the first $g1")
            val t2 = path.nextChallengeAt
            c.onTimeout(t2)
            val g3 = path.nextChallengeAt - t2
            assertTrue(g3 >= g2 * 2, "third gap $g3 is at least twice the second $g2")
        } finally {
            p.close()
        }
    }

    @Test fun negative_migrationToLoopback() {
        // a client at 10.0.0.1 cannot "move" to loopback or link-local: no path change and not a byte sent there
        for (bad in listOf(
            InetSocketAddress("127.0.0.1", 40000),
            InetSocketAddress("169.254.3.4", 40000),
            InetSocketAddress("fe80::1", 40000),
        )) {
            val (p, c) = connected()
            try {
                val s = p.server()
                p.clientSource = bad
                send(c)
                p.settle(10)
                assertEquals(p.clientAddr, s.remoteAddressForTest, "$bad")
                assertTrue(p.changes(s).isEmpty())
                assertEquals(0L, bytesTo(p, bad), "nothing goes to $bad")
                assertNull(p.closed(s))
            } finally {
                p.close()
            }
        }
    }

    @Test fun allowMigrationFalseAdvertisesAndDrops() {
        val (p, c) = connected(serverQuic = quicConfig { allowMigration = false })
        try {
            assertTrue(c.peerTp!!.disableActiveMigration, "disable_active_migration advertised")
            val s = p.server()
            p.clientSource = other
            send(c)
            p.settle(10)
            assertEquals(p.clientAddr, s.remoteAddressForTest)
            assertTrue(p.changes(s).isEmpty())
            assertEquals(0L, bytesTo(p, other))
            assertNull(p.closed(s))
        } finally {
            p.close()
        }
    }

    @Test fun serverNoLongerAdvertisesDisableActiveMigration() {
        val (p, c) = connected()
        try {
            assertFalse(c.peerTp!!.disableActiveMigration)
        } finally {
            p.close()
        }
    }

    @Test fun migrationUsesFreshPeerCidAndRetiresOld() {
        // RFC 9000 section 9.5: packets to the new address carry a connection ID never used on the old one; the old one is retired
        val (p, c) = connected()
        try {
            val s = p.server()
            val before = s.remoteCid
            p.clientSource = other
            p.clientListens += other
            send(c)
            p.settle(10)
            assertNotEquals(before, s.remoteCid, "a fresh peer connection ID on the new path")
            assertTrue(c.cids.retiredByPeer >= 1, "the old one was retired")
        } finally {
            p.close()
        }
    }

    @Test fun cidRotatedEvery10000Packets() {
        assertEquals(10_000, QuicLimits().cidRotationPackets)
        val (p, c) = connected(serverQuic = QuicConfig.Builder().apply { limits = QuicLimits(cidRotationPackets = 50) }.build())
        try {
            val s = p.server()
            val before = s.remoteCid
            val id = s.openStream(true)
            s.writeStream(id, ByteArray(120_000), 0, 120_000, true)
            p.runUntil(10.seconds) {
                s.stats.packetsSent >
                    60 &&
                    c.cids.retiredByPeer >= 1
            }
            assertNotEquals(before, s.remoteCid, "the server rotated to another of the client's IDs")
            assertTrue(c.cids.retiredByPeer >= 1)
        } finally {
            p.close()
        }
    }

    @Test fun retiredLocalCidRoutesForThreePto() {
        val (p, c) = connected()
        try {
            val s = p.server()
            val old = s.localCid.toByteArray()
            s.cids.issueRetiringOlder()
            p.settle(10)
            assertTrue(s.cids.retiredByPeer >= 1, "the client retired the handshake ID")
            val short = ByteArray(60) { 0x5a }
            short[0] = 0x40
            old.copyInto(short, 1)
            assertEquals(s, p.feed(p.server, short, p.clientAddr), "a retired ID still routes for 3 x PTO")
            p.runUntil(3.seconds) { false }
            assertNull(p.feed(p.server, short, p.clientAddr), "after 3 x PTO the ID is gone")
        } finally {
            p.close()
        }
    }

    @Test fun atMostFourPaths() {
        val (p, c) = connected()
        try {
            val s = p.server()
            for (i in 1..5) {
                p.clientSource = InetSocketAddress("10.0.$i.1", 40000)
                send(c)
                p.step()
            }
            assertEquals(4, s.pathCountForTest, "the initial path plus three probes; the fifth address is dropped")
            assertNull(p.closed(s))
        } finally {
            p.close()
        }
    }

    @Test fun peerMigrationWhileServerSendsCompletes() {
        // the interop rebind-addr case: the server is the sender, the client's IP changes mid-download; the transfer must finish without a stall
        val (p, c) = connected(crypto = KslQuicCrypto)
        try {
            val s = p.server()
            val size =
                2 shl 20
            val id = s.openStream(true)
            var written = 0
            val buf = ByteArray(size) { (it * 5).toByte() }
            val got = ByteArray(size)
            var read = 0
            var sid = -1L
            val inBuf = ByteArray(16384)
            var migrated = false
            var tAtMigration = p.now
            val ok =
                p.runUntil(60.seconds) {
                    if (written <
                        size
                    ) {
                        written +=
                            s.writeStream(id, buf, written, minOf(16384, size - written), written + minOf(16384, size - written) == size)
                    }
                    if (sid < 0) {
                        sid = p.events[c]
                            ?.filterIsInstance<ConnectionEvent.StreamOpened>()
                            ?.firstOrNull()
                            ?.id ?: -1
                    }
                    if (sid >=
                        0
                    ) {
                        while (true) {
                            val n = c.readStream(sid, inBuf, 0, inBuf.size)
                            if (n <=
                                0
                            ) {
                                break
                            }
                            inBuf.copyInto(got, read, 0, n)
                            read += n
                        }
                    }
                    if (!migrated &&
                        read > size / 4
                    ) {
                        migrated = true
                        tAtMigration = p.now
                        p.clientSource = other
                        p.clientListens += other
                    }
                    read == size
                }
            assertTrue(
                ok,
                "finished: read $read of $size, server state ${s.state}, paths ${s.pathCountForTest}, changes ${p.changes(
                    s,
                ).map { it.reason }}",
            )
            assertTrue(got.contentEquals(buf))
            assertEquals(listOf(PathChangeReason.PeerMigration), p.changes(s).map { it.reason })
            assertTrue(p.now - tAtMigration < 10.seconds, "no stall after the migration: ${p.now - tAtMigration}")
        } finally {
            p.close()
        }
    }

    @Test fun deadOldPathIsProbedAtPtoPaceOnly() {
        // the interop rebind-addr stall: the old address is dead, data flows on the new one; the old path draws one probe per PTO at most (RFC 9000 section 8.2.4),
        // never one per loss detection, and its probes are charged to its own congestion controller, not the active path's
        val (p, c) = connected(crypto = KslQuicCrypto)
        try {
            val s = p.server()
            val size =
                2 shl 20
            val id = s.openStream(true)
            var written = 0
            val buf = ByteArray(size) { (it * 5).toByte() }
            var read = 0
            var sid = -1L
            val inBuf = ByteArray(16384)
            p.clientSource = other
            p.clientListens.clear()
            p.clientListens += other // the old address no longer exists
            send(c)
            p.step() // the client's first packet from the new address moves the server there
            val t0 = p.now
            val ok =
                p.runUntil(30.seconds) {
                    if (written <
                        size
                    ) {
                        written +=
                            s.writeStream(id, buf, written, minOf(16384, size - written), written + minOf(16384, size - written) == size)
                    }
                    if (sid < 0) {
                        sid = p.events[c]
                            ?.filterIsInstance<ConnectionEvent.StreamOpened>()
                            ?.firstOrNull()
                            ?.id ?: -1
                    }
                    if (sid >= 0) {
                        while (true) {
                            val n = c.readStream(sid, inBuf, 0, inBuf.size)
                            if (n <= 0) break
                            read += n
                        }
                    }
                    read == size
                }
            assertTrue(
                ok,
                "download finished despite the dead old path: read $read, probes to the old address ${p.serverSent.count {
                    it.first == p.clientAddr
                }}, elapsed ${p.now - t0}",
            )
            assertTrue(p.now - t0 < 6.seconds, "no stall: ${p.now - t0}")
            assertTrue(
                p.runUntil(5.seconds) { s.pathState(PathId.Initial) == PathState.Failed },
                "the old path fails after the validation timeout",
            )
            val probesToOld = p.serverSent.count { it.first == p.clientAddr }
            assertTrue(probesToOld in 2..80, "PTO-paced probes over the 2 s validation window, not a storm: $probesToOld")
        } finally {
            p.close()
        }
    }

    @Test fun addPathBeforeConfirmedThrows() {
        val p = EndpointPair(crypto = KslQuicCrypto)
        try {
            val c = p.connect()
            assertTrue(
                p.runUntil {
                    c.state == io.kuicksilver.quic.ConnectionState.Established ||
                        c.state == io.kuicksilver.quic.ConnectionState.Confirmed
                },
            )
            if (c.state !=
                io.kuicksilver.quic.ConnectionState.Confirmed
            ) {
                val e = kotlin.test.assertFailsWith<IllegalStateException> { c.addPath(p.serverAddr, p.now) }
                assertTrue(e.message!!.contains("confirmed"), e.message)
            }
            assertTrue(p.confirmed(c))
            val id = c.addPath(p.serverAddr, p.now)
            assertEquals(PathState.Unknown, c.pathState(id))
            kotlin.test.assertFailsWith<IllegalStateException> { p.server().addPath(p.clientAddr, p.now) }
        } finally {
            p.close()
        }
    }

    @Test fun serverSeesActiveMigrationAsPeerMigration() {
        // the client adds a path on a second socket, probes it and switches: the server reports PeerMigration and answers on the new address
        val (p, c) = connected(crypto = KslQuicCrypto)
        try {
            val s = p.server()
            val id = c.addPath(p.serverAddr, p.now)
            p.clientSocketSources[id] = other
            p.clientListens += other
            c.probePath(id, p.now)
            assertTrue(p.runUntil(5.seconds) { c.pathState(id) == PathState.Validated }, "probe answered: ${c.pathState(id)}")
            assertEquals(p.clientAddr, s.remoteAddressForTest, "a probe alone moves nothing")
            c.switchPath(id, p.now)
            send(c)
            p.settle(5)
            assertEquals(other, s.remoteAddressForTest)
            assertEquals(listOf(PathChangeReason.PeerMigration), p.changes(s).map { it.reason })
            assertEquals(listOf(PathChangeReason.ActiveMigration), p.changes(c).map { it.reason })
            assertTrue(bytesTo(p, other) > 0)
        } finally {
            p.close()
        }
    }

    @Test fun probeThenMigrateValidatesServerPath() {
        // a path the server first saw through the client's probe (Unknown) is validated once the client moves there; otherwise the 3x budget would throttle it forever
        val (p, c) = connected()
        try {
            val s = p.server()
            c.testInjectPathChallenges = 1
            p.clientSource = other
            p.clientListens += other
            p.step()
            assertEquals(p.clientAddr, s.remoteAddressForTest, "a probe moves nothing")
            assertEquals(2, s.pathCountForTest)
            send(c, 100_000)
            assertTrue(
                p.runUntil(5.seconds) {
                    s.remoteAddressForTest == other &&
                        s.pathState(p.changes(s).first().new) == PathState.Validated
                },
                "the new path is validated after the move: ${p.changes(s).map { s.pathState(it.new) }}",
            )
            val id = s.openStream(true)
            val big = ByteArray(1_000_000)
            var w = 0
            assertTrue(
                p.runUntil(10.seconds) {
                    if (w <
                        big.size
                    ) {
                        w += s.writeStream(id, big, w, minOf(16384, big.size - w), w + minOf(16384, big.size - w) == big.size)
                    }
                    ; w ==
                        big.size &&
                        s.stats.bytesInFlight == 0L
                },
            )
            assertTrue(
                bytesTo(p, other) > 3 * s.stats.pathBytesReceived,
                "no amplification limit on a validated path: sent ${bytesTo(p, other)} received ${s.stats.pathBytesReceived}",
            )
        } finally {
            p.close()
        }
    }

    @Test fun closedPathStateIsClosed() {
        // a path id the connection issued and then closed is Closed, not Unknown (which stays for ids it never issued)
        val (p, c) = connected()
        try {
            val id = c.addPath(p.serverAddr, p.now)
            c.closePath(id)
            assertEquals(PathState.Closed, c.pathState(id))
            assertEquals(PathState.Unknown, c.pathState(PathId(id.value + 1)))
        } finally {
            p.close()
        }
    }

    @Test fun pathStateOfUnknownIdIsUnknown() {
        val (p, _) = connected()
        try {
            assertEquals(PathState.Unknown, p.server().pathState(PathId(9)))
            assertEquals(PathState.Validated, p.server().pathState(PathId.Initial))
        } finally {
            p.close()
        }
    }

    /** A NAT rebind while the server is congestion-window-limited (a download in flight) must still send PATH_CHALLENGE to the new port at once, and the dead old port's probes must not sit on the new path's window. */

    /** A real NAT rebinding: the packets in flight to the old port are lost, the client's next packets come from the new port; the server must recover them (loss detection, the inherited window) and finish the transfer. */
    @Test fun transferSurvivesNatRebindThatLosesPacketsInFlight() {
        val (p, c) = connected()
        try {
            val s = p.server()
            send(s, 400_000)
            p.settle(20) // below the client's stream window: nothing but the network limits the transfer
            val inFlightBefore = s.stats.bytesInFlight
            assertTrue(inFlightBefore >= s.stats.cwnd * 3 / 4, "window-limited before the rebind: $inFlightBefore of ${s.stats.cwnd}")
            // a real NAT rebinding: the old mapping dies, so every packet in flight to the old port is lost, and the client's next packets come from the new port
            val newPort = InetSocketAddress("10.0.0.1", 40002)
            p.clientSource = newPort
            p.clientListens.clear()
            p.clientListens +=
                newPort
            send(c)
            assertTrue(p.runUntil(2.seconds) { s.remoteAddressForTest == newPort }, "switched to the new port")
            val recvAtSwitch = c.stats.bytesReceived
            assertTrue(
                p.runUntil(3.seconds) {
                    c.stats.bytesReceived - recvAtSwitch > 100_000
                },
                "the download resumes on the new path within three seconds: ${c.stats.bytesReceived - recvAtSwitch} bytes (in flight ${s.stats.bytesInFlight} of cwnd ${s.stats.cwnd}, lost ${s.stats.lostPackets}, pto ${s.stats.ptoCount})",
            )
            assertTrue(
                p.runUntil(10.seconds) {
                    c.stats.bytesReceived >= 400_000
                },
                "the whole transfer completes after the rebind (received ${c.stats.bytesReceived}, lost ${s.stats.lostPackets})",
            )
        } finally {
            p.close()
        }
    }

    @Test fun natRebindWhileServerCwndLimitedChallengesNewPortAtOnce() {
        val (p, c) = connected()
        try {
            val s = p.server()
            send(s, 600_000)
            p.settle(20)
            assertTrue(
                s.stats.bytesInFlight >= s.stats.cwnd * 3 / 4,
                "the server is window-limited: in flight ${s.stats.bytesInFlight} of cwnd ${s.stats.cwnd}",
            )
            val newPort = InetSocketAddress("10.0.0.1", 40002)
            val before = p.serverSent.size
            p.clientSource = newPort
            p.clientListens += newPort
            send(c)
            p.settle(3)
            assertTrue(
                p.serverSent.drop(before).any {
                    it.first == newPort
                },
                "a PATH_CHALLENGE reached the new port within three rounds: ${p.serverSent.drop(before).map { it.first }.distinct()}",
            )
            assertTrue(
                p.runUntil(5.seconds) {
                    s.pathState(s.stats.currentPath) == PathState.Validated && s.remoteAddressForTest == newPort
                },
                "the new path validated: ${s.pathState(s.stats.currentPath)} at ${s.remoteAddressForTest}",
            )
            assertTrue(
                p.runUntil(10.seconds) {
                    s.stats.bytesInFlight == 0L
                },
                "the download drains on the new path (state ${s.state}, in flight ${s.stats.bytesInFlight})",
            )
            assertEquals(io.kuicksilver.quic.ConnectionState.Confirmed, s.state)
        } finally {
            p.close()
        }
    }

    /** Interop `rebind-port` against picoquic: the client's NAT mapping changed between its first Initial and the server's answer, so every retransmitted Initial came from a new port while the server kept answering the old one until the handshake timed out (final review follow-up). */
    @Test fun natRebindDuringHandshakeIsFollowedByTheServer() {
        val p = EndpointPair()
        try {
            val c = p.connect()
            p.clientListens.clear()
            p.clientListensOnSource = false // the first answer goes to a mapping that no longer exists
            p.step()
            assertEquals(1, p.server.connectionCount)
            assertTrue(p.sentElsewhere.isNotEmpty(), "the server answered the old port")
            val newPort = InetSocketAddress("10.0.0.1", 40002)
            p.clientSource = newPort
            p.clientListens += newPort
            p.clientListensOnSource =
                true
            assertTrue(
                p.confirmed(c),
                "the handshake completes through the new port (client ${c.state}, server ${p.server.connections().map { it.state }})",
            )
            assertEquals(1L, p.server.stats.connectionsCreated, "one connection, one handshake")
            assertEquals(newPort, p.server().remoteAddressForTest)
            val first =
                p.serverSent
                    .first {
                        it.first == newPort
                    }.second // the interop runner checks that the first server packet on a new path is a PATH_CHALLENGE
            assertTrue(
                first[0].toInt() and 0x80 == 0 && first.size >= 1200,
                "the first datagram to the new port is a 1-RTT probe expanded to 1200 bytes (${first.size} bytes, first byte ${first[0]})",
            )
            assertTrue(
                p.runUntil(2.seconds) { p.server().pathState(p.server().stats.currentPath) == PathState.Validated },
                "the new address validates",
            )
        } finally {
            p.close()
        }
    }

    private fun EndpointPair.rebindDuringHandshake(newPort: InetSocketAddress): ConnectionCore {
        val c = connect()
        clientListens.clear()
        clientListensOnSource = false
        step() // the first answer goes to a mapping that no longer exists
        clientSource = newPort
        clientListens += newPort
        clientListensOnSource = true
        return c
    }

    private fun isProbe(bytes: ByteArray): Boolean =
        // a PATH_CHALLENGE / PATH_RESPONSE datagram: short header expanded to 1200 bytes
        bytes[0].toInt() and 0x80 == 0 && bytes.size >= 1200

    /** picoquic drops a 1-RTT PATH_CHALLENGE that arrives before it holds the keys: the server repeats it (same data) until answered, and the Handshake packet alone does not stop that. */
    @Test fun handshakeTimeChallengeIsRepeatedUntilTheClientCanAnswer() {
        val p = EndpointPair()
        try {
            val newPort = InetSocketAddress("10.0.0.1", 40002)
            val c = p.rebindDuringHandshake(newPort)
            var dropped = false
            p.filterToClient = { _, b ->
                if (!dropped && isProbe(b)) {
                    dropped = true
                    false
                } else {
                    true
                }
            }
            assertTrue(p.confirmed(c))
            val s = p.server()
            assertTrue(p.runUntil(3.seconds) { s.pathState(s.stats.currentPath) == PathState.Validated }, "the new address validates")
            assertTrue(dropped, "the first probe was dropped")
            assertTrue(
                s.challengedAddressesForTest.count { it == newPort } >= 2,
                "the challenge was repeated: ${s.challengedAddressesForTest}",
            )
            assertTrue(p.events[s]!!.any { it is ConnectionEvent.PathValidated }, "validated by a PATH_RESPONSE")
            assertEquals(1L, p.server.stats.connectionsCreated)
        } finally {
            p.close()
        }
    }

    /** A client that never answers the handshake-time challenge: the Handshake packet already validated the address (RFC 9000 section 8.1), so the deadline settles the path instead of closing the connection. */
    @Test fun unansweredHandshakeTimeChallengeDoesNotCloseTheConnection() {
        val p = EndpointPair()
        try {
            val newPort = InetSocketAddress("10.0.0.1", 40002)
            val c = p.rebindDuringHandshake(newPort)
            p.filterToServer = { _, b -> !isProbe(b) } // every PATH_RESPONSE is lost
            assertTrue(p.confirmed(c))
            val s = p.server()
            assertTrue(
                p.runUntil(10.seconds) {
                    s.pathState(s.stats.currentPath) == PathState.Validated
                },
                "the path settles (${s.pathState(s.stats.currentPath)})",
            )
            assertNull(p.closed(c))
            assertEquals(io.kuicksilver.quic.ConnectionState.Confirmed, s.state)
            send(s, 50_000)
            assertTrue(
                p.runUntil(5.seconds) { s.stats.bytesInFlight == 0L && c.stats.bytesReceived > 50_000 },
                "data flows on the settled path",
            )
        } finally {
            p.close()
        }
    }

    /** The rebind lands on the client's Finished flight (interop JVM runs): the first datagram to the new port is the PATH_CHALLENGE, not a DPLPMTUD probe. */
    @Test fun natRebindOnTheClientsFinishedChallengesBeforePmtuProbes() {
        val df =
            io.kuicksilver.quic.IoCapabilities(
                ecnSend = false,
                ecnReceive = false,
                gsoMaxSegments = 1,
                gro = false,
                df = true,
                batch = 1,
            )
        val p = EndpointPair()
        try {
            p.onServerCreated = { it.setPathCapabilities(PathId.Initial, df) }
            val c = p.connect()
            c.setPathCapabilities(PathId.Initial, df)
            p.step() // the server's flight reached the client; its Finished leaves from the new port
            val newPort = InetSocketAddress("10.0.0.1", 40002)
            p.clientSource = newPort
            p.clientListens.clear()
            p.clientListens +=
                newPort
            assertTrue(p.confirmed(c))
            val s = p.server()
            val first = p.serverSent.first { it.first == newPort }.second
            assertTrue(
                isProbe(first) && first.size == 1200,
                "the first datagram to the new port is the 1200-byte PATH_CHALLENGE probe, not a PMTU probe (${first.size} bytes)",
            )
            assertTrue(p.runUntil(3.seconds) { s.pathState(s.stats.currentPath) == PathState.Validated })
            assertEquals(newPort, s.remoteAddressForTest)
        } finally {
            p.close()
        }
    }

    private fun dcidOf(datagram: ByteArray): io.kuicksilver.quic.wire.ConnectionId =
        io.kuicksilver.quic.wire
            .ConnectionId(datagram.copyOfRange(1, 9))

    /** RFC 9000 section 9.5: a probe on a new path never carries the connection ID the active path uses, on either side. */
    @Test fun probeUsesUnusedPeerCid() {
        val (p, c) = connected()
        try {
            val s = p.server()
            val id = c.addPath(p.serverAddr, p.now)
            p.clientSocketSources[id] = other
            p.clientListens += other
            val clientProbes = ArrayList<ByteArray>()
            val serverAnswers = ArrayList<ByteArray>()
            p.filterToServer =
                { _, b ->
                    if (io.kuicksilver.quic
                            .nullOneRttFrames(b)
                            ?.any { it is io.kuicksilver.quic.TestFrame.PathChallenge } ==
                        true
                    ) {
                        clientProbes += b
                    }
                    ; true
                }
            p.filterToClient =
                { _, b ->
                    if (io.kuicksilver.quic
                            .nullOneRttFrames(b)
                            ?.any { it is io.kuicksilver.quic.TestFrame.PathResponse } ==
                        true
                    ) {
                        serverAnswers += b
                    }
                    ; true
                }
            c.probePath(id, p.now)
            assertTrue(p.runUntil(5.seconds) { c.pathState(id) == PathState.Validated }, "probe answered: ${c.pathState(id)}")
            assertTrue(clientProbes.isNotEmpty() && serverAnswers.isNotEmpty())
            for (d in clientProbes) {
                assertNotEquals(
                    c.remoteCid,
                    dcidOf(d),
                    "the client's probe on the new socket uses another of the server's IDs",
                )
            }
            val serverIds = (0L..7L).mapNotNull { s.cids.localForTest(it)?.cid }
            for (d in clientProbes) assertTrue(dcidOf(d) in serverIds, "a connection ID the server issued")
            for (d in serverAnswers) {
                assertNotEquals(
                    s.remoteCid,
                    dcidOf(d),
                    "the server's PATH_RESPONSE to the new address uses another of the client's IDs",
                )
            }
            c.switchPath(id, p.now)
            send(c)
            p.settle(5)
            assertEquals(other, s.remoteAddressForTest)
            assertNull(p.closed(c))
            assertNull(p.closed(s))
        } finally {
            p.close()
        }
    }

    /** A path evicted to make room for a fifth address frees its queued PATH_RESPONSE slots, as closePath does; otherwise three evictions fill the queue for good. */
    @Test fun evictedPathFreesResponseSlots() {
        val paths = Paths(Path(PathId.Initial, InetSocketAddress("10.0.0.1", 1), PathId.Initial, NewReno(), 333.milliseconds))
        val probed =
            (1..3).map { i ->
                paths.add(PathId.Initial, InetSocketAddress("10.0.1.$i", 1), NewReno(), 333.milliseconds)!!.also {
                    assertTrue(paths.queueResponse(i.toLong(), it))
                }
            }
        val fifth = paths.add(PathId.Initial, InetSocketAddress("10.0.2.1", 1), NewReno(), 333.milliseconds)
        assertTrue(fifth != null, "a path was evicted for the new address")
        val evicted = probed.single { it.state == PathState.Closed }
        assertFalse(paths.hasResponseFor(evicted), "no response is left for the evicted path")
        assertEquals(2, paths.responses)
        assertTrue(paths.queueResponse(9, fifth!!), "its slot is free again")
    }

    /** A probe that was sent on a path closed since then and is declared lost must not reach the active path's congestion controller (RFC 9000 section 9.4). */
    @Test fun lostProbeOnClosedPathDoesNotTouchActiveCwnd() {
        val (p, c) = connected(clientQuic = quicConfig { congestionController = { NewReno() } })
        try {
            val cwnd = c.stats.cwnd
            val lostBefore = c.stats.lostPackets
            val id = c.addPath(p.serverAddr, p.now)
            p.clientSocketSources[id] = other
            p.clientListens += other
            p.filterToServer =
                { _, b ->
                    io.kuicksilver.quic.nullOneRttFrames(b)?.none {
                        it is io.kuicksilver.quic.TestFrame.PathChallenge
                    } ?: true
                } // the probe never arrives
            c.probePath(id, p.now)
            p.step()
            c.closePath(id)
            repeat(30) {
                send(c, 200)
                p.step()
            } // a little application-limited traffic on the active path: its window does not grow, and later ACKs declare the probe lost
            assertTrue(c.stats.lostPackets > lostBefore, "the probe was declared lost")
            assertEquals(cwnd, c.stats.cwnd, "the active window is untouched by the closed path's loss")
        } finally {
            p.close()
        }
    }

    /**
     * The handshake-time rebind follow (kept for picoquic interop) must not let anyone who saw the client's Initial move the path. Initial keys
     * are public, so an Initial from a third address while the client's own address is alive (something arrived from it within one PTO) is processed but
     * not followed; with allowMigration = false no handshake packet moves the path.
     */
    @Test fun forgedInitialFromThirdAddressDoesNotMovePath() {
        val attacker = InetSocketAddress("10.0.0.66", 6666)
        val p = EndpointPair()
        try {
            var forged: ByteArray? = null
            p.filterToServer =
                { _, b ->
                    if (forged == null &&
                        b[0].toInt() and 0xf0 == 0xc0
                    ) {
                        forged =
                            b.copyOf().also { f ->
                                val off =
                                    1 + 4 + 1 + (f[5].toInt() and 0xff)
                                val pnOff =
                                    off + 1 + (f[off].toInt() and 0xff) + 1 + 2
                                f[pnOff + (f[0].toInt() and 0x03)] = 0x33
                            }
                    }
                    ; true
                } // the client's first Initial with a fresh packet number (Null crypto: the header is plaintext)
            val c = p.connect()
            p.step()
            val s = p.server.connections().single()
            p.feed(p.server, forged!!, attacker)
            assertEquals(p.clientAddr, s.remoteAddressForTest, "a forged Initial from a third address does not move a live path")
            assertTrue(p.confirmed(c))
            assertEquals(p.clientAddr, s.remoteAddressForTest)
            assertEquals(
                0,
                p.serverSent.count {
                    it.first ==
                        attacker
                },
                "nothing went to the attacker",
            )
        } finally {
            p.close()
        }
        val q = EndpointPair(serverQuic = quicConfig { allowMigration = false })
        try {
            val newPort = InetSocketAddress("10.0.0.1", 40002)
            q.rebindDuringHandshake(newPort)
            q.runUntil(3.seconds) { false }
            assertEquals(
                q.clientAddr,
                q.server().remoteAddressForTest,
                "allowMigration = false: the handshake does not follow a new address either",
            )
        } finally {
            q.close()
        }
    }

    /** Native interop: a client connects to a host name (resolved once at connect) and the socket reports the peer by its IP literal; Kotlin/Native's InetSocketAddress compares strings, so every datagram looked like an unknown server address and was dropped. Paths compare the IP bytes. */
    @Test fun byRemoteMatchesAHostNameAgainstItsIpLiteral() {
        val paths = Paths(Path(PathId.Initial, InetSocketAddress("::1", 4433), PathId.Initial, NewReno(), 333.milliseconds))
        assertTrue(
            paths.byRemote(PathId.Initial, InetSocketAddress("0:0:0:0:0:0:0:1", 4433)) != null,
            "two spellings of one IPv6 address are one peer",
        )
        assertNull(paths.byRemote(PathId.Initial, InetSocketAddress("::1", 4434)), "another port is another path")
        assertNull(paths.byRemote(PathId.Initial, InetSocketAddress("::2", 4433)), "another address is another path")
    }
}
