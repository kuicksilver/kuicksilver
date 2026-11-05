// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.Bbr
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
import kotlin.test.assertNotNull
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertSame
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

    /**
     * Starts a [bytes] download from [s] and loses one of its first datagrams, so the server's controller leaves slow start with a
     * window that one pacing burst fills: this harness acknowledges within a step, so without a loss the burst (ten datagrams),
     * not the window, limits the sender. (The server's 0.5-RTT flight used to be lost the same way before the client replayed it.)
     */
    private fun EndpointPair.windowLimitedDownload(
        s: ConnectionCore,
        bytes: Int,
    ) {
        val lost = sentToClient + 1
        filterToClient = { i, _ -> i != lost }
        send(s, bytes)
        settle(20)
        filterToClient = { _, _ -> true }
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

    /**
     * RFC 9000 section 9: a path is the 4-tuple. A server on a wildcard socket learns which of its addresses the client sent to
     * ([io.kuicksilver.quic.PacketBatch.localAddress]) and every datagram of the connection, from the first flight on, names that
     * address as its source: on a multi-address host or a VIP the client hears back from the address it chose.
     */
    @Test fun serverRepliesFromTheLocalAddressTheClientUsed() {
        val vip = InetSocketAddress("192.0.2.10", 443)
        val p = EndpointPair()
        try {
            p.serverLocal = vip
            val c = p.connect()
            assertTrue(p.confirmed(c))
            send(c, 3000)
            p.settle(10)
            assertTrue(p.serverSentLocal.isNotEmpty())
            assertTrue(p.serverSentLocal.all { it == vip }, "every server datagram leaves from $vip: ${p.serverSentLocal.toSet()}")
            assertEquals(
                vip,
                p
                    .server()
                    .paths.active.local,
            )
            assertTrue(p.changes(p.server()).isEmpty(), "the same 4-tuple: no path change")
        } finally {
            p.close()
        }
    }

    /** Where the socket cannot tell (the portable sockets, a specific bind) nothing names a source: the socket's own address is used. */
    @Test fun noLocalAddressWithoutTheSocketReportingIt() {
        val (p, c) = connected()
        try {
            send(c, 3000)
            p.settle(10)
            assertTrue(p.serverSentLocal.all { it == null }, "no source named: ${p.serverSentLocal.toSet()}")
            assertNull(
                p
                    .server()
                    .paths.active.local,
            )
        } finally {
            p.close()
        }
    }

    /**
     * Only a client migrates, and a client discards packets from a server address it did not send to (RFC 9000 section 9), so datagrams of the same client address reaching another of the server's addresses are no reason to answer from there:
     * an off-path attacker's copy sent to that address would otherwise move the server to an address the client drops, stalling the
     * connection. The local end of a path is fixed when the path is made (as quinn-proto's `FourTuple::local_ip` and quic-go's
     * `sendConn` packet info): such datagrams are processed on the existing path and every answer keeps leaving from its address,
     * whether migration is allowed or not.
     */
    @Test fun negative_datagramsToAnotherLocalAddressDoNotMoveTheServer() {
        for (allow in listOf(true, false)) {
            val a = InetSocketAddress("192.0.2.10", 443)
            val b = InetSocketAddress("192.0.2.11", 443)
            val p = EndpointPair(serverQuic = io.kuicksilver.quic.quicConfig { allowMigration = allow })
            try {
                p.serverLocal = a
                val c = p.connect()
                assertTrue(p.confirmed(c))
                p.settle()
                val s = p.server()
                val sentBefore = p.serverSentLocal.size
                p.serverLocal = b // the client's own packets, or an attacker's copies of them, now reach address b
                send(c, 3000)
                p.settle(10)
                assertTrue(p.changes(s).isEmpty(), "allowMigration=$allow: no path change: ${p.changes(s).map { it.reason }}")
                assertEquals(1, s.paths.all.size, "allowMigration=$allow: no second path")
                assertEquals(a, s.paths.active.local)
                val after = p.serverSentLocal.drop(sentBefore)
                assertTrue(
                    after.isNotEmpty() && after.all { it == a },
                    "allowMigration=$allow: every answer still from $a: ${after.toSet()}",
                )
                assertTrue(s.stats.bytesReceived > 3000, "the data was processed on the existing path")
            } finally {
                p.close()
            }
        }
    }

    /**
     * A real move of the client (here a NAT rebinding: a new port) opens a path whose local end is the address its first datagram
     * reached; when that is another address of ours, the path never gets the connection ID the old address used (RFC 9000 section
     * 9.5: "MUST NOT reuse a connection ID when sending from more than one local address").
     */
    @Test fun aNewClientAddressTakesTheLocalAddressItsDatagramReached() {
        val a = InetSocketAddress("192.0.2.10", 443)
        val b = InetSocketAddress("192.0.2.11", 443)
        val p = EndpointPair()
        try {
            p.serverLocal = a
            val c = p.connect()
            assertTrue(p.confirmed(c))
            p.settle()
            val s = p.server()
            val sentBefore = p.serverSent.size
            p.serverLocal = b
            p.clientSource = InetSocketAddress("10.0.0.1", 40001)
            p.clientListens += p.clientSource
            send(c)
            p.settle(10)
            assertEquals(listOf(PathChangeReason.NatRebinding), p.changes(s).map { it.reason })
            assertEquals(p.clientSource, s.paths.active.remote)
            assertEquals(b, s.paths.active.local)
            assertEquals(b, p.serverSentLocal.last())
            val len = c.localCid.length

            fun dcid(i: Int) =
                p.serverSent[i]
                    .second
                    .copyOfRange(1, 1 + len)
                    .toList()

            fun shortFrom(l: InetSocketAddress) =
                p.serverSentLocal.indices.filter { p.serverSentLocal[it] == l && p.serverSent[it].second[0].toInt() and 0x80 == 0 }
            val fromA = shortFrom(a).map { dcid(it) }.toSet()
            val fromB = shortFrom(b).filter { it >= sentBefore }.map { dcid(it) }.toSet()
            assertTrue(fromA.isNotEmpty() && fromB.isNotEmpty())
            assertTrue(fromA.intersect(fromB).isEmpty(), "no connection ID from both local addresses")
        } finally {
            p.close()
        }
    }

    /** A new client address whose datagram's destination the socket could not tell (family 0) keeps the server's current source. */
    @Test fun aNewClientAddressWithAnUnknownDestinationKeepsTheServersSource() {
        val a = InetSocketAddress("192.0.2.10", 443)
        val p = EndpointPair()
        try {
            p.serverLocal = a
            val c = p.connect()
            assertTrue(p.confirmed(c))
            p.settle()
            val s = p.server()
            p.serverLocal = null
            p.clientSource = InetSocketAddress("10.0.0.1", 40001)
            p.clientListens += p.clientSource
            send(c)
            p.settle(10)
            assertEquals(listOf(PathChangeReason.NatRebinding), p.changes(s).map { it.reason })
            assertEquals(a, s.paths.active.local)
            assertEquals(a, p.serverSentLocal.last())
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

    /**
     * Found by the stateful connection fuzzer (`connectionNull`): every PATH_CHALLENGE the server sent was appended to a
     * test-only record that nothing trimmed, so forged copies from ever new addresses grew the connection's memory without
     * bound. The record keeps the latest [ConnectionCore.TEST_RECORD_LIMIT] entries.
     */
    @Test fun negative_challengeRecordStaysBoundedUnderForgedAddresses() {
        val (p, c) = connected()
        try {
            val s = p.server()
            repeat(100) { i ->
                val attacker = InetSocketAddress("10.0.1.${i % 250}", 7000 + i)
                var copied = false
                p.filterToServer = { _, b ->
                    if (!copied && b[0].toInt() and 0x80 == 0) {
                        copied = true
                        p.feed(p.server, b, attacker)
                    }
                    true
                }
                send(c)
                p.settle(3)
            }
            assertTrue(s.pathChallengesSentForTest > ConnectionCore.TEST_RECORD_LIMIT, "challenges sent: ${s.pathChallengesSentForTest}")
            assertTrue(
                s.challengedAddressesForTest.size <= ConnectionCore.TEST_RECORD_LIMIT,
                "challenge record: ${s.challengedAddressesForTest.size}",
            )
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

    @Test fun validationTimeoutFollowsInitialRtt() {
        // RFC 9000 section 8.2.4 with initialRtt = 100 ms: max(3 x PTO, 6 x 100 ms) — the 20 ms pair's 3 x PTO is below 600 ms
        val (p, c) = connected(serverQuic = quicConfig { initialRtt = 100.milliseconds })
        try {
            p.clientListensOnSource = false
            val s = p.server()
            assertEquals(maxOf(s.pto() * 3, 600.milliseconds), s.validationTimeout())
            assertEquals(600.milliseconds, s.validationTimeout())
            p.clientSource = other
            send(c)
            p.step()
            val t0 = p.now
            assertTrue(p.runUntil(5.seconds) { p.events[s]!!.any { it is ConnectionEvent.PathFailed } })
            val took = p.now - t0
            assertTrue(took >= 590.milliseconds && took <= 900.milliseconds, "validation failed after $took")
        } finally {
            p.close()
        }
    }

    @Test fun pathChallengeRepeatsBackOff() {
        // RFC 9000 section 8.2.1 and RFC 9002 section 6.2.1: an unanswered PATH_CHALLENGE is repeated after 1 PTO twice (three
        // attempts inside the 3 x PTO validation timeout, as quic-go), then with an exponentially growing gap, not once per PTO
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
            assertEquals(g1, g2, "the second repeat follows after the same PTO")
            val t2 = path.nextChallengeAt
            c.onTimeout(t2)
            val g3 = path.nextChallengeAt - t2
            assertTrue(g3 >= g2 * 2, "third gap $g3 is at least twice the second $g2")
            val t3 = path.nextChallengeAt
            if (path.state == PathState.Validating) {
                c.onTimeout(t3)
                val g4 = path.nextChallengeAt - t3
                if (path.state == PathState.Validating) assertTrue(g4 >= g3 * 2, "fourth gap $g4 is at least twice the third $g3")
            }
        } finally {
            p.close()
        }
    }

    /**
     * Review finding 10, RFC 9000 section 8.2.1: "The endpoint MUST use unpredictable data in every PATH_CHALLENGE frame", and section
     * 13.3: "PATH_CHALLENGE frames include a different payload each time they are sent." Repeats carried the first data again; a
     * late PATH_RESPONSE to an earlier challenge of the same validation still validates the path.
     */
    @Test fun everyPathChallengeRepeatCarriesFreshData() {
        val (p, c) = connected()
        val batch = io.kuicksilver.quic.PacketBatch(16)
        try {
            val id = c.addPath(p.serverAddr, p.now)
            c.probePath(id, p.now)
            val path = c.paths.byId(id)!!
            c.poll(batch, p.now)
            repeat(3) {
                val t = path.nextChallengeAt
                c.onTimeout(t)
                batch.clear()
                c.poll(batch, t)
            }
            val sent = c.challengeDataSentForTest.toList()
            assertEquals(4, sent.size, "four PATH_CHALLENGEs: $sent")
            assertEquals(sent.size, sent.toSet().size, "each one carries new data: $sent")
            assertEquals(PathState.Validating, path.state)
            c.onPathResponse(sent.first())
            assertEquals(PathState.Validated, path.state, "a response to the first challenge of the validation is accepted")
        } finally {
            batch.close()
            p.close()
        }
    }

    /**
     * Review finding 26, RFC 9000 section 9.5: "An endpoint SHOULD NOT initiate migration with a peer that has requested a zero-length
     * connection ID, because traffic over the new path might be trivially linkable to traffic over the old one."
     */
    @Test fun noMigrationToAZeroLengthCidServer() {
        val (p, c) = connected()
        try {
            c.remoteCid = io.kuicksilver.quic.wire.ConnectionId.EMPTY // as from a server whose Source Connection ID was empty
            val e = kotlin.test.assertFailsWith<IllegalStateException> { c.addPath(p.serverAddr, p.now) }
            assertTrue("zero-length" in (e.message ?: ""), e.message)
            assertEquals(1, c.paths.all.size)
        } finally {
            p.close()
        }
    }

    /**
     * Review finding 8, RFC 9000 section 8.2.1: "When an endpoint is unable to expand the datagram size to 1200 bytes due to the
     * anti-amplification limit, the path MTU will not be validated. To ensure that the path MTU is large enough, the endpoint MUST
     * perform a second path validation by sending a PATH_CHALLENGE frame in a datagram of at least 1200 bytes." A NAT rebinding
     * whose first packet was a small ACK left the server a budget below 1200 bytes, and the one small challenge validated the path.
     */
    @Test fun amplificationLimitedChallengeIsFollowedByAFullSizeOne() {
        val (p, c) = connected()
        try {
            val s = p.server()
            val rebound = InetSocketAddress("10.0.0.1", 40003)
            p.clientSource = rebound
            p.clientListens += rebound
            send(s, 100) // the client's first packet from the new port is the ACK for this
            val sentBefore = p.serverSent.size
            assertTrue(
                p.runUntil(3.seconds) { s.remoteAddressForTest == rebound && s.pathState(s.stats.currentPath) == PathState.Validated },
            )
            p.settle(10)
            val challenges =
                p.serverSent
                    .drop(sentBefore)
                    .filter { (to, b) ->
                        to == rebound &&
                            io.kuicksilver.quic
                                .nullOneRttFrames(b)
                                ?.any { it is io.kuicksilver.quic.TestFrame.PathChallenge } == true
                    }.map { it.second.size }
            assertTrue(challenges.isNotEmpty() && challenges.first() < 1200, "the first challenge is amplification-limited: $challenges")
            assertTrue(challenges.any { it >= 1200 }, "a second validation in a datagram of at least 1200 bytes: $challenges")
            val firstFull = challenges.indexOfFirst { it >= 1200 }
            assertTrue(firstFull > 0, "after the small one: $challenges")
            assertNull(p.closed(s))
        } finally {
            p.close()
        }
    }

    @Test fun newPathGetsThreeChallengesBeforeDeadline() {
        // RFC 9000 section 8.2.4: three PATH_CHALLENGEs (at 0, 1 and 2 PTO) go out before the 3 x PTO validation timeout
        // a 1 ms initialRtt keeps the 6 x initialRtt floor out of the way: the deadline is 3 x PTO
        val (p, c) = connected(clientQuic = quicConfig { initialRtt = 1.milliseconds })
        try {
            assertEquals(c.pto() * 3, c.validationTimeout())
            val id = c.addPath(p.serverAddr, p.now)
            c.probePath(id, p.now)
            val path = c.paths.byId(id)!!
            val deadline = path.challengeDeadline
            var attempts = 1
            while (path.state == PathState.Validating && path.nextChallengeAt < deadline) {
                c.onTimeout(path.nextChallengeAt)
                attempts++
            }
            assertTrue(attempts >= 3, "$attempts PATH_CHALLENGEs before the validation deadline")
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

    /**
     * A client that moves four times before any of its new addresses could answer (each old NAT mapping dies at once) fills
     * every path slot with validations of dead addresses; RFC 9000 section 8.2.4 lets a migration abandon those, so the newest address
     * still becomes the active path and validates.
     */
    @Test fun rapidMigrationsKeepTheNewestPath() {
        val (p, c) = connected()
        try {
            val s = p.server()
            val newest = InetSocketAddress("10.0.4.1", 40000)
            p.clientListens.clear()
            p.clientListensOnSource = false
            p.clientListens += newest // only the last mapping is alive
            for (i in 1..4) {
                p.clientSource = InetSocketAddress("10.0.$i.1", 40000)
                send(c)
                repeat(10) { p.step() }
            }
            assertTrue(
                p.runUntil(2.seconds) { s.remoteAddressForTest == newest && s.pathState(s.stats.currentPath) == PathState.Validated },
                "the newest address is the validated active path (server at ${s.remoteAddressForTest}, paths ${s.paths.all})",
            )
            assertTrue(s.pathCountForTest <= 4)
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

    /**
     * Review finding 23, RFC 9000 section 9.5: "an endpoint MUST NOT reuse a connection ID when sending to more than one destination
     * address"; it MAY keep the current one only for a peer whose packets from the new address carry the same Destination Connection
     * ID (a NAT rebinding). A server without a spare ID of the client answered a deliberate migration (a new DCID) with its current
     * ID, linking both paths; it now sends nothing there until the client gives it a new ID (as ngtcp2's CONN_ID_BLOCKED).
     */
    @Test fun serverWithoutSpareCidDoesNotReuseItTowardAMigratingClient() {
        val (p, c) = connected()
        try {
            val s = p.server()
            for (seq in 1L..7L) s.cids.markUsedForTest(seq) // every spare ID of the client is spent
            assertTrue(!s.cids.hasSparePeerForTest)
            val id = c.addPath(p.serverAddr, p.now)
            p.clientSocketSources[id] = other
            p.clientListens += other
            c.probePath(id, p.now)
            p.runUntil(3.seconds) { c.pathState(id) != PathState.Validating }
            val toOther = p.serverSent.filter { it.first == other }.map { it.second }
            for (d in toOther) assertNotEquals(s.remoteCid, dcidOf(d), "the server's current ID toward the new address links the paths")
            assertNull(p.closed(s))
        } finally {
            p.close()
        }
    }

    /**
     * Review finding 23: the ID a server answers a client's probe with stays with that path once it is validated, so the client's
     * switch there right after (QuicConnection.migrate) does not need one more spare ID of the client.
     */
    @Test fun serverKeepsTheProbedPathsCidForTheSwitch() {
        val (p, c) = connected()
        try {
            val s = p.server()
            val id = c.addPath(p.serverAddr, p.now)
            p.clientSocketSources[id] = other
            p.clientListens += other
            c.probePath(id, p.now)
            assertTrue(p.runUntil(5.seconds) { c.pathState(id) == PathState.Validated }, "probe answered: ${c.pathState(id)}")
            val probed = s.paths.all.single { it.remote == other }
            val held = assertNotNull(probed.peerCid, "the server path keeps the client ID it answered with")
            for (seq in 0L..7L) s.cids.markUsedForTest(seq) // no spare left for the switch itself
            c.switchPath(id, p.now)
            send(c)
            p.settle(5)
            assertEquals(other, s.remoteAddressForTest, "the server followed the client")
            assertEquals(held.cid, s.remoteCid, "with the ID the probed path held")
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
            p.windowLimitedDownload(s, 400_000) // below the client's stream window: nothing but the network limits the transfer
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
            p.windowLimitedDownload(s, 600_000)
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

    /**
     * Review finding 25, RFC 9000 section 9.3: "An endpoint only changes the address to which it sends packets in response to the
     * highest-numbered non-probing packet", so reordered packets do not send it back to an old address. During the handshake the
     * server followed every Handshake packet from another address, a delayed older one included. (Null protection: the packet
     * number, payload and tag of a captured Handshake packet can be rewritten in place.)
     */
    @Test fun handshakeTimeRebindIgnoresAnOlderPacketFromTheOldAddress() {
        val p = EndpointPair()
        var held: ByteArray? = null
        val hv =
            io.kuicksilver.quic.wire
                .PacketHeaderView()

        fun handshakePacketOf(d: ByteArray): IntArray? {
            val b = PacketBuffer.of(d)
            try {
                var off = 0
                while (off < d.size &&
                    io.kuicksilver.quic.wire.PacketHeaderCodec
                        .parse(b, off, d.size, 8, hv)
                ) {
                    if (d[off].toInt() and 0x80 != 0 &&
                        (d[off].toInt() and 0x30) ushr 4 == 2
                    ) {
                        return intArrayOf(off, hv.pnOffset, hv.packetEnd)
                    }
                    off = hv.packetEnd
                }
                return null
            } finally {
                b.close()
            }
        }
        p.filterToServer = { _, b ->
            if (handshakePacketOf(b) != null) {
                if (held == null) held = b
                false // the server sees no client Handshake packet: it stays in the handshake
            } else {
                true
            }
        }
        try {
            val c = p.connect()
            assertTrue(p.runUntil(2.seconds) { held != null })
            val s = p.server()
            assertEquals(io.kuicksilver.quic.ConnectionState.Handshaking, s.state)
            val d = held!!
            val (off, pnOff, end) = handshakePacketOf(d)!!

            // the client's Handshake packet [pn], PING and padding only (no CRYPTO: the handshake stays open)
            fun forged(pn: Int): ByteArray {
                val pkt = d.copyOfRange(off, end)
                val pnLen = (pkt[0].toInt() and 0x03) + 1
                val at = pnOff - off
                for (i in 0 until pnLen) pkt[at + i] = ((pn ushr (8 * (pnLen - 1 - i))) and 0xff).toByte()
                for (i in at + pnLen until pkt.size) pkt[i] = 0
                pkt[at + pnLen] = 0x01
                for (i in 0 until 8) pkt[pkt.size - 8 + i] = ((pn.toLong() ushr (8 * (7 - i))) and 0xff).toByte() // the Null tag
                return pkt
            }
            val newPort = InetSocketAddress("10.0.0.1", 40002)

            fun deliver(
                bytes: ByteArray,
                from: InetSocketAddress,
            ) {
                val b = PacketBuffer.of(bytes)
                try {
                    p.server.handleDatagram(b, bytes.size, from, io.kuicksilver.quic.Ecn.NotEct, p.now)
                } finally {
                    b.close()
                }
            }
            deliver(forged(10), newPort)
            assertEquals(newPort, s.remoteAddressForTest, "the server follows the newest Handshake packet")
            deliver(forged(9), p.clientAddr) // sent before the rebinding, delayed in the network
            assertEquals(newPort, s.remoteAddressForTest, "an older packet from the old address does not move it back")
            assertNull(p.closed(s))
            assertTrue(c.state != io.kuicksilver.quic.ConnectionState.Closed)
        } finally {
            p.close()
        }
    }

    /**
     * Review of dbf26e67: an attacker alternates a raced copy of a client Handshake packet from a spoofed address with the client's
     * next packet from its own address. Each copy moves the path (provisionally) and each genuine packet restores it; a restore that
     * resent every space at once would answer every pair with the whole outstanding flight. Only the first restore of a connection
     * (and the deadline's revert) resends at once; later ones leave it to the PTO, so the pairs cost ACKs, not flights.
     */
    @Test fun negative_alternatingCopiesDoNotResendTheFlightEachTime() {
        val p = EndpointPair()
        var held: ByteArray? = null
        val hv =
            io.kuicksilver.quic.wire
                .PacketHeaderView()

        fun handshakePacketOf(d: ByteArray): IntArray? {
            val b = PacketBuffer.of(d)
            try {
                var off = 0
                while (off < d.size &&
                    io.kuicksilver.quic.wire.PacketHeaderCodec
                        .parse(b, off, d.size, 8, hv)
                ) {
                    if (d[off].toInt() and 0x80 != 0 &&
                        (d[off].toInt() and 0x30) ushr 4 == 2
                    ) {
                        return intArrayOf(off, hv.pnOffset, hv.packetEnd)
                    }
                    off = hv.packetEnd
                }
                return null
            } finally {
                b.close()
            }
        }
        p.filterToServer = { _, b ->
            if (handshakePacketOf(b) != null) {
                if (held == null) held = b
                false // the server sees no client Handshake packet but the forged ones below: it stays in the handshake
            } else {
                true
            }
        }
        try {
            p.connect()
            assertTrue(p.runUntil(2.seconds) { held != null })
            val s = p.server()
            val d = held!!
            val (off, pnOff, end) = handshakePacketOf(d)!!

            // the client's Handshake packet [pn], PING and padding only (no CRYPTO: the handshake stays open)
            fun forged(pn: Int): ByteArray {
                val pkt = d.copyOfRange(off, end)
                val pnLen = (pkt[0].toInt() and 0x03) + 1
                val at = pnOff - off
                for (i in 0 until pnLen) pkt[at + i] = ((pn ushr (8 * (pnLen - 1 - i))) and 0xff).toByte()
                for (i in at + pnLen until pkt.size) pkt[i] = 0
                pkt[at + pnLen] = 0x01
                for (i in 0 until 8) pkt[pkt.size - 8 + i] = ((pn.toLong() ushr (8 * (7 - i))) and 0xff).toByte() // the Null tag
                return pkt
            }
            val attacker = InetSocketAddress("10.9.9.9", 4444)
            var fromAttacker = 0L
            var toAttacker = 0L

            fun deliver(
                bytes: ByteArray,
                from: InetSocketAddress,
            ): Long {
                p.feedNoAdmit(p.server, bytes, from)
                if (from == attacker) fromAttacker += bytes.size
                var toClient = 0L
                while (true) {
                    p.batch.clear()
                    val n = s.poll(p.batch, p.now)
                    if (n == 0) break
                    for (i in 0 until n) {
                        val len = p.batch.length(i)
                        if (p.batch.address(i) == attacker) toAttacker += len else toClient += len
                    }
                }
                return toClient
            }
            deliver(forged(5), p.clientAddr) // from the client's own address, where the whole flight went: validated
            assertTrue(s.paths.active.amplification.validated)
            var first = 0L
            var later = 0L
            val pairs = 20
            for (k in 0 until pairs) {
                deliver(forged(10 + 2 * k), attacker)
                assertEquals(attacker, s.remoteAddressForTest, "the copy moves the path (pair $k)")
                val back = deliver(forged(11 + 2 * k), p.clientAddr)
                assertEquals(p.clientAddr, s.remoteAddressForTest, "the client's newer packet takes it back (pair $k)")
                if (k == 0) first = back else later += back
            }
            assertEquals(1, s.handshakeResendsAtOnceForTest, "only the first restore resends at once")
            assertTrue(
                later <= (pairs - 1) * 100L,
                "$later bytes to the client over ${pairs - 1} further pairs (the first restore sent $first)",
            )
            assertTrue(toAttacker <= 3 * fromAttacker, "$toAttacker bytes to the spoofed address for $fromAttacker received from it")
        } finally {
            p.close()
        }
    }

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

    /** A client whose ClientHello spans two Initial datagrams (ksl's, with an ML-KEM key share): its flights, polled by hand. */
    private class SplitHello(
        val p: EndpointPair,
    ) {
        val c: ConnectionCore = p.connect()
        val newPort = InetSocketAddress("10.0.0.1", 40002)

        fun flight(): List<ByteArray> {
            p.batch.clear()
            val n = c.poll(p.batch, p.now)
            return List(n) { p.batch.buffer(it).toByteArray(p.batch.length(it)) }
        }

        fun serverSends(s: ConnectionCore): List<Pair<InetSocketAddress, ByteArray>> {
            val all = ArrayList<Pair<InetSocketAddress, ByteArray>>()
            while (true) { // everything the server may send now (its amplification budget decides, not one batch)
                p.batch.clear()
                val n = s.poll(p.batch, p.now)
                if (n == 0) return all
                for (i in 0 until n) all += p.batch.address(i)!! to p.batch.buffer(i).toByteArray(p.batch.length(i))
            }
        }

        /**
         * The first half of the ClientHello reaches the server from the old mapping [delay] after it left (the second half is lost)
         * and the server's answer is lost with the mapping; at [repeatAfter] the client's PTO repeat leaves from [newPort]. Returns
         * the server connection and the repeat.
         */
        fun rebindWithinTheHello(
            delay: Duration,
            repeatAfter: Duration,
        ): Pair<ConnectionCore, List<ByteArray>> {
            val start = p.now
            val first = flight()
            assertEquals(2, first.size, "ksl ClientHello spans two Initial datagrams")
            p.now = start + delay
            val s = assertNotNull(p.feed(p.server, first[0], p.clientAddr), "the first half creates the connection")
            serverSends(s) // to the old mapping, which the rebind removed
            val pto = c.nextTimeoutOrNever()
            assertTrue(pto != io.kuicksilver.quic.TimeMark.NEVER)
            p.now = maxOf(pto, start + repeatAfter)
            c.onTimeout(p.now)
            val repeat = flight()
            assertTrue(repeat.size >= 2, "the PTO repeats the ClientHello (${repeat.size} datagrams)")
            return s to repeat
        }
    }

    private fun isLoneAck(bytes: ByteArray): Boolean = bytes[0].toInt() and 0x80 != 0 && bytes.size < 200

    /**
     * 0.2.0 gate repetitions of kuicksilver->quiche:rebind-addr (2026-10-16): quiche's two-datagram ClientHello began before the
     * simulator's rebind at 1 s, only its first datagram reached us from the old address, and its PTO repeat came from the new one
     * in two receive batches. The first repeat (no new CRYPTO bytes, so no keys yet) moved the path and its Initial ACK became our
     * first datagram to the new address. The path now moves with the datagram that completes the ClientHello, and the first
     * datagram there carries the answer to it. The repeat leaves well after the server's anti-spoofing PTO here (the other branch
     * is [handshakeTimeRebindMovesAtOnceWhenTheHelloCompletesThere]).
     */
    @Test fun handshakeTimeRebindMovesWithTheDatagramThatCompletesTheClientHello() {
        val p = EndpointPair(crypto = KslQuicCrypto)
        try {
            val h = SplitHello(p)
            val (s, repeat) = h.rebindWithinTheHello(delay = 10.milliseconds, repeatAfter = 3.seconds)
            val toNewPort = ArrayList<ByteArray>()
            for ((i, d) in repeat.withIndex()) { // one receive batch each, as the endpoint loop flushes after every batch
                p.feedNoAdmit(p.server, d, h.newPort)
                val sent = h.serverSends(s)
                if (i ==
                    0
                ) {
                    assertTrue(sent.none { it.first == h.newPort }, "nothing goes to the new port before the ClientHello is complete")
                }
                for ((to, bytes) in sent) if (to == h.newPort) toNewPort += bytes
            }
            assertEquals(io.kuicksilver.quic.ConnectionState.Handshaking, s.state)
            assertEquals(h.newPort, s.remoteAddressForTest, "the server follows the new mapping once the ClientHello is complete")
            assertTrue(toNewPort.isNotEmpty())
            assertFalse(
                isLoneAck(toNewPort.first()),
                "the first datagram to the new port is no lone Initial ACK (${toNewPort.first().size} bytes)",
            )
            assertTrue(toNewPort.none { isProbe(it) }, "no 1-RTT probe the client could not read yet")
        } finally {
            p.close()
        }
    }

    /**
     * The 0.2.0 gate's kuicksilver->quiche:rebind-addr itself: the ClientHello completed from the new address 1 s after its first half
     * came from the old one, inside the server's PTO, and the anti-spoofing rule for Initials kept the whole ServerHello flight going to
     * the dead mapping until the client's next PTO 2 s later. The datagram that completes the ClientHello now moves the path at once;
     * the new address's budget counts both repeated datagrams, so the whole flight leaves without waiting for an ACK and the client
     * completes its side of the handshake from it.
     */
    @Test fun handshakeTimeRebindMovesAtOnceWhenTheHelloCompletesThere() {
        val p = EndpointPair(crypto = KslQuicCrypto)
        try {
            val h = SplitHello(p)
            // the first half arrives late (queued behind the rebind), so the repeat comes well inside the server's PTO
            val (s, repeat) = h.rebindWithinTheHello(delay = 500.milliseconds, repeatAfter = Duration.ZERO)
            assertTrue(p.now - s.lastReceivedOnActivePath < s.pto() - 200.milliseconds, "the repeat comes inside the server's PTO")
            val toNewPort = ArrayList<ByteArray>()
            val toOldPort = ArrayList<ByteArray>()
            for (d in repeat) {
                p.feedNoAdmit(p.server, d, h.newPort)
                for ((to, bytes) in h.serverSends(s)) if (to == h.newPort) toNewPort += bytes else toOldPort += bytes
            }
            assertEquals(h.newPort, s.remoteAddressForTest, "the datagram that completes the ClientHello moves the path at once")
            // the repeat's first half completes nothing: its ACK may still go to the old mapping, the flight may not
            assertTrue(toOldPort.all { isLoneAck(it) }, "nothing of the flight goes to the old mapping (${toOldPort.map { it.size }})")
            assertEquals(
                repeat.sumOf { it.size }.toLong(),
                s.paths.active.amplification.received,
                "the new address's budget counts every repeated datagram, not only the last",
            )
            for (d in toNewPort) p.feedNoAdmit(p.client, d, p.serverAddr)
            h.flight() // the client's TLS runs on what it received; its answer (Finished) is not needed here
            p.drain(h.c)
            assertTrue(
                h.c.state != io.kuicksilver.quic.ConnectionState.Handshaking,
                "the client completes its side from that one burst (${toNewPort.size} datagrams, ${toNewPort.sumOf { it.size }} bytes; " +
                    "budget left ${s.paths.active.amplification.budget()})",
            )
        } finally {
            p.close()
        }
    }

    /**
     * An on-path attacker copies the datagram that completes the ClientHello and gets its copy in first from a spoofed address (RFC 9000
     * section 9.3.3). The flight goes there within 3x the bytes received from it, nothing more; the client's next Initial moves the path
     * back once the spoofed address has been quiet for a PTO, and the handshake completes on the client's own address.
     */
    @Test fun negative_spoofedCopyOfTheCompletingDatagramOnlyDelaysTheHandshake() {
        val p = EndpointPair(crypto = KslQuicCrypto)
        try {
            val h = SplitHello(p)
            val attacker = InetSocketAddress("10.9.9.9", 4444)
            val first = h.flight()
            val s = assertNotNull(p.feed(p.server, first[0], p.clientAddr))
            h.serverSends(s)
            p.feedNoAdmit(p.server, first[1], attacker) // the copy, first
            assertEquals(attacker, s.remoteAddressForTest, "the copy that completes the ClientHello moves the path")
            val toAttacker = h.serverSends(s).filter { it.first == attacker }.sumOf { it.second.size }
            assertTrue(toAttacker <= 3 * first[1].size, "$toAttacker bytes to the spoofed address for ${first[1].size} received")
            p.feedNoAdmit(p.server, first[1], p.clientAddr) // the genuine datagram: a duplicate now
            assertEquals(attacker, s.remoteAddressForTest)
            assertTrue(p.confirmed(h.c), "the handshake completes (client ${h.c.state}, server ${s.state})")
            assertEquals(p.clientAddr, s.remoteAddressForTest, "the path is back on the client's own address")
            assertEquals(1L, p.server.stats.connectionsCreated)
        } finally {
            p.close()
        }
    }

    /**
     * Review of 0.2.0 (9f35cde5): an off-path attacker that sees the client's datagrams (RFC 9000 section 21.1.3.2) races a copy of
     * every one of them from a spoofed address, so the copy that completes the ClientHello moves the path there and every genuine
     * datagram after it is dropped as a duplicate: the spoofed address stays fresh and the client's own looks quiet. Before, the
     * unvalidated active path had no deadline and the handshake was held there until the handshake timeout. The move is now undone
     * once it went a validation period (RFC 9000 section 8.2.4) without a Handshake packet from the new address (section 9.3.2:
     * revert to the address before it), and the handshake completes with the real client within that bound.
     */
    @Test fun negative_spoofedAddressKeptFreshFallsBackToTheClientWithinTheValidationTimeout() {
        val p = EndpointPair(crypto = KslQuicCrypto)
        try {
            val h = SplitHello(p)
            val attacker = InetSocketAddress("10.9.9.9", 4444)
            val first = h.flight()
            val s = assertNotNull(p.feed(p.server, first[0], p.clientAddr))
            for ((to, bytes) in h.serverSends(s)) if (to == p.clientAddr) p.feedNoAdmit(p.client, bytes, p.serverAddr)
            p.drain(h.c)
            var fromAttacker = 0L
            var toAttacker = 0L

            fun race(d: ByteArray) { // the attacker's copy wins the race while the server is in its handshake; the genuine one follows
                if (s.state == io.kuicksilver.quic.ConnectionState.Handshaking) {
                    p.feedNoAdmit(p.server, d, attacker)
                    fromAttacker += d.size
                }
                p.feedNoAdmit(p.server, d, p.clientAddr)
            }
            race(first[1])
            assertEquals(attacker, s.remoteAddressForTest, "the copy that completes the ClientHello moves the path")
            val movedAt = p.now
            val bound = movedAt + s.validationTimeout() + s.pto()
            val end = movedAt + QuicConfig.Default.handshakeTimeout
            while (p.now < end &&
                !(h.c.state == io.kuicksilver.quic.ConnectionState.Confirmed && s.state == io.kuicksilver.quic.ConnectionState.Confirmed)
            ) {
                for ((to, bytes) in h.serverSends(s)) {
                    if (to == attacker) {
                        toAttacker += bytes.size
                    } else if (to == p.clientAddr) {
                        p.feedNoAdmit(p.client, bytes, p.serverAddr)
                    }
                }
                p.drain(h.c)
                p.drain(s)
                val out = h.flight()
                for (d in out) race(d)
                if (out.isNotEmpty()) continue
                p.now = maxOf(p.now + 1.milliseconds, minOf(h.c.nextTimeoutOrNever(), s.nextTimeoutOrNever()))
                if (h.c.nextTimeoutOrNever() <= p.now) h.c.onTimeout(p.now)
                if (s.nextTimeoutOrNever() <= p.now) s.onTimeout(p.now)
            }
            assertEquals(
                io.kuicksilver.quic.ConnectionState.Confirmed,
                h.c.state,
                "the client confirms the handshake (server ${s.state}, ${p.closed(s)})",
            )
            assertEquals(io.kuicksilver.quic.ConnectionState.Confirmed, s.state)
            assertTrue(p.now <= bound, "confirmed ${p.now - movedAt} after the move, bound ${bound - movedAt}")
            assertEquals(p.clientAddr, s.remoteAddressForTest, "the path is back on the client's own address")
            assertTrue(toAttacker <= 3 * fromAttacker, "$toAttacker bytes to the spoofed address for $fromAttacker received from it")
            assertEquals(1L, p.server.stats.connectionsCreated)
        } finally {
            p.close()
        }
    }

    /** True when [d] holds a long-header Handshake packet (QUIC v1), alone or coalesced. */
    private fun hasHandshakePacket(d: ByteArray): Boolean {
        val hv =
            io.kuicksilver.quic.wire
                .PacketHeaderView()
        val b = PacketBuffer.of(d)
        try {
            var off = 0
            while (off < d.size &&
                io.kuicksilver.quic.wire.PacketHeaderCodec
                    .parse(b, off, d.size, 8, hv)
            ) {
                if (d[off].toInt() and 0x80 == 0) return false
                if ((d[off].toInt() and 0x30) ushr 4 == 2) return true
                off = hv.packetEnd
            }
            return false
        } finally {
            b.close()
        }
    }

    /** The client [c] and the server it creates, their datagrams handed over by hand; [route] decides where each client datagram comes from. */
    private class HandPump(
        val p: EndpointPair,
        val c: ConnectionCore,
    ) {
        var s: ConnectionCore? = null

        fun clientSends(route: (ByteArray) -> Unit): Int {
            p.batch.clear()
            val n = c.poll(p.batch, p.now)
            val out = List(n) { p.batch.buffer(it).toByteArray(p.batch.length(it)) }
            for (d in out) {
                if (s == null) s = p.feed(p.server, d, p.clientAddr) else route(d)
            }
            return n
        }

        /** Everything the server sends now: [deliver] says whether the client receives a datagram sent to that address. */
        fun serverSends(deliver: (InetSocketAddress, ByteArray) -> Boolean) {
            val srv = s ?: return
            while (true) {
                p.batch.clear()
                val n = srv.poll(p.batch, p.now)
                if (n == 0) break
                val all = List(n) { p.batch.address(it)!! to p.batch.buffer(it).toByteArray(p.batch.length(it)) }
                for ((to, bytes) in all) if (deliver(to, bytes)) p.feedNoAdmit(p.client, bytes, p.serverAddr)
            }
            p.drain(c)
            p.drain(srv)
        }

        /** Runs both sides' timers up to the next one due. */
        fun advance() {
            val srv = s!!
            p.now = maxOf(p.now + 1.milliseconds, minOf(c.nextTimeoutOrNever(), srv.nextTimeoutOrNever()))
            if (c.nextTimeoutOrNever() <= p.now) c.onTimeout(p.now)
            if (srv.nextTimeoutOrNever() <= p.now) srv.onTimeout(p.now)
        }
    }

    /**
     * Review of 98a233f3 (0.2.1): a Handshake packet from a new address moved the path at once and validated that address (the
     * comment said "a Handshake packet proves the client"); the path then settled as validated without a PATH_RESPONSE, so one copied
     * datagram sent the whole connection's downlink to an address of the attacker's choosing, with no deadline. The attacker here
     * races copies from the client's second flight on (its Handshake packets, its Finished among them), never an Initial copy. A
     * Handshake packet now validates an address only when the whole flight went there; the move it makes is provisional and undone
     * at the validation deadline, after the handshake completed too, and the handshake completes on the client's own address.
     */
    @Test fun negative_racedHandshakePacketDoesNotValidateTheSpoofedAddress() {
        val p = EndpointPair()
        try {
            val h = HandPump(p, p.connect())
            val attacker = InetSocketAddress("10.9.9.9", 4444)
            var fromAttacker = 0L
            var toAttacker = 0L
            var movedAt: io.kuicksilver.quic.TimeMark? = null
            var attackerValidated = false
            val end = p.now + QuicConfig.Default.handshakeTimeout
            var racing = false

            fun watch() {
                val a = h.s?.paths?.active ?: return
                if (a.isRemote(attacker)) {
                    if (movedAt == null) movedAt = p.now
                    if (a.amplification.validated || a.state == PathState.Validated) attackerValidated = true
                }
                for (q in h.s!!.paths.all) {
                    if (q.isRemote(attacker) &&
                        (q.amplification.validated || q.state == PathState.Validated)
                    ) {
                        attackerValidated = true
                    }
                }
            }
            while (p.now < end &&
                !(h.c.state == io.kuicksilver.quic.ConnectionState.Confirmed && h.s?.state == io.kuicksilver.quic.ConnectionState.Confirmed)
            ) {
                val sent =
                    h.clientSends { d ->
                        if (hasHandshakePacket(d)) racing = true // from the client's second flight on, every datagram is raced
                        if (racing) {
                            p.feedNoAdmit(p.server, d, attacker)
                            fromAttacker += d.size
                            watch()
                        }
                        p.feedNoAdmit(p.server, d, p.clientAddr)
                        watch()
                    }
                h.serverSends { to, bytes ->
                    if (to == attacker) toAttacker += bytes.size
                    to == p.clientAddr
                }
                watch()
                if (sent == 0) h.advance()
                watch()
            }
            val s = assertNotNull(h.s)
            val moved = assertNotNull(movedAt, "the raced Handshake packet moves the path")
            assertFalse(attackerValidated, "the spoofed address is never validated")
            assertEquals(io.kuicksilver.quic.ConnectionState.Confirmed, h.c.state, "the client confirms (server ${s.state})")
            assertEquals(io.kuicksilver.quic.ConnectionState.Confirmed, s.state)
            assertTrue(p.now <= moved + s.validationTimeout() + s.pto(), "confirmed ${p.now - moved} after the move")
            assertTrue(toAttacker <= 3 * fromAttacker, "$toAttacker bytes to the spoofed address for $fromAttacker received from it")
            assertEquals(1L, p.server.stats.connectionsCreated)
        } finally {
            p.close()
        }
    }

    /**
     * The client's mapping changes after our ServerHello left: its Handshake packet (its Finished) comes from a new address. The path
     * follows at once, led by a PATH_CHALLENGE within 3x the bytes received there; the Handshake packet does not validate the address
     * (the flight went to the old one), the client's answer from the new address does: its PATH_RESPONSE, or its acknowledgement of
     * the challenge's packet (or of anything else sent there), whichever the server reads first.
     */
    @Test fun handshakeTimeRebindAfterTheServerHelloIsValidatedByTheClientsAnswer() {
        val p = EndpointPair()
        try {
            val h = HandPump(p, p.connect())
            val newPort = InetSocketAddress("10.0.0.1", 40002)
            var rebound = false
            var fromNew = 0L
            var toNew = 0L
            var validatedBeforeAnswer = false
            var answered = false
            val end = p.now + 5.seconds
            while (p.now < end && !(answered && h.s!!.pathState(h.s!!.stats.currentPath) == PathState.Validated)) {
                val sent =
                    h.clientSends { d ->
                        if (hasHandshakePacket(d)) rebound = true
                        val src = if (rebound) newPort else p.clientAddr
                        val s = h.s!!
                        if (rebound && s.paths.active.isRemote(newPort) && !answered) {
                            answered = true // the client's first datagram after the move: its answer to the challenge
                            if (s.paths.active.amplification.validated) validatedBeforeAnswer = true
                            assertTrue(toNew <= 3 * fromNew, "$toNew bytes to the new address for $fromNew received before its answer")
                        }
                        if (rebound) fromNew += d.size
                        p.feedNoAdmit(p.server, d, src)
                    }
                h.serverSends { to, bytes ->
                    if (to == newPort) toNew += bytes.size
                    to == (if (rebound) newPort else p.clientAddr)
                }
                if (sent == 0) h.advance()
            }
            val s = assertNotNull(h.s)
            assertTrue(rebound && answered, "the client answered from the new address")
            assertEquals(newPort, s.remoteAddressForTest)
            assertFalse(validatedBeforeAnswer, "the Handshake packet alone does not validate the new address")
            assertEquals(PathState.Validated, s.pathState(s.stats.currentPath), "the answer validates it")
            assertTrue(s.challengedAddressesForTest.contains(newPort), "a PATH_CHALLENGE led the move")
            assertTrue(p.events[s]!!.any { it is ConnectionEvent.PathValidated }, "the client's answer validates it")
            assertEquals(io.kuicksilver.quic.ConnectionState.Confirmed, s.state)
            assertNull(s.handshakeFallback)
        } finally {
            p.close()
        }
    }

    /**
     * The other side of [negative_spoofedAddressKeptFreshFallsBackToTheClientWithinTheValidationTimeout]: a client that really rebound
     * answers the flight from its new address with a Handshake packet, which validates it (RFC 9000 section 8.1), so the move stays
     * well past the validation period the fallback waits for, and the old address is not taken back.
     */
    @Test fun handshakeTimeRebindValidatedByTheHandshakeOutlastsTheFallbackDeadline() {
        val p = EndpointPair(crypto = KslQuicCrypto)
        try {
            val h = SplitHello(p)
            val (s, repeat) = h.rebindWithinTheHello(delay = 500.milliseconds, repeatAfter = Duration.ZERO)
            for (d in repeat) p.feedNoAdmit(p.server, d, h.newPort)
            assertEquals(h.newPort, s.remoteAddressForTest, "the datagram that completes the ClientHello moves the path at once")
            val until = p.now + s.validationTimeout() * 2
            while (p.now < until) {
                for ((to, bytes) in h.serverSends(s)) if (to == h.newPort) p.feedNoAdmit(p.client, bytes, p.serverAddr)
                p.drain(h.c)
                p.drain(s)
                val out = h.flight()
                for (d in out) p.feedNoAdmit(p.server, d, h.newPort)
                if (out.isNotEmpty()) continue
                p.now = maxOf(p.now + 1.milliseconds, minOf(until, h.c.nextTimeoutOrNever(), s.nextTimeoutOrNever()))
                if (h.c.nextTimeoutOrNever() <= p.now) h.c.onTimeout(p.now)
                if (s.nextTimeoutOrNever() <= p.now) s.onTimeout(p.now)
            }
            assertEquals(io.kuicksilver.quic.ConnectionState.Confirmed, h.c.state)
            assertEquals(io.kuicksilver.quic.ConnectionState.Confirmed, s.state)
            assertEquals(h.newPort, s.remoteAddressForTest, "the validated new address is kept")
            assertNull(s.handshakeFallback)
        } finally {
            p.close()
        }
    }

    /** The Initial spoof guard still holds: with the keys already there, an Initial from a new address inside the PTO moves nothing. */
    @Test fun negative_initialThatCompletesNothingDoesNotMoveThePathInsideThePto() {
        val p = EndpointPair(crypto = KslQuicCrypto)
        try {
            val h = SplitHello(p)
            val start = p.now
            val first = h.flight()
            p.now = start + 500.milliseconds
            val s = assertNotNull(p.feed(p.server, first[0], p.clientAddr))
            p.feedNoAdmit(p.server, first[1], p.clientAddr) // the ClientHello completes from the old address: the keys are there
            h.serverSends(s)
            p.now = h.c.nextTimeoutOrNever()
            h.c.onTimeout(p.now)
            val repeat = h.flight()
            assertTrue(p.now - s.lastReceivedOnActivePath < s.pto() - 200.milliseconds)
            for (d in repeat) {
                p.feedNoAdmit(p.server, d, h.newPort)
                h.serverSends(s)
            }
            assertEquals(p.clientAddr, s.remoteAddressForTest, "an Initial that completes nothing moves the path only after a quiet PTO")
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

    /**
     * Core review before 0.2.0: one Initial from a new address (public keys, so anyone can forge it) makes a handshaking server challenge that
     * address; with no Handshake packet after it, the passed validation deadline must not stay in the past and make every timer check
     * due again until the handshake timeout. (0.2.1: the deadline now undoes the move instead of opening a new validation period.)
     */
    @Test fun negative_spoofedInitialFromNewAddressDoesNotSpinTimers() {
        val p = EndpointPair()
        try {
            val newPort = InetSocketAddress("10.0.0.1", 40002)
            p.rebindDuringHandshake(newPort)
            assertTrue(
                p.runUntil(5.seconds) {
                    p.server.connections().singleOrNull()?.paths?.active?.let {
                        it.isRemote(
                            newPort,
                        ) && it.state == PathState.Validating
                    } ==
                        true
                },
                "the server follows the Initial from the new address",
            )
            p.filterToServer = { _, _ -> false } // nothing after that Initial: no Handshake packet validates the address
            val s = p.server()
            val path = s.paths.active
            assertFalse(path.handshakeValidated)
            val end = p.now + QuicConfig.Default.handshakeTimeout
            p.now = maxOf(p.now, path.challengeDeadline - 10.milliseconds)
            p.step() // the validation deadline passes while the handshake is still running
            // since the 0.2.1 review the move is undone at its validation deadline (no Handshake packet came from the new address);
            // before, a new validation period began: either way no deadline stays in the past
            assertTrue(s.state == io.kuicksilver.quic.ConnectionState.Handshaking)
            assertTrue(
                path.isRemote(p.clientAddr) && path.state != PathState.Validating,
                "the move is undone at its validation deadline (${path.remote}, ${path.state})",
            )
            assertTrue(s.nextTimeoutOrNever() >= p.now + s.pto(), "next timer ${s.nextTimeoutOrNever()} is a PTO after ${p.now}")
            var fired = 0
            while (p.now < end && s.state == io.kuicksilver.quic.ConnectionState.Handshaking) {
                val next = s.nextTimeoutOrNever()
                p.now = maxOf(p.now, next - 10.milliseconds)
                p.step()
                fired++
            }
            assertTrue(fired < 20, "$fired timer rounds within the handshake timeout")
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

    /**
     * From a trace of `MigrationApiTest.migrateMovesTrafficToNewIo`: after the client's active migration the server re-validates
     * the client's old address (RFC 9000 section 9.3.3); the client must answer the first PATH_CHALLENGE there, not only a repeat.
     */
    @Test fun firstRevalidationChallengeIsAnswered() {
        val (p, c) = connected()
        try {
            val s = p.server()
            val id = c.addPath(p.serverAddr, p.now)
            p.clientSocketSources[id] = other
            p.clientListens += other
            c.probePath(id, p.now)
            assertTrue(p.runUntil(5.seconds) { c.pathState(id) == PathState.Validated }, "probe answered: ${c.pathState(id)}")
            p.settle(5)
            send(c, 300_000) // traffic both ways across the switch, as in the runtime echo
            send(s, 300_000)
            repeat(5) { p.step() }
            val responsesBefore = c.pathResponsesSentForTest
            c.switchPath(id, p.now)
            assertTrue(p.runUntil(2.seconds) { s.remoteAddressForTest == other }, "the server follows the client")
            val old = s.paths.all.first { it.isRemote(p.clientAddr) }
            assertTrue(
                p.runUntil(5.seconds) { old.state != PathState.Validating },
                "the old address is re-validated (${old.state}, challenges ${s.challengedAddressesForTest})",
            )
            assertEquals(PathState.Validated, old.state)
            assertEquals(
                1,
                s.challengedAddressesForTest.count { it == p.clientAddr },
                "the first PATH_CHALLENGE to the old address is answered (client responses ${c.pathResponsesSentForTest - responsesBefore})",
            )
        } finally {
            p.close()
        }
    }

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
        assertTrue(paths.queueResponse(9, fifth), "its slot is free again")
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
                        forged = withPacketNumber(b, 1)
                    }
                    ; true
                }
            // the client's first Initial with packet number 1, which the client sends next (its ACK of our Initial): an unused number
            // would have the server acknowledge a packet the client never sent, and the client close the connection (RFC 9000 section
            // 13.1; the residual of threat-model 3.5)
            val c = p.connect()
            p.step()
            val s = p.server.connections().single()
            val received = s.stats.packetsReceived
            p.feed(p.server, forged!!, attacker)
            assertEquals(received + 1, s.stats.packetsReceived, "the forged Initial decrypts and is processed")
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

    private val bbr = quicConfig { congestionController = { Bbr() } }

    /** A server whose BBR has measured the path: the client uploads and reads back an echo of 30 kB. */
    private fun bbrWithAModel(): Triple<EndpointPair, ConnectionCore, Bbr> {
        val (p, c) = connected(serverQuic = bbr)
        send(c, 20_000)
        p.settle(40)
        val s = p.server()
        val sid = s.openStream(true)
        s.writeStream(sid, ByteArray(30_000), 0, 30_000, true)
        p.settle(60)
        val model = s.path.cc as Bbr
        assertTrue(model.minRttNanos < Long.MAX_VALUE && model.maxBw > 0, "the server's BBR measured the path")
        return Triple(p, c, model)
    }

    @Test fun bbrStartsAFreshModelOnANewAddress() {
        // RFC 9000 section 9.4: a new peer address resets congestion control; BBR's model, filters and rate sampler go with it
        val (p, c, old) = bbrWithAModel()
        try {
            val s = p.server()
            p.clientSource = other
            p.clientListens += other
            send(c)
            p.step()
            assertEquals(PathChangeReason.PeerMigration, p.changes(s).single().reason)
            val fresh = s.path.cc as Bbr
            assertNotSame(old, fresh)
            assertEquals(Bbr.State.Startup, fresh.state)
            assertEquals(0L, fresh.maxBw)
            p.settle(40)
            assertNull(p.closed(s))
        } finally {
            p.close()
        }
    }

    @Test fun bbrKeepsItsModelAcrossANatRebinding() {
        // RFC 9000 section 9.4: only the port changed, the network path is the same; CUBIC and NewReno keep their state here too
        val (p, c, old) = bbrWithAModel()
        try {
            val s = p.server()
            val maxBw = old.maxBw
            p.clientSource = InetSocketAddress("10.0.0.1", 40001)
            p.clientListens += p.clientSource
            send(c)
            p.settle(5)
            assertEquals(PathChangeReason.NatRebinding, p.changes(s).single().reason)
            assertSame(old, s.path.cc)
            assertTrue(old.maxBw >= maxBw / 2, "max_bw kept: $maxBw then ${old.maxBw}")
            assertTrue(s.paths.all.none { it !== s.path && it.cc === old }, "the old address probes on a controller of its own")
        } finally {
            p.close()
        }
    }

    /**
     * A handshake whose client really rebinds from C ([EndpointPair.clientAddr]) to [newAddr] (S) once [rebindAfter] server datagrams
     * reached it at C. From the rebind on, every client datagram also reaches the server as a copy from C (an off-path attacker racing
     * it, RFC 9000 section 9.3.3); [copyWins] (the datagram's index after the rebind) says whether the copy arrives first, the genuine
     * one then being a duplicate; once both sides confirmed the handshake the race stops. Nothing sent to C reaches the client unless [oldAlive] (the old NAT mapping still forwards);
     * [lose] drops a server datagram sent to S.
     */
    private class CopyRace(
        val p: EndpointPair,
        val newAddr: InetSocketAddress,
        val rebindAfter: Int,
        val oldAlive: Boolean = false,
        val lose: (ByteArray) -> Boolean = { false },
        val copyWins: (Int) -> Boolean,
    ) {
        val h = HandPump(p, p.connect())
        private var rebound = false
        private var reached = 0
        private var index = 0
        var fromOld = 0L
        var toOld = 0L
        var movedAt: io.kuicksilver.quic.TimeMark? = null
        var candidateSeen = false

        val s: ConnectionCore get() = assertNotNull(h.s, "the server connection")

        fun confirmed(): Boolean =
            h.c.state == io.kuicksilver.quic.ConnectionState.Confirmed && h.s?.state == io.kuicksilver.quic.ConnectionState.Confirmed

        private fun watch() {
            val srv = h.s ?: return
            if (movedAt == null && srv.paths.active.isRemote(newAddr)) movedAt = p.now
            if (srv.handshakeCandidate != null) candidateSeen = true
        }

        private fun fromClient(
            d: ByteArray,
            from: InetSocketAddress,
        ) {
            if (from == p.clientAddr) fromOld += d.size
            p.feedNoAdmit(p.server, d, from)
            watch()
        }

        /** Runs both sides until both confirmed the handshake, or until [limit] passed (and at least until [atLeast]). */
        fun run(
            limit: Duration,
            atLeast: Duration = Duration.ZERO,
        ) {
            val start = p.now
            val end = start + limit
            while (p.now < end && (!confirmed() || p.now < start + atLeast)) {
                val racing = !confirmed() // the attacker races the handshake; what follows is 1-RTT migration, tested elsewhere
                val sent =
                    h.clientSends { d ->
                        if (!rebound) {
                            fromClient(d, p.clientAddr)
                        } else if (!racing) {
                            fromClient(d, newAddr)
                        } else if (copyWins(index++)) {
                            fromClient(d, p.clientAddr)
                            fromClient(d, newAddr)
                        } else {
                            fromClient(d, newAddr)
                            fromClient(d, p.clientAddr)
                        }
                    }
                if (h.s != null && fromOld == 0L) fromOld = 1200 // the first datagram created the connection from C (padded to 1200)
                h.serverSends { to, bytes ->
                    if (to == p.clientAddr) toOld += bytes.size
                    if (!rebound) {
                        if (to == p.clientAddr && ++reached >= rebindAfter) rebound = true
                        to == p.clientAddr
                    } else {
                        (to == newAddr && !lose(bytes)) || (oldAlive && to == p.clientAddr)
                    }
                }
                watch()
                if (sent == 0) h.advance()
                watch()
            }
        }
    }

    /**
     * The known limit of 0.2.1 (rfc-compliance, §9 and §8.1 rebind during the handshake): the client really rebinds from C to S after
     * the server's first datagram reached it, C is dead, and an off-path observer races copies of the client's datagrams from C, winning
     * two races out of three. Each copy from C was a newer packet from the old address: the path kept returning to the dead C, the
     * challenge sent to S was forgotten with every return, and the client never got HANDSHAKE_DONE (the handshake timed out on its
     * side). Both addresses are now validated on their own (the one the active path does not have is the candidate), S answers its
     * challenge from wherever, and the handshake completes on S within two validation periods of the move.
     */
    @Test fun handshakeRebindUnderCopyRaceFromTheOldAddressCompletesOnTheNewOne() {
        val p = EndpointPair(crypto = KslQuicCrypto)
        try {
            val r = CopyRace(p, InetSocketAddress("10.0.0.1", 40002), rebindAfter = 1) { i -> i % 3 != 0 }
            r.run(QuicConfig.Default.handshakeTimeout)
            val s = r.s
            assertTrue(r.confirmed(), "both confirm the handshake (client ${r.h.c.state}, server ${s.state}, ${p.closed(r.h.c)})")
            val moved = assertNotNull(r.movedAt, "the server followed S")
            assertTrue(r.candidateSeen, "the address left was kept as the candidate")
            val bound = moved + s.validationTimeout() * 2 + s.pto()
            assertTrue(p.now <= bound, "confirmed ${p.now - moved} after the move, bound ${bound - moved}")
            assertEquals(r.newAddr, s.remoteAddressForTest, "the connection ends on the client's new address")
            assertTrue(r.toOld <= 3 * r.fromOld, "${r.toOld} bytes to C for ${r.fromOld} received from it")
            assertEquals(1L, p.server.stats.connectionsCreated)
        } finally {
            p.close()
        }
    }

    /** The same race with the first PATH_CHALLENGE to S lost: the handshake completes within the same bound, and S is validated after it. */
    @Test fun handshakeRebindUnderCopyRaceSurvivesALostCandidateChallenge() {
        val p = EndpointPair(crypto = KslQuicCrypto)
        try {
            var lost = 0
            val newAddr = InetSocketAddress("10.0.0.1", 40002)
            val r =
                CopyRace(p, newAddr, rebindAfter = 1, lose = { b ->
                    if (lost == 0 && isProbe(b)) {
                        lost++
                        true
                    } else {
                        false
                    }
                }) { i -> i % 3 != 0 }
            r.run(QuicConfig.Default.handshakeTimeout)
            val s = r.s
            assertEquals(1, lost, "a challenge to S was lost")
            assertTrue(r.confirmed(), "both confirm the handshake (client ${r.h.c.state}, server ${s.state})")
            val moved = assertNotNull(r.movedAt)
            assertTrue(p.now <= moved + s.validationTimeout() * 2 + s.pto(), "confirmed ${p.now - moved} after the move")
            assertEquals(newAddr, s.remoteAddressForTest)
            r.run(s.validationTimeout(), atLeast = s.validationTimeout())
            assertEquals(newAddr, s.remoteAddressForTest)
            assertEquals(PathState.Validated, s.paths.active.state, "S is validated without the lost challenge: ${s.paths.all}")
            assertNull(s.handshakeCandidate)
            assertTrue(
                p.events[s]!!.any { it is ConnectionEvent.PathValidated && it.path == PathId.Initial },
                "a PATH_RESPONSE (or the settled handshake validation) validated the connection's path: ${p.events[s]}",
            )
        } finally {
            p.close()
        }
    }

    /**
     * The old mapping still forwards (a NAT that keeps both): the copies from C are answered from C as well. Whichever address answers
     * its own challenge first is kept; the handshake completes and the candidate is gone (what follows is 1-RTT migration).
     */
    @Test fun handshakeRebindWithTheOldMappingAliveSettlesOnOneAddress() {
        val p = EndpointPair(crypto = KslQuicCrypto)
        try {
            val newAddr = InetSocketAddress("10.0.0.1", 40002)
            val r = CopyRace(p, newAddr, rebindAfter = 1, oldAlive = true) { i -> i % 3 != 0 }
            r.run(QuicConfig.Default.handshakeTimeout)
            val s = r.s
            assertTrue(r.confirmed(), "both confirm the handshake (client ${r.h.c.state}, server ${s.state})")
            r.run(s.validationTimeout() * 2, atLeast = s.validationTimeout() * 2)
            assertTrue(s.remoteAddressForTest == newAddr || s.remoteAddressForTest == p.clientAddr, "${s.remoteAddressForTest}")
            assertNull(s.handshakeCandidate)
            assertTrue(s.paths.all.none { it.handshakeCandidate }, "${s.paths.all}")
            assertNull(p.closed(r.h.c))
            assertEquals(1L, p.server.stats.connectionsCreated)
        } finally {
            p.close()
        }
    }

    /**
     * A plain NAT rebinding in the handshake (no attacker): the address left is the candidate while the move is undecided, and once
     * the client answers on its new address the candidate is gone. The application sees one path: no event names another.
     */
    @Test fun candidatesCollapseWhenTheHandshakeCompletes() {
        val p = EndpointPair(crypto = KslQuicCrypto)
        try {
            val newAddr = InetSocketAddress("10.0.0.1", 40002)
            val r = CopyRace(p, newAddr, rebindAfter = 1) { false }
            r.run(QuicConfig.Default.handshakeTimeout)
            val s = r.s
            assertTrue(r.confirmed(), "both confirm the handshake (client ${r.h.c.state}, server ${s.state})")
            assertTrue(r.candidateSeen, "the old address was a candidate during the handshake")
            r.run(s.validationTimeout() * 2, atLeast = s.validationTimeout() * 2)
            assertEquals(newAddr, s.remoteAddressForTest)
            assertNull(s.handshakeCandidate)
            assertEquals(1, s.paths.all.size, "one path: ${s.paths.all}")
            val pathEvents =
                p.events[s]!!.filter {
                    it is ConnectionEvent.PathValidated || it is ConnectionEvent.PathFailed || it is ConnectionEvent.PathChanged
                }
            assertTrue(
                pathEvents.all {
                    when (it) {
                        is ConnectionEvent.PathValidated -> it.path == PathId.Initial
                        is ConnectionEvent.PathFailed -> it.path == PathId.Initial
                        is ConnectionEvent.PathChanged -> false
                        else -> true
                    }
                },
                "only the connection's own path is reported: $pathEvents",
            )
        } finally {
            p.close()
        }
    }

    /**
     * [initial], a client Initial datagram under the Null cipher (plaintext header, the 8-byte tag at the end of the packet is the
     * packet number), with its packet number set to [pn] (one byte, so below 256) and the tag to match: a forged Initial that
     * decrypts, as one under the public Initial keys would.
     */
    private fun withPacketNumber(
        initial: ByteArray,
        pn: Int,
    ): ByteArray =
        initial.copyOf().also { f ->
            val off = 1 + 4 + 1 + (f[5].toInt() and 0xff)
            val pnOff = off + 1 + (f[off].toInt() and 0xff) + 1 + 2
            val pnLen = (f[0].toInt() and 0x03) + 1
            val length = ((f[pnOff - 2].toInt() and 0x3f) shl 8) or (f[pnOff - 1].toInt() and 0xff)
            for (i in 0 until pnLen) f[pnOff + i] = if (i == pnLen - 1) pn.toByte() else 0
            val end = pnOff + length
            for (i in 0 until 8) f[end - 8 + i] = ((pn.toLong() ushr (8 * (7 - i))) and 0xff).toByte()
        }

    /** The bounds of the client's first Handshake packet in [d] (start, packet number offset, end), or null. */
    private fun handshakePacketBounds(d: ByteArray): IntArray? {
        val hv =
            io.kuicksilver.quic.wire
                .PacketHeaderView()
        val b = PacketBuffer.of(d)
        try {
            var off = 0
            while (off < d.size &&
                io.kuicksilver.quic.wire.PacketHeaderCodec
                    .parse(b, off, d.size, 8, hv)
            ) {
                if (d[off].toInt() and 0x80 != 0 && (d[off].toInt() and 0x30) ushr 4 == 2) return intArrayOf(off, hv.pnOffset, hv.packetEnd)
                off = hv.packetEnd
            }
            return null
        } finally {
            b.close()
        }
    }

    /**
     * A server held in its handshake: no client Handshake packet reaches it but those forged from the client's first one (PING and
     * padding with a chosen packet number, under the Null cipher), delivered by hand from any address. The client itself completed its
     * side and answers what it is handed.
     */
    private inner class HeldHandshake(
        val newAddr: InetSocketAddress = InetSocketAddress("10.0.0.1", 40002),
    ) {
        val p = EndpointPair()
        val c: ConnectionCore
        val s: ConnectionCore
        private val d: ByteArray
        private val bounds: IntArray
        val attacker = InetSocketAddress("10.9.9.9", 4444)
        val received = HashMap<InetSocketAddress, Long>()
        val sent = HashMap<InetSocketAddress, Long>()

        init {
            var held: ByteArray? = null
            p.filterToServer = { _, b ->
                if (handshakePacketBounds(b) != null) {
                    if (held == null) held = b
                    false
                } else {
                    true
                }
            }
            c = p.connect()
            assertTrue(p.runUntil(2.seconds) { held != null })
            s = p.server.connections().single()
            assertEquals(io.kuicksilver.quic.ConnectionState.Handshaking, s.state)
            d = held!!
            bounds = handshakePacketBounds(d)!!
        }

        /** The client's own datagram with its Finished, held back so far. */
        fun finished(): ByteArray = d

        /** The forged packet, followed by zeros up to [padTo] bytes (the server counts the whole datagram toward the budget, section 8.1). */
        fun forged(
            pn: Int,
            padTo: Int = 0,
        ): ByteArray {
            val (off, pnOff, end) = bounds
            val pkt = d.copyOfRange(off, end)
            val pnLen = (pkt[0].toInt() and 0x03) + 1
            val at = pnOff - off
            for (i in 0 until pnLen) pkt[at + i] = ((pn ushr (8 * (pnLen - 1 - i))) and 0xff).toByte()
            for (i in at + pnLen until pkt.size) pkt[i] = 0
            pkt[at + pnLen] = 0x01
            for (i in 0 until 8) pkt[pkt.size - 8 + i] = ((pn.toLong() ushr (8 * (7 - i))) and 0xff).toByte() // the Null tag
            return if (pkt.size >= padTo) pkt else pkt.copyOf(padTo)
        }

        /** Delivers [bytes] to the server from [from] and returns everything the server sends now. */
        fun deliver(
            bytes: ByteArray,
            from: InetSocketAddress,
        ): List<Pair<InetSocketAddress, ByteArray>> {
            received[from] = (received[from] ?: 0L) + bytes.size
            p.feedNoAdmit(p.server, bytes, from)
            return serverSends()
        }

        fun serverSends(): List<Pair<InetSocketAddress, ByteArray>> {
            val all = ArrayList<Pair<InetSocketAddress, ByteArray>>()
            while (true) {
                p.batch.clear()
                val n = s.poll(p.batch, p.now)
                if (n == 0) break
                for (i in 0 until n) {
                    val to = p.batch.address(i)!!
                    all += to to p.batch.buffer(i).toByteArray(p.batch.length(i))
                    sent[to] = (sent[to] ?: 0L) + p.batch.length(i)
                }
            }
            p.drain(s)
            return all
        }

        /** The client reads [bytes] (as if they reached it) and returns what it sends in answer. */
        fun clientAnswers(bytes: List<ByteArray>): List<ByteArray> {
            for (b in bytes) p.feedNoAdmit(p.client, b, p.serverAddr)
            p.drain(c)
            val out = ArrayList<ByteArray>()
            while (true) {
                p.batch.clear()
                val n = c.poll(p.batch, p.now)
                if (n == 0) break
                for (i in 0 until n) out += p.batch.buffer(i).toByteArray(p.batch.length(i))
            }
            return out
        }

        /** Runs the server's timers up to [until], collecting what it sends. */
        fun advance(until: io.kuicksilver.quic.TimeMark): List<Pair<InetSocketAddress, ByteArray>> {
            val all = ArrayList<Pair<InetSocketAddress, ByteArray>>()
            while (true) {
                val t = s.nextTimeoutOrNever()
                if (t > until) break
                p.now = maxOf(p.now, t)
                s.onTimeout(p.now)
                all += serverSends()
            }
            p.now = until
            return all
        }

        fun close() = p.close()
    }

    /**
     * Threat model 3.5: where a PATH_RESPONSE comes from proves nothing (an off-path attacker races copies of the client's datagrams
     * from any address, RFC 9000 section 9.3.3); its data does (section 8.2.3). The client answers the challenge sent to one address and
     * its answer reaches the server from the other one: the address whose challenge was answered is kept, never the packet's source.
     */
    @Test fun negative_candidateValidatedOnlyByItsOwnChallengeData() {
        for (answerTheCandidate in listOf(true, false)) {
            val h = HeldHandshake()
            try {
                h.deliver(h.forged(5), h.p.clientAddr) // the whole flight went to C: validated
                // the client's Handshake packet from S, in a full-size datagram: the path moves there
                val sent = h.deliver(h.forged(10, padTo = 1200), h.newAddr)
                assertEquals(h.newAddr, h.s.remoteAddressForTest)
                val k = assertNotNull(h.s.handshakeCandidate, "the address left is the candidate")
                assertTrue(k.isRemote(h.p.clientAddr))
                val toC = sent.filter { it.first == h.p.clientAddr && isProbe(it.second) }.map { it.second }
                val toS = sent.filter { it.first == h.newAddr && isProbe(it.second) }.map { it.second }
                assertTrue(toC.isNotEmpty() && toS.isNotEmpty(), "both addresses are challenged (${toC.size} to C, ${toS.size} to S)")
                val answer = h.clientAnswers(if (answerTheCandidate) toC else toS)
                assertTrue(answer.isNotEmpty(), "the client answers the challenge")
                // the answer arrives from the address whose challenge it does not answer
                val source = if (answerTheCandidate) h.newAddr else h.p.clientAddr
                for (a in answer) h.deliver(a, source)
                // a server processes no 1-RTT packet before its handshake completes (RFC 9001 section 5.7): the answer waits for the
                // client's Finished, which a copy brings from the same address
                assertEquals(io.kuicksilver.quic.ConnectionState.Handshaking, h.s.state)
                h.deliver(h.finished(), source)
                val answered = if (answerTheCandidate) h.p.clientAddr else h.newAddr
                assertNull(h.s.handshakeCandidate, "the handshake-time rebind is decided")
                val validatedPaths =
                    h.p.events[h.s]!!
                        .filterIsInstance<ConnectionEvent.PathValidated>()
                        .map { it.path }
                assertEquals(listOf(PathId.Initial), validatedPaths, "only the connection's path was validated")
                assertTrue(
                    assertNotNull(h.s.paths.byId(PathId.Initial)).isRemote(answered),
                    "it has the address whose challenge was answered: ${h.s.paths.all}",
                )
                if (answerTheCandidate) {
                    // the answer's own source then moves the confirmed connection by the rules of 1-RTT migration: under validation,
                    // within its budget, and with the answered address validated again (section 9.3.3)
                    assertTrue(
                        h.s.paths.all
                            .none { it.isRemote(source) && (it.state == PathState.Validated || it.amplification.validated) },
                        "the source of the answer is not validated: ${h.s.paths.all}",
                    )
                }
            } finally {
                h.close()
            }
        }
    }

    /**
     * Only the two addresses of the first handshake-time rebind become the candidate: a third address (an attacker's copy from
     * anywhere) moves the active path by the rules of 0.2.1 but is never kept and challenged on its own, and once the path leaves it,
     * it is gone.
     */
    @Test fun negative_thirdAddressNeverBecomesACandidate() {
        val h = HeldHandshake()
        try {
            h.deliver(h.forged(5), h.p.clientAddr)
            h.deliver(h.forged(10), h.newAddr)
            assertTrue(assertNotNull(h.s.handshakeCandidate).isRemote(h.p.clientAddr))
            h.deliver(h.forged(11), h.attacker) // a third address
            assertEquals(h.attacker, h.s.remoteAddressForTest, "a third address moves the active path as before")
            assertTrue(assertNotNull(h.s.handshakeCandidate).isRemote(h.p.clientAddr), "the candidate stays on C")
            h.deliver(h.forged(12), h.p.clientAddr) // back to C: the address left is the third one
            assertEquals(h.p.clientAddr, h.s.remoteAddressForTest)
            assertNull(h.s.handshakeCandidate, "the third address never becomes the candidate")
            assertTrue(
                h.s.paths.all
                    .none { it.isRemote(h.attacker) },
                "${h.s.paths.all}",
            )
            h.deliver(h.forged(13), h.attacker)
            h.deliver(h.forged(14), h.p.clientAddr)
            assertNull(h.s.handshakeCandidate, "a candidate is opened once per connection")
            assertEquals(1, h.s.paths.all.size)
        } finally {
            h.close()
        }
    }

    /**
     * RFC 9000 section 8.1 per address: the candidate's PATH_CHALLENGEs to an unvalidated address count against that address's budget
     * together with everything the active path sent there while it had it. An attacker that keeps alternating copies from a spoofed
     * address with the client's own packets, while the challenges repeat for two validation periods, gets at most 3x what it sent.
     */
    @Test fun negative_candidateChallengesStayWithinItsAmplificationBudget() {
        val h = HeldHandshake()
        try {
            val spoofed = h.newAddr
            h.deliver(h.forged(5), h.p.clientAddr) // C validated
            var pn = 10
            val end = h.p.now + h.s.validationTimeout() * 2
            var swaps = 0
            while (h.p.now < end) {
                h.deliver(h.forged(pn++), spoofed)
                h.deliver(h.forged(pn++), h.p.clientAddr) // S is the candidate now, still challenged
                swaps++
                h.advance(h.p.now + h.s.pto())
            }
            assertTrue(swaps > 3, "$swaps swaps")
            assertTrue(h.s.challengedAddressesForTest.contains(spoofed), "the spoofed address was challenged")
            val toSpoofed = h.sent[spoofed] ?: 0L
            val fromSpoofed = h.received[spoofed] ?: 0L
            assertTrue(toSpoofed <= 3 * fromSpoofed, "$toSpoofed bytes to the spoofed address for $fromSpoofed received from it")
        } finally {
            h.close()
        }
    }

    /**
     * After the handshake, an observer races copies of every client datagram from a second address, both mappings alive, the copy
     * winning every other race. Each won race is an apparent migration: the server follows the newest non-probing packet and
     * validates the previous path (RFC 9000 section 9.3.3), the client answers that PATH_CHALLENGE in a non-probing packet, whose
     * raced copy is the next apparent migration. With no gap between a challenge and the next one on the same path, this loop ran
     * without end in this zero-latency harness (and at one challenge per round trip on a real network) until the AEAD
     * confidentiality limit closed the connection. A path is now challenged no more often than once per PTO, the pace of an Initial
     * packet (section 8.2.1: "SHOULD NOT probe a new path with packets containing a PATH_CHALLENGE frame more frequently than it
     * would send an Initial packet"); a revalidation asked for sooner is sent when that gap has passed.
     */
    @Test fun negative_copyRaceAfterTheHandshakeDoesNotDriveUnboundedPathValidations() {
        val (p, c) = connected()
        try {
            val s = p.server()
            val other = InetSocketAddress("10.0.0.1", 40002)
            var index = 0
            var serverDatagrams = 0
            var rounds = 0

            fun pump(): Boolean { // one exchange at the current instant; false once neither side sends
                p.batch.clear()
                val n = c.poll(p.batch, p.now)
                val out = List(n) { p.batch.buffer(it).toByteArray(p.batch.length(it)) }
                for (d in out) {
                    val first = if (index++ % 2 == 0) p.clientAddr else other
                    p.feedNoAdmit(p.server, d, first)
                    p.feedNoAdmit(p.server, d, if (first == other) p.clientAddr else other)
                }
                var sent = 0
                while (true) {
                    p.batch.clear()
                    val m = s.poll(p.batch, p.now)
                    if (m == 0) break
                    val back = List(m) { p.batch.buffer(it).toByteArray(p.batch.length(it)) }
                    sent += m
                    for (b in back) p.feedNoAdmit(p.client, b, p.serverAddr) // both mappings alive
                }
                serverDatagrams += sent
                p.drain(c)
                p.drain(s)
                return n + sent > 0
            }
            val stream = c.openStream(true)
            val chunk = ByteArray(100) { 0x41 }
            c.writeStream(stream, chunk, 0, chunk.size, false)
            while (rounds < 10_000 && pump()) rounds++
            assertTrue(rounds < 100, "the exchange at one instant ends ($rounds rounds, $serverDatagrams server datagrams)")
            val start = p.now
            val challengesBefore = s.challengedAddressesForTest.size
            val pto = s.pto()
            val end = p.now + pto * 40
            while (p.now < end && p.closed(c) == null) {
                c.writeStream(stream, chunk, 0, chunk.size, false) // the client keeps sending, so the races go on
                var k = 0
                while (k < 10_000 && pump()) k++
                assertTrue(k < 100, "the exchange at ${p.now - start} ends ($k rounds)")
                p.now = maxOf(p.now + pto / 4, minOf(end, c.nextTimeoutOrNever(), s.nextTimeoutOrNever()))
                if (c.nextTimeoutOrNever() <= p.now) c.onTimeout(p.now)
                if (s.nextTimeoutOrNever() <= p.now) s.onTimeout(p.now)
            }
            assertNull(p.closed(c), "the connection survives the race")
            val challenges = s.challengedAddressesForTest.size - challengesBefore
            // at most one challenge per path per PTO (two addresses), plus the repeats of the validations under way
            assertTrue(challenges <= 2 * 40 + 8, "$challenges PATH_CHALLENGEs over 40 PTOs")
        } finally {
            p.close()
        }
    }

    /**
     * The client rebinds from C to S right after the server's first datagram (an Initial ACK) reached it, before any ServerHello did;
     * C is dead and an observer races copies of its repeated ClientHello from C, winning every other race. The server does not move
     * on an Initial while the current address keeps sending (anyone can forge one), so before 0.3.0 its whole flight kept going to
     * the dead C and the handshake timed out. The address the client's Initials also come from is now mirrored: at each PTO the
     * flight is retransmitted there too, within that address's own budget, and the client completes from S.
     */
    @Test fun handshakeRebindBeforeAnyServerHelloUnderCopyRaceCompletes() {
        val p = EndpointPair(crypto = KslQuicCrypto)
        try {
            val newAddr = InetSocketAddress("10.0.0.1", 40002)
            val r = CopyRace(p, newAddr, rebindAfter = 1) { i -> i % 2 == 1 }
            val start = p.now
            r.run(QuicConfig.Default.handshakeTimeout)
            val s = r.s
            assertTrue(r.confirmed(), "both confirm the handshake (client ${r.h.c.state}, server ${s.state}, ${p.closed(r.h.c)})")
            assertTrue(s.handshakeMirrorSent, "the flight was retransmitted to S")
            assertEquals(newAddr, s.remoteAddressForTest)
            assertTrue(r.toOld <= 3 * r.fromOld, "${r.toOld} bytes to C for ${r.fromOld} received from it")
            assertTrue(p.now - start < QuicConfig.Default.handshakeTimeout / 2, "confirmed after ${p.now - start}")
            assertEquals(1L, p.server.stats.connectionsCreated)
        } finally {
            p.close()
        }
    }

    /**
     * The other side of [handshakeRebindBeforeAnyServerHelloUnderCopyRaceCompletes]: the client stays at C and an observer races
     * copies of its datagrams from X while the server's first flight is lost (so its PTO fires). X gets the flight's retransmission
     * within 3x what came from X and nothing more; the path never leaves C and the handshake completes there.
     */
    @Test fun negative_mirroredFlightToARacedAddressStaysWithinItsBudget() {
        val p = EndpointPair(crypto = KslQuicCrypto)
        try {
            val h = HandPump(p, p.connect())
            val x = InetSocketAddress("10.9.9.9", 4444)
            var index = 0
            var fromX = 0L
            var toX = 0L
            var lostFirst = false
            val end = p.now + QuicConfig.Default.handshakeTimeout
            while (p.now < end &&
                !(h.c.state == io.kuicksilver.quic.ConnectionState.Confirmed && h.s?.state == io.kuicksilver.quic.ConnectionState.Confirmed)
            ) {
                val sent =
                    h.clientSends { d ->
                        val copyFirst = index++ % 2 == 1
                        if (copyFirst) {
                            fromX += d.size
                            p.feedNoAdmit(p.server, d, x)
                        }
                        p.feedNoAdmit(p.server, d, p.clientAddr)
                        if (!copyFirst) {
                            fromX += d.size
                            p.feedNoAdmit(p.server, d, x)
                        }
                    }
                h.serverSends { to, bytes ->
                    if (to == x) toX += bytes.size
                    if (to == p.clientAddr && !lostFirst) {
                        lostFirst = true
                        false
                    } else {
                        to == p.clientAddr
                    }
                }
                if (sent == 0) h.advance()
            }
            val s = assertNotNull(h.s)
            assertEquals(io.kuicksilver.quic.ConnectionState.Confirmed, h.c.state, "the handshake completes (server ${s.state})")
            assertEquals(p.clientAddr, s.remoteAddressForTest)
            assertTrue(toX <= 3 * fromX, "$toX bytes to X for $fromX received from it")
            assertTrue(s.paths.all.none { it.isRemote(x) && it.amplification.validated }, "X is never validated")
        } finally {
            p.close()
        }
    }

    /** Hands the challenges in [sent] to [targets] to the client and returns its answers (see [HeldHandshake.clientAnswers]). */
    private fun HeldHandshake.answer(
        sent: List<Pair<InetSocketAddress, ByteArray>>,
        vararg targets: InetSocketAddress,
    ): List<ByteArray> = clientAnswers(sent.filter { it.first in targets && isProbe(it.second) }.map { it.second })

    /**
     * RFC 9000 section 9.4: a handshake-time change of the active path to another IP starts its congestion controller, RTT estimate and
     * MTU over (a move, and the candidate's adoption back across IPs); a port-only change keeps them, as for a NAT rebinding.
     */
    @Test fun handshakeTimeAddressChangeAcrossIpsStartsCongestionRttAndMtuOver() {
        for (otherIp in listOf(true, false)) {
            val h = HeldHandshake(if (otherIp) InetSocketAddress("10.0.0.9", 40002) else InetSocketAddress("10.0.0.1", 40002))
            try {
                h.deliver(h.forged(5), h.p.clientAddr)
                val a = h.s.paths.active
                h.s.setMtu(a, 1452)
                val cc = a.cc
                val rtt = a.rtt
                val sent = h.deliver(h.forged(10, padTo = 1200), h.newAddr)
                assertEquals(h.newAddr, h.s.remoteAddressForTest)
                if (otherIp) {
                    assertNotSame(cc, a.cc, "a fresh congestion controller on the new IP")
                    assertNotSame(rtt, a.rtt, "a fresh RTT estimate on the new IP")
                    assertSame(a.rtt, h.s.loss.rtt, "loss recovery uses it")
                    assertEquals(h.s.config.newPathInitialRtt, a.rtt.smoothed)
                    assertEquals(1200, a.mtu)
                } else {
                    assertSame(cc, a.cc, "a port-only change keeps the controller")
                    assertSame(rtt, a.rtt)
                    assertEquals(1452, a.mtu)
                }
                // the client answers the candidate C's challenge: the path is adopted back there, across IPs again or not
                val ccAtNew = a.cc
                h.setMtuOfActive(1452)
                for (b in h.answer(sent, h.p.clientAddr)) h.deliver(b, h.p.clientAddr)
                h.deliver(h.finished(), h.p.clientAddr)
                val initial = assertNotNull(h.s.paths.byId(PathId.Initial))
                assertTrue(initial.isRemote(h.p.clientAddr), "adopted: ${h.s.paths.all}")
                if (otherIp) {
                    assertNotSame(ccAtNew, initial.cc, "the adoption across IPs starts the controller over")
                    assertEquals(1200, initial.mtu)
                } else {
                    assertSame(ccAtNew, initial.cc, "a port-only adoption keeps it")
                    assertEquals(1452, initial.mtu)
                }
            } finally {
                h.close()
            }
        }
    }

    private fun HeldHandshake.setMtuOfActive(mtu: Int) = s.setMtu(s.paths.active, mtu)

    /**
     * The candidate's and the active address's challenges are answered in one packet: the decision waits for the packet's end and
     * the active address keeps the path; the candidate is dropped without ever being adopted.
     */
    @Test fun bothAnswersInOnePacketKeepTheActiveAddress() {
        val h = HeldHandshake()
        try {
            h.deliver(h.forged(5), h.p.clientAddr)
            val sent = h.deliver(h.forged(10, padTo = 1200), h.newAddr)
            // the candidate's challenge reaches the client first, so its PATH_RESPONSE comes first in the client's packet
            val probes =
                sent.filter { it.first == h.p.clientAddr && isProbe(it.second) } +
                    sent.filter { it.first == h.newAddr && isProbe(it.second) }
            val answer = h.clientAnswers(probes.map { it.second })
            assertEquals(1, answer.size, "both PATH_RESPONSEs in one datagram")
            for (b in answer) h.deliver(b, h.newAddr)
            h.deliver(h.finished(), h.newAddr)
            val initial = assertNotNull(h.s.paths.byId(PathId.Initial))
            assertTrue(initial.isRemote(h.newAddr), "the active address keeps the path: ${h.s.paths.all}")
            assertEquals(PathState.Validated, initial.state)
            assertNull(h.s.handshakeCandidate)
            assertEquals(1, h.s.paths.all.size, "${h.s.paths.all}")
        } finally {
            h.close()
        }
    }

    /**
     * Review of the mirrored flight (S2): an Initial of the client's from a third address X (here a copy of its repeated ClientHello
     * that wins the race; a forged one under the public Initial keys does the same) makes the server retransmit its flight to X at
     * each PTO, within X's budget. The flight (an ML-KEM key share and a certificate) does not fit X's budget, so part of what was
     * queued again for X stays unsent; before the review it then went to the client's own address as fresh data at the next poll,
     * spending that unvalidated address's 3x budget. Now the client's address gets exactly what it gets without X: the same
     * datagrams and bytes.
     */
    @Test fun negative_mirroredFlightChangesNothingSentToTheClientsAddress() {
        val x = InetSocketAddress("10.0.0.66", 6666)

        /** Datagrams and bytes the server sends to the client's address (which never receives them) over three PTOs; bytes to [x]. */
        fun run(race: Boolean): Triple<Int, Long, Long> {
            val p = EndpointPair(crypto = KslQuicCrypto)
            try {
                val c = p.connect()

                fun clientFlight(): List<ByteArray> {
                    p.batch.clear()
                    val n = c.poll(p.batch, p.now)
                    return List(n) { p.batch.buffer(it).toByteArray(p.batch.length(it)) }
                }
                var toClient = 0
                var toClientBytes = 0L
                var toX = 0L

                fun serverSends(s: ConnectionCore) {
                    while (true) {
                        p.batch.clear()
                        val n = s.poll(p.batch, p.now)
                        if (n == 0) break
                        for (i in 0 until n) {
                            val len = p.batch.length(i)
                            if (p.batch.address(i) == p.clientAddr) {
                                toClient++
                                toClientBytes += len
                            } else if (p.batch.address(i) == x) {
                                toX += len
                            }
                        }
                    }
                    p.drain(s)
                }
                val hello = clientFlight()
                assertEquals(2, hello.size, "ksl ClientHello spans two Initial datagrams")
                val s = assertNotNull(p.feed(p.server, hello[0], p.clientAddr))
                p.feedNoAdmit(p.server, hello[1], p.clientAddr)
                serverSends(s) // the whole flight is lost: the client never holds a handshake key
                p.now = c.nextTimeoutOrNever()
                c.onTimeout(p.now)
                val repeat = clientFlight()
                assertTrue(repeat.size >= 2, "the PTO repeats the ClientHello")
                p.feedNoAdmit(p.server, repeat[0], p.clientAddr)
                if (race) p.feedNoAdmit(p.server, repeat[1], x) // the copy wins: the genuine one below is a duplicate
                for (d in repeat.drop(1)) p.feedNoAdmit(p.server, d, p.clientAddr)
                if (race) assertNotNull(s.handshakeCandidate, "X is mirrored")
                serverSends(s)
                repeat(3) {
                    p.now = s.nextTimeoutOrNever()
                    s.onTimeout(p.now)
                    serverSends(s)
                }
                if (race) {
                    assertTrue(s.handshakeMirrorSent, "the flight was retransmitted to X")
                    assertTrue(toX <= 3L * repeat[1].size, "$toX bytes to X for ${repeat[1].size} received from it")
                }
                return Triple(toClient, toClientBytes, toX)
            } finally {
                p.close()
            }
        }
        val baseline = run(race = false)
        val raced = run(race = true)
        assertEquals(0L, baseline.third)
        assertTrue(raced.third > 0, "something went to X")
        assertEquals(baseline.first, raced.first, "datagrams to the client's address (raced $raced, baseline $baseline)")
        assertEquals(baseline.second, raced.second, "bytes to the client's address (raced $raced, baseline $baseline)")
    }

    /**
     * The residual of threat-model 3.5, pinned: an Initial forged under the public Initial keys with a packet number the client never
     * sent is processed like any other client Initial (nothing tells it apart), the server acknowledges it, and the client treats
     * the acknowledgement of a packet it did not send as a PROTOCOL_VIOLATION (RFC 9000 section 13.1 SHOULD, as quic-go, quiche,
     * ngtcp2 and msquic do). RFC 9000 section 21.1.1.3 accepts it: "An on-path or off-path attacker can force a handshake to fail by
     * replacing or racing Initial packets."
     */
    @Test fun forgedInitialWithAnUnusedPacketNumberEndsTheHandshake() {
        val p = EndpointPair()
        try {
            val c = p.connect()
            p.batch.clear()
            assertEquals(1, c.poll(p.batch, p.now))
            val first = p.batch.buffer(0).toByteArray(p.batch.length(0))
            assertNotNull(p.feed(p.server, first, p.clientAddr))
            // the forgery arrives before the server answered, so its acknowledgement reaches the client while it still reads Initials
            p.feedNoAdmit(p.server, withPacketNumber(first, 0x33), InetSocketAddress("10.0.0.66", 6666))
            assertFalse(p.confirmed(c))
            val closed = assertNotNull(p.closed(c), "the client closed")
            assertTrue(closed.toString().contains("ACK for a packet never sent"), "$closed")
        } finally {
            p.close()
        }
    }

    /**
     * A mirrored datagram carries the flight and nothing else: no ACK frame of its space (an acknowledgement owed to the client goes to
     * the active address, where the client is believed to be). The server owes one here: X's Initial (packet number 1, which it
     * processed) is still unacknowledged when its PTO fires.
     */
    @Test fun negative_mirroredFlightCarriesNoAcknowledgement() {
        val p = EndpointPair()
        try {
            val x = InetSocketAddress("10.0.0.66", 6666)
            val c = p.connect()
            p.batch.clear()
            assertEquals(1, c.poll(p.batch, p.now))
            val first = p.batch.buffer(0).toByteArray(p.batch.length(0))
            val s = assertNotNull(p.feed(p.server, first, p.clientAddr))
            val toX = ArrayList<ByteArray>()

            fun serverSends() {
                while (true) {
                    p.batch.clear()
                    val n = s.poll(p.batch, p.now)
                    if (n == 0) break
                    for (i in 0 until n) if (p.batch.address(i) == x) toX += p.batch.buffer(i).toByteArray(p.batch.length(i))
                }
            }
            serverSends() // the flight is lost
            p.feedNoAdmit(p.server, withPacketNumber(first, 1), x)
            assertNotNull(s.handshakeCandidate, "X is mirrored")
            var rounds = 0
            while (toX.isEmpty() && rounds++ < 5) { // the acknowledgement's own timer may come first; then the PTO
                p.now = s.nextTimeoutOrNever()
                s.onTimeout(p.now)
                serverSends()
            }
            assertTrue(toX.isNotEmpty(), "the flight was mirrored to X")
            val hv =
                io.kuicksilver.quic.wire
                    .PacketHeaderView()
            for (d in toX) {
                val b = PacketBuffer.of(d)
                try {
                    var off = 0
                    while (off < d.size && d[off].toInt() != 0 &&
                        io.kuicksilver.quic.wire.PacketHeaderCodec
                            .parse(b, off, d.size, 8, hv)
                    ) {
                        // Null cipher: the header is not protected, the payload is plaintext; the first frame follows the number
                        val pnLen = (d[off].toInt() and 0x03) + 1
                        val frameType = d[hv.pnOffset + pnLen].toInt() and 0xff
                        assertTrue(frameType != 0x02 && frameType != 0x03, "an ACK frame in a mirrored packet (type $frameType)")
                        off = hv.packetEnd
                    }
                } finally {
                    b.close()
                }
            }
        } finally {
            p.close()
        }
    }
}
