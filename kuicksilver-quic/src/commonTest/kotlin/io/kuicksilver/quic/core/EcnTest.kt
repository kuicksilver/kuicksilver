// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.EcnState
import io.kuicksilver.quic.IoCapabilities
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.endpoint.EndpointPair
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** RFC 9000 sections 13.4 and 21.10: ECT(0) marking, ECN counting in ACK frames, path validation, CE as a congestion signal. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class EcnTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val ecnCaps = IoCapabilities(ecnSend = true, ecnReceive = true, gsoMaxSegments = 1, gro = false, df = false, batch = 1)
    private val sendOnly = IoCapabilities(ecnSend = true, ecnReceive = false, gsoMaxSegments = 1, gro = false, df = false, batch = 1)

    private fun pair(
        clientCaps: IoCapabilities = ecnCaps,
        serverCaps: IoCapabilities = ecnCaps,
        configure: EndpointPair.() -> Unit = {
        },
    ): Pair<EndpointPair, ConnectionCore> {
        val p = EndpointPair()
        p.serverEcnReceive = serverCaps.ecnReceive
        p.clientEcnReceive = clientCaps.ecnReceive
        p.configure()
        val c = p.connect()
        c.setPathCapabilities(PathId.Initial, clientCaps)
        p.onServerCreated = { it.setPathCapabilities(PathId.Initial, serverCaps) }
        assertTrue(p.confirmed(c))
        return p to c
    }

    private fun transfer(
        p: EndpointPair,
        c: ConnectionCore,
        bytes: Int = 200_000,
    ) {
        val id = c.openStream(true)
        var w = 0
        assertTrue(
            p.runUntil(10.seconds) {
                if (w <
                    bytes
                ) {
                    w +=
                        c.writeStream(
                            id,
                            ByteArray(minOf(16384, bytes - w)),
                            0,
                            minOf(16384, bytes - w),
                            w + minOf(16384, bytes - w) == bytes,
                        )
                }
                ; w ==
                    bytes &&
                    c.stats.bytesInFlight == 0L
            },
        )
    }

    @Test fun validationSucceedsOnCleanPath() {
        val (p, c) = pair()
        try {
            transfer(p, c)
            assertEquals(EcnState.Capable, c.stats.ecnState)
            assertEquals(
                EcnState.Capable,
                p.server
                    .connections()
                    .single()
                    .stats.ecnState,
            )
            assertTrue(
                p.clientEcnSent.count { it == Ecn.Ect0 } > 100,
                "data packets carry ECT(0): ${p.clientEcnSent.groupingBy { it }.eachCount()}",
            )
        } finally {
            p.close()
        }
    }

    @Test fun ackEcnCountsReported() {
        // RFC 9000 section 13.4.1: the receiver counts ECT(0) marks of processed packets and reports them in ACK_ECN
        val (p, c) = pair()
        try {
            transfer(p, c)
            val s = p.server.connections().single()
            val counts = s.ecnReceivedForTest()
            val marked = p.clientEcnSent.count { it == Ecn.Ect0 }.toLong()
            assertTrue(
                counts[0] in (marked - 4)..marked && counts[0] > 100,
                "ect0 count in the 1-RTT space = marked datagrams received (the handshake datagrams were counted in their own, discarded spaces): $marked sent, ${counts[0]} counted",
            )
            assertEquals(0L, counts[1])
            assertEquals(0L, counts[2])
            assertTrue(c.ecnPeerCountsForTest()[0] >= counts[0] - 2, "the client learned the counts through ACK_ECN")
        } finally {
            p.close()
        }
    }

    @Test fun ceMarkTriggersOneCongestionEventPerRecovery() {
        val rnd = Random(3)
        val (p, c) = pair { ecnToServer = { e -> if (e == Ecn.Ect0 && rnd.nextDouble() < 0.05) Ecn.Ce else e } }
        try {
            val t0 = p.now
            transfer(p, c, 400_000)
            val s = p.server.connections().single()
            assertTrue(s.stats.ecnCeReceived > 5, "CE marks were counted: ${s.stats.ecnCeReceived}")
            assertTrue(c.stats.ecnCeEvents >= 1, "the sender reacted")
            val rtts =
                ((p.now - t0).inWholeMilliseconds / 20).toInt() + 1
            assertTrue(
                c.stats.ecnCeEvents <= rtts,
                "at most one congestion event per recovery period: ${c.stats.ecnCeEvents} in $rtts RTTs",
            )
            assertTrue(c.stats.cwnd < 400_000L, "the window did not grow unchecked: ${c.stats.cwnd}")
        } finally {
            p.close()
        }
    }

    @Test fun ecnStaysCapableAcrossReorderedAcks() {
        // RFC 9000 section 13.4.2.1: the network reorders ACKs, so a later ACK carries smaller counts than one already processed;
        // a stale ACK must neither fail the validation ("counts decreased") nor count its CE marks again
        val (p, c) = pair()
        var held: ByteArray? = null
        var reordered = 0
        p.filterToClient =
            { i, b ->
                when (i % 3) {
                    1 -> {
                        held = b
                        false
                    }

                    2 -> {
                        true
                    }

                    else -> {
                        held?.let {
                            p.feedEcn(p.client, it, p.serverAddr, Ecn.Ect0)
                            reordered++
                        }
                        held = null
                        true
                    }
                }
            }
        try {
            transfer(p, c, 2_000_000) // the pair acknowledges once per 10 ms step: a long transfer for enough ACK datagrams
            assertTrue(reordered > 10, "ACK datagrams were reordered: $reordered of ${p.sentToClient}")
            assertEquals(EcnState.Capable, c.stats.ecnState, "the sender keeps ECN across reordered ACKs")
            assertEquals(
                EcnState.Capable,
                p.server
                    .connections()
                    .single()
                    .stats.ecnState,
            )
        } finally {
            p.close()
        }
    }

    @Test fun validationFailsOnBleaching() {
        // a network that clears the ECN bits: the peer reports no counts for packets we marked → Failed, and nothing is marked afterwards (section 13.4.2)
        val (p, c) = pair { ecnToServer = { Ecn.NotEct } }
        try {
            transfer(p, c)
            assertEquals(EcnState.Failed, c.stats.ecnState)
            val afterFailure = p.clientEcnSent.drop(p.clientEcnSent.indexOfLast { it == Ecn.Ect0 } + 1)
            assertTrue(afterFailure.size > 50 && afterFailure.all { it == Ecn.NotEct }, "no marks after failure")
            assertTrue(
                p.clientEcnSent.count { it == Ecn.Ect0 } <= 10,
                "only the test packets were marked: ${p.clientEcnSent.count { it == Ecn.Ect0 }}",
            )
        } finally {
            p.close()
        }
    }

    @Test fun validationFailsWhenPeerReportsNoCounts() {
        val (p, c) = pair(serverCaps = sendOnly)
        try {
            transfer(p, c)
            assertEquals(EcnState.Failed, c.stats.ecnState, "a peer that cannot read marks never reports counts")
        } finally {
            p.close()
        }
    }

    @Test fun validationFailsWhenAllTestPacketsLost() {
        // an ECN black hole: every marked datagram vanishes (appendix A.4). ECN starts after the handshake so the ten test packets are data packets
        var dropped = 0
        val (p, c) = pair(clientCaps = IoCapabilities.Portable)
        try {
            c.setPathCapabilities(PathId.Initial, ecnCaps)
            p.filterToServer =
                { i, _ ->
                    if (p.clientEcnSentAt(i) == Ecn.Ect0) {
                        dropped++
                        false
                    } else {
                        true
                    }
                }
            transfer(p, c, 100_000)
            assertTrue(dropped >= 10, "the ten test packets (and what followed before the PTO) were marked and lost: $dropped")
            assertEquals(EcnState.Failed, c.stats.ecnState, "all testing packets lost (appendix A.4): the PTO ends the test")
            val after =
                p.clientEcnSent.drop(p.clientEcnSent.indexOfLast { it == Ecn.Ect0 } + 1)
            ; assertTrue(after.size >= 5 && after.all { it == Ecn.NotEct }, "no marks after failure: ${p.clientEcnSent}")
        } finally {
            p.close()
        }
    }

    @Test fun ecnIgnoredFromUnprocessedDatagram() {
        // RFC 9000 section 21.10: a datagram whose packets could not be processed must not move the counts
        val (p, c) = pair()
        try {
            transfer(p, c, 20_000)
            val s = p.server.connections().single()
            val before = s.ecnReceivedForTest().copyOf()
            val junk = ByteArray(80) { 0x5a }
            junk[0] = 0x40
            s.localCid.toByteArray().copyInto(junk, 1)
            p.feedEcn(p.server, junk, p.clientAddr, Ecn.Ce)
            assertEquals(before.toList(), s.ecnReceivedForTest().toList(), "a CE on an undecryptable datagram counts nothing")
            assertEquals(0L, s.stats.ecnCeReceived)
        } finally {
            p.close()
        }
    }

    @Test fun noMarkingWithoutCapability() {
        val (p, c) = pair(clientCaps = IoCapabilities.Portable, serverCaps = IoCapabilities.Portable)
        try {
            transfer(p, c, 50_000)
            assertTrue(p.clientEcnSent.all { it == Ecn.NotEct })
            assertEquals(EcnState.Disabled, c.stats.ecnState)
        } finally {
            p.close()
        }
    }

    @Test fun newPathRestartsValidation() {
        val (p, c) = pair()
        try {
            transfer(p, c, 50_000)
            val s = p.server.connections().single()
            assertEquals(EcnState.Capable, s.stats.ecnState)
            val other = InetSocketAddress("10.0.0.7", 40000)
            p.clientSource = other
            p.clientListens += other
            val id = c.openStream(true)
            c.writeStream(id, ByteArray(100), 0, 100, true)
            p.step() // the move happens in this round; no ACK from the new path yet
            assertEquals(other, s.remoteAddressForTest)
            assertTrue(
                s.stats.ecnState == EcnState.Testing || s.stats.ecnState == EcnState.Unknown,
                "a new path validates ECN afresh: ${s.stats.ecnState}",
            )
            transfer(p, c, 100_000)
            assertEquals(EcnState.Capable, s.stats.ecnState)
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 13.4.2: "an endpoint validates the ECN counts for each network path". A handshake-time move of the server's
     * active path to another client IP started congestion control, RTT and DPLPMTUD over but kept the ECN state of the old address
     * (0.3.0 cross-review); it starts over too.
     */
    @Test fun handshakeTimeMoveToAnotherIpRestartsValidation() {
        val p = EndpointPair()
        try {
            p.serverEcnReceive = true
            p.clientEcnReceive = true
            p.onServerCreated = { it.setPathCapabilities(PathId.Initial, ecnCaps) }
            val c = p.connect()
            c.setPathCapabilities(PathId.Initial, ecnCaps)
            p.clientListens.clear()
            p.clientListensOnSource = false // the first answer goes to a mapping that no longer exists
            p.step()
            val s = p.server.connections().single()
            s.paths.active.ecn
                .onAck(countsPresent = false, countsValid = false, newlyAckedMarked = 1)
            assertEquals(EcnState.Failed, s.paths.active.ecn.state, "the first address failed validation")
            val moved = InetSocketAddress("10.0.0.9", 40002)
            p.clientSource = moved
            p.clientListens += moved
            p.clientListensOnSource = true
            assertTrue(p.confirmed(c), "client ${c.state}, server ${s.state}")
            assertEquals(moved, s.remoteAddressForTest)
            assertTrue(s.paths.active.ecn.state != EcnState.Failed, "validated afresh on the new address: ${s.paths.active.ecn.state}")
            // past the loss of the marked packets that went to the old address: they neither fail nor validate the new one, and the
            // new address's own test packets do
            val since = assertNotNull(s.paths.active.ecnSince)
            val listener = ConnectionLossListener(s)
            val app = io.kuicksilver.quic.recovery.SpaceId.Application
            val before = s.paths.active.ecn.state
            repeat(10) {
                val old = s.loss.space(app).newSentPacket()
                old.ecnMarked = true
                old.timeSent = since - 1.milliseconds
                old.pathId = s.paths.active.id.value
                listener.onLost(app, old) // a marked packet to the old address declared lost
            }
            listener.onEcnAck(app, false, false, 1, false, p.now, since - 1.milliseconds, s.paths.active.id.value)
            assertEquals(before, s.paths.active.ecn.state, "feedback about packets to the old address leaves the new validation alone")
            val id = c.openStream(true)
            c.writeStream(id, byteArrayOf(1), 0, 1, true)
            assertTrue(p.runUntil(5.seconds) { s.isStreamOpenForTest(id) })
            s.writeStream(id, ByteArray(60_000), 0, 60_000, true)
            assertTrue(p.runUntil(10.seconds) { s.stats.bytesInFlight == 0L && s.paths.active.ecn.state == EcnState.Capable })
            assertTrue(s.lostPackets > 0 || s.stats.lostPackets > 0, "the packets to the old address were declared lost")
            assertTrue(p.now > since)
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9002 section 7.1 per path (RFC 9000 section 9.4: each path its own congestion controller): a CE report on one path started
     * a recovery period for the whole connection, so a CE report on another path in it was ignored; and a CE increase in counts that
     * failed validation (RFC 9000 section 13.4.2.1) was acted on (0.3.0 cross-review).
     */
    @Test fun ceReportsAreGatedPerPathAndOnlyWithValidCounts() {
        val (p, c) = pair()
        try {
            val other = c.addPath(InetSocketAddress("10.0.0.2", 443), p.now, PathId(7))
            val listener = ConnectionLossListener(c)
            val sentEarlier = p.now - 50.milliseconds
            val before = c.stats.ecnCeEvents
            listener.onEcnAck(io.kuicksilver.quic.recovery.SpaceId.Application, true, false, 1, true, p.now, sentEarlier, c.path.id.value)
            assertEquals(before, c.stats.ecnCeEvents, "counts that fail validation are no CE report")
            listener.onEcnAck(io.kuicksilver.quic.recovery.SpaceId.Application, true, true, 1, true, p.now, sentEarlier, c.path.id.value)
            assertEquals(before + 1, c.stats.ecnCeEvents)
            listener.onEcnAck(io.kuicksilver.quic.recovery.SpaceId.Application, true, true, 1, true, p.now, sentEarlier, other.value)
            assertEquals(before + 2, c.stats.ecnCeEvents, "the other path's controller reacts to its own report")
            listener.onEcnAck(io.kuicksilver.quic.recovery.SpaceId.Application, true, true, 1, true, p.now, sentEarlier, c.path.id.value)
            assertEquals(before + 2, c.stats.ecnCeEvents, "one per recovery period of the path")
        } finally {
            p.close()
        }
    }

    @Test fun onlyTheTestPacketsAreMarkedUntilValidated() {
        // RFC 9000 appendix A.4: 'On paths with a "testing" or "capable" state, the endpoint sends packets with an ECT marking --
        // ECT(0) by default; otherwise, the endpoint sends unmarked packets.' After the ten test packets the path is "unknown" until
        // an ACK validates the counts: a black hole that eats marked datagrams then costs ten packets, not everything until a PTO
        val (p, c) = pair(clientCaps = IoCapabilities.Portable)
        try {
            transfer(p, c, 1_000_000) // a window wider than the ten test packets
            c.setPathCapabilities(PathId.Initial, ecnCaps)
            p.filterToServer = { i, _ -> p.clientEcnSentAt(i) != Ecn.Ect0 }
            transfer(p, c, 200_000)
            val marked = p.clientEcnSent.count { it == Ecn.Ect0 }
            assertTrue(marked in 10..12, "the ten test packets (and an ACK-only packet or two between them) were marked: $marked")
            assertEquals(EcnState.Failed, c.stats.ecnState, "the ten test packets were all declared lost (appendix A.4)")
        } finally {
            p.close()
        }
    }

    @Test fun ceMarkedPacketIsAcknowledgedAtOnce() {
        // RFC 9000 section 13.2.1: "an endpoint SHOULD immediately acknowledge all packets marked with the ECN Congestion Experienced
        // (CE) codepoint in the IP header". One small ack-eliciting packet otherwise waits for max_ack_delay (25 ms, three steps)
        var ce = false
        val (p, c) = pair { ecnToServer = { e -> if (ce && e == Ecn.Ect0) Ecn.Ce else e } }
        try {
            transfer(p, c, 50_000)
            assertEquals(EcnState.Capable, c.stats.ecnState)

            fun stepsToAck(): Int {
                p.runUntil(1.seconds) { false } // quiet
                val id = c.openStream(true)
                c.writeStream(id, ByteArray(100), 0, 100, true)
                var steps = 0
                while (steps < 20) {
                    p.step()
                    steps++
                    if (c.stats.bytesInFlight == 0L) break
                }
                return steps
            }
            assertTrue(stepsToAck() > 1, "control: an unmarked lone packet waits for the delayed ACK")
            ce = true
            assertEquals(1, stepsToAck(), "a CE-marked packet is acknowledged in the round it arrived")
        } finally {
            p.close()
        }
    }
}
