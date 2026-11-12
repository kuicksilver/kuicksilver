// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.CongestionController
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.recovery.SpaceId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * RFC 9002 section 7: "An endpoint MUST NOT send a packet if it would cause bytes_in_flight ... to be larger than the congestion
 * window, unless the packet is sent on a PTO timer expiration (see Section 6.2) or when entering recovery"; section 7.5: "Probe
 * packets MUST NOT be blocked by the congestion controller".
 */
@OptIn(ExperimentalKuicksilverApi::class)
class CongestionWindowTest {
    /** A window that never moves, [rate] bytes per second of pacing, [quantum] bytes per burst. */
    private class FixedWindow(
        override val cwnd: Long,
        private val rate: Long = 10_000_000_000L,
        override val sendQuantum: Int = 65_536,
    ) : CongestionController {
        override var bytesInFlight: Long = 0
            private set

        override fun onPacketSent(
            now: TimeMark,
            bytes: Int,
        ) {
            bytesInFlight += bytes
        }

        override fun onAck(
            now: TimeMark,
            sentTime: TimeMark,
            bytes: Int,
            smoothedRtt: Duration,
            appLimited: Boolean,
        ) {
            bytesInFlight -= bytes
        }

        override fun onLoss(
            now: TimeMark,
            lostBytes: Int,
            largestLostSentTime: TimeMark,
            persistentCongestion: Boolean,
        ) {
            bytesInFlight -= lostBytes
            losses++
        }

        /** Congestion events (losses) reported. */
        var losses = 0

        override fun onEcnCe(
            now: TimeMark,
            sentTime: TimeMark,
        ) {}

        override fun onMtuUpdate(maxDatagramSize: Int) {}

        override fun onDiscarded(bytes: Int) {
            bytesInFlight -= bytes
        }

        override fun pacingRate(smoothedRtt: Duration): Long = rate
    }

    private fun confirmedPair(cc: () -> CongestionController): CorePair {
        val p = CorePair(clientQuic = quicConfig { congestionController = cc })
        assertTrue(p.handshake())
        assertTrue(p.runUntil { p.client.state == ConnectionState.Confirmed })
        p.runUntil(200.milliseconds) { p.client.stats.bytesInFlight == 0L }
        return p
    }

    /** Writes far more than the window holds, then polls without delivering anything: what goes out must stay within [cwnd]. */
    private fun fillWindow(
        p: CorePair,
        c: ConnectionCore,
        batch: PacketBatch,
    ) {
        val id = c.openStream(true)
        c.writeStream(id, ByteArray(200_000), 0, 200_000, false)
        repeat(5) {
            batch.clear()
            c.poll(batch, p.now)
            assertTrue(
                c.cc.bytesInFlight <= c.cc.cwnd,
                "bytes in flight ${c.cc.bytesInFlight} above the window ${c.cc.cwnd} after poll $it",
            )
            p.advance(1.milliseconds)
        }
    }

    /**
     * A PTO probe still owed in a space when the space is discarded (a server's Initial probe that its anti-amplification budget
     * held back, then the client's Handshake packet) used to stay owed for ever, and every later datagram was treated as a probe,
     * outside the window.
     */
    @Test fun aProbeLeftInADiscardedSpaceDoesNotLiftTheWindow() {
        val p = CorePair(clientQuic = quicConfig { congestionController = { FixedWindow(12_000) } })
        val batch = PacketBatch(64)
        try {
            val c = p.client
            assertTrue(p.runUntil { c.writeKeys[2] != null && !c.spaceDiscarded[SpaceId.Handshake.ordinal] })
            c.probePending[SpaceId.Handshake.ordinal] = 2
            c.discardSpace(SpaceId.Handshake)
            assertEquals(0, c.probePending[SpaceId.Handshake.ordinal], "a discarded space owes no probe")
            assertTrue(p.handshake())
            assertTrue(p.runUntil { c.state == ConnectionState.Confirmed })
            p.runUntil(200.milliseconds) { c.stats.bytesInFlight == 0L }
            c.probePending[SpaceId.Initial.ordinal] = 1 // a count left behind in a space that is gone exempts nothing either
            fillWindow(p, c, batch)
        } finally {
            batch.close()
            p.close()
        }
    }

    /**
     * A window of 10.5 datagrams: the check used to stop only once bytes in flight reached the window, so the eleventh datagram
     * went out with 600 bytes of room and left 600 bytes more in flight than the window allows.
     */
    @Test fun noDatagramTakesBytesInFlightAboveTheWindow() {
        val p = confirmedPair { FixedWindow(12_600) }
        val batch = PacketBatch(64)
        try {
            fillWindow(p, p.client, batch)
            assertEquals(12_000L, p.client.cc.bytesInFlight, "ten full datagrams; the eleventh does not fit")
        } finally {
            batch.close()
            p.close()
        }
    }

    /** RFC 9002 section 7.5: the pacer held a PTO probe back when its bucket was empty. */
    @Test fun thePacerDoesNotHoldAProbeBack() {
        val p = confirmedPair { FixedWindow(1_000_000, rate = 1_000_000, sendQuantum = 12_000) }
        val batch = PacketBatch(64)
        try {
            val c = p.client
            val id = c.openStream(true)
            c.writeStream(id, ByteArray(100_000), 0, 100_000, false)
            assertTrue(c.poll(batch, p.now) >= 9, "one burst goes")
            batch.clear()
            assertEquals(0, c.poll(batch, p.now), "the bucket is empty: the pacer holds the next datagram")
            batch.clear()
            c.probePending[SpaceId.Application.ordinal] = 1
            assertEquals(1, c.poll(batch, p.now), "the probe goes at once")
            assertEquals(0, c.probePending[SpaceId.Application.ordinal])
        } finally {
            batch.close()
            p.close()
        }
    }

    /**
     * RFC 9000 section 14.4: "PMTU probes consume congestion window"; RFC 9002 section 2 counts every ack-eliciting packet in
     * flight. A DPLPMTUD probe used to bypass the window and never count in flight (a comment even cited section 14.4 for it).
     * It now waits for room, counts in flight, and its loss takes it out of flight without a congestion event.
     */
    @Test fun aPmtuProbeCountsInFlightAndWaitsForTheWindow() {
        val cc = FixedWindow(12_000)
        val p = confirmedPair { cc }
        val batch = PacketBatch(64)
        try {
            val c = p.client
            val id = c.openStream(true)
            c.writeStream(id, ByteArray(12_000), 0, 12_000, false)
            batch.clear()
            c.poll(batch, p.now)
            assertEquals(12_000L, c.cc.bytesInFlight, "the window is full")
            c.path.pmtud = Pmtud(upperBound = 1500) // a probe (1340 bytes) is due at once
            batch.clear()
            c.poll(batch, p.now)
            assertEquals(0, c.pmtudProbesSentForTest, "no room in the window: the probe waits")
            assertEquals(0, c.path.pmtud!!.probeInFlightForTest)
            // everything is acknowledged: the probe goes and counts in flight
            assertTrue(p.runUntil(2.seconds) { c.pmtudProbesSentForTest > 0 })
            val probe = c.path.pmtud!!.probeInFlightForTest
            assertEquals(1340, probe)
            assertTrue(c.cc.bytesInFlight >= probe, "the probe is in flight: ${c.cc.bytesInFlight}")
            assertTrue(c.loss.bytesInFlight >= probe)
        } finally {
            batch.close()
            p.close()
        }
    }

    @Test fun aLostPmtuProbeLeavesFlightWithoutACongestionEvent() {
        val cc = FixedWindow(100_000)
        val p = confirmedPair { cc }
        try {
            val c = p.client
            p.filterToServer = { _, b -> b.size <= 1200 } // the path carries 1200 bytes at most
            c.path.pmtud = Pmtud(upperBound = 1500)
            assertTrue(p.runUntil(1.seconds) { c.pmtudProbesSentForTest > 0 })
            assertTrue(c.cc.bytesInFlight >= 1340)
            val id = c.openStream(true)
            c.writeStream(id, ByteArray(5_000), 0, 5_000, true) // later packets get through, so the probe is declared lost
            // the congestion window lets go of it once loss detection declares it lost; DPLPMTUD gives the probe up only when its
            // PROBE_TIMER expires (RFC 8899 section 5.1.1)
            assertTrue(p.runUntil(3.seconds) { c.stats.lostPackets > 0 && c.stats.bytesInFlight == 0L })
            assertEquals(0L, c.cc.bytesInFlight, "the probe left flight")
            assertEquals(0, cc.losses, "a lost probe is no congestion signal")
            assertTrue(c.stats.lostPackets > 0, "the probe was declared lost")
        } finally {
            p.close()
        }
    }

    /**
     * A window of 2 400 bytes on a path whose MTU is 9 000 (the window collapsed before the MTU grew, and RFC 8899 section 3 item 7
     * keeps it from growing with the MTU): a datagram used to go only when a whole MTU fitted, so nothing was ever sent again.
     * With at least 1 200 bytes of room the datagram is cut to the room.
     */
    @Test fun aWindowSmallerThanTheMtuStillCarriesData() {
        val p = confirmedPair { FixedWindow(2_400) }
        val batch = PacketBatch(16, 9_000)
        try {
            val c = p.client
            c.path.mtu = 9_000
            val id = c.openStream(true)
            c.writeStream(id, ByteArray(20_000), 0, 20_000, false)
            val n = c.poll(batch, p.now)
            assertTrue(n >= 1, "data goes out")
            for (i in 0 until n) assertTrue(batch.length(i) <= 2_400, "datagram of ${batch.length(i)} bytes")
            assertTrue(c.cc.bytesInFlight in 1_200L..2_400L, "in flight ${c.cc.bytesInFlight}")
        } finally {
            batch.close()
            p.close()
        }
    }
}
