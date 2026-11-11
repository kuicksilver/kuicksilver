// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.NewReno
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.TimeMark
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

@OptIn(ExperimentalKuicksilverApi::class)
class NewRenoTest {
    private val t0 = TimeMark(5_000_000_000L)
    private val srtt = 100.milliseconds

    private fun sendAndAck(
        cc: NewReno,
        bytes: Int,
        sentAt: TimeMark,
        ackAt: TimeMark,
        appLimited: Boolean = false,
    ) {
        cc.onPacketSent(sentAt, bytes)
        cc.onAck(ackAt, sentAt, bytes, srtt, appLimited)
    }

    @Test fun initialWindow12000At1200() {
        assertEquals(12000L, NewReno(1200).cwnd)
        assertIs<io.kuicksilver.quic.Cubic>(QuicConfig.Default.congestionController())
        assertIs<NewReno>(
            io.kuicksilver.quic
                .quicConfig {
                    congestionController =
                        { NewReno() }
                }.congestionController(),
        )
    }

    @Test fun initialWindowFor1452() = assertEquals(14520L, NewReno(1452).cwnd)

    @Test fun minimumWindow2400() {
        val cc = NewReno(1200)
        cc.onPacketSent(t0, 1200)
        cc.onLoss(t0 + 1.milliseconds, 1200, t0, persistentCongestion = true)
        assertEquals(2400L, cc.cwnd)
        cc.onPacketSent(t0 + 2.milliseconds, 1200)
        cc.onLoss(t0 + 3.milliseconds, 1200, t0 + 2.milliseconds, false)
        assertEquals(2400L, cc.cwnd)
    }

    @Test fun slowStartGrowsByAckedBytes() {
        val cc = NewReno(1200)
        sendAndAck(cc, 1200, t0, t0 + srtt)
        assertEquals(13200L, cc.cwnd)
        assertEquals(0L, cc.bytesInFlight)
    }

    @Test fun lossHalvesWindow() {
        val cc = NewReno(1200)
        cc.onPacketSent(t0, 1200)
        cc.onLoss(t0 + srtt, 1200, t0, false)
        assertEquals(6000L, cc.cwnd)
        assertEquals(6000L, cc.ssthresh)
        assertEquals(0L, cc.bytesInFlight)
    }

    @Test fun noSecondReductionInsideRecovery() {
        val cc = NewReno(1200)
        cc.onPacketSent(t0, 1200)
        cc.onPacketSent(t0 + 1.milliseconds, 1200)
        cc.onLoss(t0 + srtt, 1200, t0, false)
        assertEquals(6000L, cc.cwnd)
        cc.onLoss(t0 + srtt + 1.milliseconds, 1200, t0 + 1.milliseconds, false)
        assertEquals(6000L, cc.cwnd, "a loss of a packet sent before recovery started is the same event")
        cc.onPacketSent(t0 + srtt + 2.milliseconds, 1200)
        cc.onLoss(t0 + srtt * 2, 1200, t0 + srtt + 2.milliseconds, false)
        assertEquals(3000L, cc.cwnd, "a packet sent after recovery started is a new event")
    }

    @Test fun congestionAvoidanceOneDatagramPerWindow() {
        val cc = NewReno(1200)
        cc.onPacketSent(t0, 1200)
        cc.onLoss(t0 + srtt, 1200, t0, false)
        assertEquals(6000L, cc.cwnd)
        val start = t0 + srtt + 1.milliseconds
        repeat(5) { sendAndAck(cc, 1200, start + it.milliseconds, start + srtt + it.milliseconds) } // a full window acknowledged
        assertTrue(cc.cwnd in 7100L..7200L, "about one datagram per window (RFC 9002 B.5 per-ACK formula, integer math): ${cc.cwnd}")
    }

    @Test fun persistentCongestionCollapsesToMinimum() {
        val cc = NewReno(1200)
        cc.onPacketSent(t0, 6000)
        cc.onLoss(t0 + 2000.milliseconds, 6000, t0, persistentCongestion = true)
        assertEquals(2400L, cc.cwnd)
    }

    @Test fun appLimitedDoesNotGrow() {
        val cc = NewReno(1200)
        sendAndAck(cc, 1200, t0, t0 + srtt, appLimited = true)
        assertEquals(12000L, cc.cwnd)
    }

    @Test fun ecnCeIsCongestionEvent() {
        val cc = NewReno(1200)
        cc.onPacketSent(t0, 1200)
        cc.onEcnCe(t0 + srtt, t0)
        assertEquals(6000L, cc.cwnd)
        assertTrue(cc.bytesInFlight == 1200L)
    }

    @Test fun congestionAvoidanceKeepsGrowingAboveMssSquared() {
        // RFC 9002 section 7.3.3: one maximum datagram per window of acknowledged bytes. 1200 x 1200 / cwnd is 0 in integer bytes
        // once cwnd > 1.44 MB, so growth used to stop there; the remainder now carries over
        val cc = NewReno(1200)
        var t = t0
        while (cc.cwnd < 2_000_000L) {
            sendAndAck(cc, 1200, t, t + srtt)
            t += 1.milliseconds
        }
        cc.onPacketSent(t, 1200)
        cc.onLoss(t + srtt, 1200, t, false) // into congestion avoidance at about 1 MB
        t += srtt * 2
        while (cc.cwnd < 1_500_000L) {
            val before = cc.cwnd
            repeat((cc.cwnd / 1200).toInt()) { i -> sendAndAck(cc, 1200, t + i.milliseconds / 1000, t + srtt) }
            assertTrue(cc.cwnd >= before + 1100, "about one datagram per window at cwnd $before: ${cc.cwnd}")
            t += srtt * 2
        }
    }

    /**
     * RFC 9002 section 7.2: "If the maximum datagram size changes during the connection, the initial congestion window SHOULD be
     * recalculated with the new size. If the maximum datagram size is decreased ..., the congestion window SHOULD be set to the
     * new initial congestion window." Only the minimum window used to follow the size. A larger size never raises the window
     * (RFC 8899 section 3 item 7), and a window that has moved keeps its bytes.
     */
    @Test fun theInitialWindowFollowsTheDatagramSize() {
        for (cc in listOf<io.kuicksilver.quic.CongestionController>(NewReno(1500), io.kuicksilver.quic.Cubic(1500))) {
            assertEquals(14_720L, cc.cwnd)
            cc.onMtuUpdate(1200)
            assertEquals(12_000L, cc.cwnd, "${cc::class.simpleName}: the initial window of 1200-byte datagrams")
            cc.onMtuUpdate(1452)
            assertEquals(12_000L, cc.cwnd, "${cc::class.simpleName}: a larger size does not raise it")
        }
        val grown = NewReno(1500)
        grown.onPacketSent(t0, 1500)
        grown.onAck(t0 + 10.milliseconds, t0, 1500, 10.milliseconds, false)
        grown.onMtuUpdate(1200)
        assertEquals(14_720L + 1500, grown.cwnd, "a window that grew keeps its bytes")
    }

    /**
     * After a collapse to 2 x 1200 bytes and a datagram size raised to 9000, the minimum window (2 x 9000) is above the window: a
     * reduction used to lift the window to it, 2 400 to 18 000 bytes on a loss, which RFC 8899 section 3 item 7 forbids for an MTU
     * update ("MUST NOT increase the congestion window measured in bytes"). A reduction never raises the window now.
     */
    @Test fun aReductionNeverLiftsTheWindowToALargerSizesMinimum() {
        for (make in listOf<() -> io.kuicksilver.quic.CongestionController>({ NewReno(1200) }, { io.kuicksilver.quic.Cubic(1200) })) {
            val cc = make()
            cc.onPacketSent(t0, 1200)
            cc.onLoss(t0 + 1.milliseconds, 1200, t0, persistentCongestion = true)
            assertEquals(2400L, cc.cwnd)
            cc.onMtuUpdate(9000)
            assertEquals(2400L, cc.cwnd, "${cc::class.simpleName}: the MTU update does not raise it")
            cc.onPacketSent(t0 + 2.milliseconds, 1200)
            cc.onLoss(t0 + 3.milliseconds, 1200, t0 + 2.milliseconds, false)
            assertTrue(cc.cwnd <= 2400L, "${cc::class.simpleName}: a loss does not raise it either (${cc.cwnd})")
            cc.onPacketSent(t0 + 4.milliseconds, 1200)
            cc.onLoss(t0 + 5.milliseconds, 1200, t0 + 4.milliseconds, persistentCongestion = true)
            assertTrue(cc.cwnd <= 2400L, "${cc::class.simpleName}: nor persistent congestion (${cc.cwnd})")
        }
    }
}
