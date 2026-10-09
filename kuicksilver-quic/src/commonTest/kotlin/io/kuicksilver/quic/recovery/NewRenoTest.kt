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
}
