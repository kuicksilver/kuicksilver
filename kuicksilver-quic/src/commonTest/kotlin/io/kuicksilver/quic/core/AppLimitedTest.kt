// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.NewReno
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.endpoint.EndpointPair
import io.kuicksilver.quic.recovery.CongestionEvent
import io.kuicksilver.quic.recovery.CongestionKind
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

/**
 * RFC 9002 section 7.8: the window grows only on ACKs of a sender that used it. The core judges that per ACK frame from what was in
 * flight before the frame (as quic-go's isCwndLimited(priorInFlight)), not from what is left after the frame's earlier packets.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class AppLimitedTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val t0 = TimeMark(50_000_000_000L)

    private fun withListener(block: (ConnectionLossListener) -> Unit) {
        val p = EndpointPair()
        try {
            val c: ConnectionCore = p.connect()
            assertTrue(p.confirmed(c))
            block(ConnectionLossListener(c))
        } finally {
            p.close()
        }
    }

    /** One ACK frame acknowledging [packets] packets of 1200 bytes sent at [sent], as loss detection reports it. */
    private fun ackFrame(
        l: ConnectionLossListener,
        cc: NewReno,
        packets: Int,
        sent: TimeMark,
        now: TimeMark,
    ) {
        l.onAckFrameStart()
        val e = CongestionEvent()
        repeat(packets) {
            e.kind = CongestionKind.Acked
            e.bytes = 1200
            e.sentTime = sent
            e.now = now
            e.pathId = 0
            e.cc = cc
            l.onCongestion(e)
        }
        l.onAckProcessed(now)
    }

    @Test fun aFullWindowAcknowledgedInOneFrameGrowsByAllOfIt() {
        // slow start: ten packets fill the 12 000-byte window; one ACK frame for all ten must count all ten (the old test, bytes in
        // flight below cwnd / 2 after each packet, called the second half of the frame application-limited)
        withListener { l ->
            val cc = NewReno(1200)
            repeat(10) { cc.onPacketSent(t0, 1200) }
            ackFrame(l, cc, 10, t0, t0 + 50.milliseconds)
            assertEquals(24_000L, cc.cwnd)
        }
    }

    @Test fun congestionAvoidanceDoesNotGrowOnAFifthOfTheWindowUnused() {
        // congestion avoidance with 80 % of the window in flight: 12 000 bytes unused are far more than a burst, the sender is
        // application-limited (quic-go: available bytes > 3 datagrams), so the window must not grow
        withListener { l ->
            val cc = NewReno(1200)
            var t = t0
            while (cc.cwnd < 120_000L) {
                cc.onPacketSent(t, 1200)
                cc.onAck(t + 50.milliseconds, t, 1200, 50.milliseconds, false)
                t += 1.milliseconds
            }
            cc.onPacketSent(t, 1200)
            cc.onLoss(t + 50.milliseconds, 1200, t, false) // congestion avoidance at 60 000
            val cwnd = cc.cwnd
            t += 100.milliseconds
            repeat(40) { cc.onPacketSent(t, 1200) }
            ackFrame(l, cc, 40, t, t + 50.milliseconds)
            assertEquals(cwnd, cc.cwnd, "48 000 of 60 000 in flight")
        }
    }
}
