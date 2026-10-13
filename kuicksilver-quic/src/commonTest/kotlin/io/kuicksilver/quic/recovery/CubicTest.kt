// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.Cubic
import io.kuicksilver.quic.TimeMark
import kotlin.math.cbrt
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** RFC 9438 CUBIC with RFC 9406 HyStart++: byte arithmetic, C = 0.4, beta = 0.7, fast convergence, Reno-friendly region. */
@OptIn(ExperimentalKuicksilverApi::class)
class CubicTest {
    private val t0 = TimeMark(5_000_000_000L)
    private val srtt = 100.milliseconds
    private val mss = 1200

    private fun sendAndAck(
        cc: Cubic,
        bytes: Int,
        sentAt: TimeMark,
        ackAt: TimeMark,
        rtt: Duration = srtt,
        appLimited: Boolean = false,
    ) {
        cc.onPacketSent(sentAt, bytes)
        cc.onAck(ackAt, sentAt, bytes, rtt, appLimited)
    }

    /** One loss at t0 from the initial window: cwnd 12000 -> 8400, W_max 12000, recovery started at t0 + srtt. */
    private fun afterFirstLoss(): Cubic {
        val cc = Cubic(mss)
        cc.onPacketSent(t0, mss)
        cc.onLoss(t0 + srtt, mss, t0, false)
        return cc
    }

    /** Acknowledges [windows] full windows one datagram at a time, RTT by RTT, starting at [from]; returns the time after the last ACK. */
    private fun ackWindows(
        cc: Cubic,
        from: TimeMark,
        windows: Int,
        rtt: Duration = srtt,
    ): TimeMark {
        var t = from
        repeat(windows) {
            val n =
                (
                    cc.cwnd /
                        mss
                ).toInt()
            ; repeat(n) { i -> sendAndAck(cc, mss, t + i.milliseconds, t + rtt + i.milliseconds, rtt) }
            t += rtt
        }
        return t
    }

    @Test fun initialWindowLikeNewReno() {
        assertEquals(12000L, Cubic(1200).cwnd)
        assertEquals(14520L, Cubic(1452).cwnd)
        assertEquals(Long.MAX_VALUE, Cubic().ssthresh)
    }

    @Test fun lossReducesToSeventyPercent() {
        val cc = afterFirstLoss()
        assertEquals(8400L, cc.cwnd)
        assertEquals(8400L, cc.ssthresh)
        assertEquals(12000L, cc.wMax)
        assertEquals(0L, cc.bytesInFlight)
    }

    @Test fun fastConvergenceLowersWmax() {
        // a second loss below the previous W_max: the flow is losing out, so W_max comes down to cwnd (1 + beta) / 2 (RFC 9438 section 4.6)
        val cc = afterFirstLoss()
        val t = t0 + srtt + 1.milliseconds
        cc.onPacketSent(t, mss)
        cc.onLoss(t + srtt, mss, t, false)
        assertEquals(8400L * 17 / 20, cc.wMax, "W_max = 8400 x 1.7 / 2")
        assertEquals(8400L * 7 / 10, cc.cwnd)
    }

    @Test fun growthReachesWmaxAtK() {
        // RFC 9438 section 4.2: K = cbrt((W_max - cwnd) / C) in RTT-independent seconds; the window is back at W_max after K. A large window on a
        // 100 ms RTT, where the cubic curve outruns the Reno-friendly estimate (small windows on short RTTs stay in the Reno region by design, section 4.3)
        val cc = Cubic(mss)
        var t = t0
        while (cc.cwnd < 1_440_000L) {
            sendAndAck(cc, mss, t, t + srtt)
            t += 1.milliseconds
        } // slow start to 1200 datagrams
        val w0 = cc.cwnd
        cc.onPacketSent(t, mss)
        cc.onLoss(t + srtt, mss, t, false)
        val w1 = cc.cwnd
        assertEquals(w0, cc.wMax)
        assertEquals(w0 * 7 / 10, w1)
        val k = cbrt((w0 - w1).toDouble() / mss / 0.4)
        assertTrue(k in 9.0..10.5, "K = $k s")
        val start = t + srtt
        t = start + 1.milliseconds
        while (t < start + k.seconds) {
            val n = (cc.cwnd / mss).toInt()
            repeat(n) { i -> sendAndAck(cc, mss, t, t + srtt) }
            t += srtt
        }
        assertTrue(cc.cwnd in (w0 - 2 * mss)..(w0 + 2 * mss), "cwnd ${cc.cwnd} at K = ${k}s, W_max $w0")
    }

    @Test fun renoFriendlyRegionOnShortRtt() {
        // RFC 9438 section 4.3: on a short RTT the cubic curve is slower than Reno, so the window follows the Reno estimate (alpha = 3(1 - beta)/(1 + beta) = 0.529 MSS per RTT)
        val cc = afterFirstLoss()
        val before = cc.cwnd
        ackWindows(cc, t0 + srtt + 1.milliseconds, 20, rtt = 1.milliseconds)
        val renoEstimate = before + (20 * 0.529 * mss * 0.8).toLong() // 20 RTTs of growth, with slack for integer math
        assertTrue(cc.cwnd >= renoEstimate, "cwnd ${cc.cwnd} should grow at least like Reno ($renoEstimate) on a 1 ms RTT")
    }

    @Test fun appLimitedDoesNotGrow() {
        val cc = Cubic(mss)
        sendAndAck(cc, mss, t0, t0 + srtt, appLimited = true)
        assertEquals(12000L, cc.cwnd)
        val c2 = afterFirstLoss()
        sendAndAck(
            c2,
            mss,
            t0 + srtt + 1.milliseconds,
            t0 + srtt * 2,
            appLimited = true,
        )
        assertEquals(8400L, c2.cwnd)
    }

    @Test fun persistentCongestionToMinimum() {
        val cc = Cubic(mss)
        cc.onPacketSent(t0, 6000)
        cc.onLoss(t0 + 2.seconds, 6000, t0, persistentCongestion = true)
        assertEquals(2400L, cc.cwnd)
    }

    @Test fun ecnCeIsCongestionEvent() {
        val cc = Cubic(mss)
        cc.onPacketSent(t0, mss)
        cc.onEcnCe(t0 + srtt, t0)
        assertEquals(8400L, cc.cwnd)
        assertEquals(1200L, cc.bytesInFlight)
    }

    @Test fun noSecondReductionInsideRecovery() {
        val cc = Cubic(mss)
        cc.onPacketSent(t0, mss)
        cc.onPacketSent(t0 + 1.milliseconds, mss)
        cc.onLoss(t0 + srtt, mss, t0, false)
        assertEquals(8400L, cc.cwnd)
        cc.onLoss(t0 + srtt + 1.milliseconds, mss, t0 + 1.milliseconds, false)
        assertEquals(8400L, cc.cwnd, "a loss of a packet sent before recovery started is the same event")
        cc.onPacketSent(t0 + srtt + 2.milliseconds, mss)
        cc.onLoss(t0 + srtt * 2, mss, t0 + srtt + 2.milliseconds, false)
        assertEquals(5880L, cc.cwnd, "a packet sent after recovery started is a new event")
    }

    /** One HyStart++ round: 8 packets sent, 8 RTT samples and ACKs of exactly those packets. Returns the time after the round. */
    private fun round(
        cc: Cubic,
        start: TimeMark,
        rtt: Duration,
        min: Duration,
    ): TimeMark {
        repeat(8) { i -> cc.onPacketSent(start + i.milliseconds, mss) }
        repeat(8) { i ->
            val sent =
                start + i.milliseconds
            val ack = sent + rtt
            cc.onRttSample(ack, rtt, min)
            cc.onAck(ack, sent, mss, rtt, appLimited = false)
        }
        return start + rtt + 10.milliseconds
    }

    @Test fun hystartEntersCssOnRttIncrease() {
        // RFC 9406: a round whose min RTT exceeds the previous round's by max(4 ms, min(16 ms, lastMin / 8)) enters Conservative Slow Start: growth divided by 4
        val cc = Cubic(mss)
        var t = round(cc, t0, 50.milliseconds, 50.milliseconds)
        val afterRound1 = cc.cwnd
        assertEquals(12000L + 8 * mss, afterRound1, "plain slow start in the first round")
        t = round(cc, t, 60.milliseconds, 50.milliseconds)
        assertTrue(cc.inConservativeSlowStart, "50 -> 60 ms crosses the 6.25 ms threshold")
        val before = cc.cwnd
        round(cc, t, 60.milliseconds, 50.milliseconds)
        assertEquals(before + 8 * mss / 4, cc.cwnd, "CSS grows at a quarter of the rate")
    }

    @Test fun hystartExitsAfterFiveCssRounds() {
        val cc = Cubic(mss)
        var t = round(cc, t0, 50.milliseconds, 50.milliseconds)
        t = round(cc, t, 60.milliseconds, 50.milliseconds)
        assertTrue(cc.inConservativeSlowStart)
        repeat(5) { t = round(cc, t, 60.milliseconds, 50.milliseconds) }
        assertTrue(cc.ssthresh <= cc.cwnd, "five CSS rounds end slow start: ssthresh ${cc.ssthresh} cwnd ${cc.cwnd}")
        assertTrue(!cc.inConservativeSlowStart)
    }

    @Test fun hystartBackToSlowStartWhenRttDrops() {
        val cc = Cubic(mss)
        var t = round(cc, t0, 50.milliseconds, 50.milliseconds)
        t = round(cc, t, 60.milliseconds, 50.milliseconds)
        assertTrue(cc.inConservativeSlowStart)
        // a CSS round whose RTT fell below the baseline; the verdict comes when the next round begins
        t = round(cc, t, 48.milliseconds, 48.milliseconds)
        val before = cc.cwnd
        round(cc, t, 48.milliseconds, 48.milliseconds)
        assertTrue(!cc.inConservativeSlowStart, "the RTT fell below the CSS baseline: back to slow start")
        assertEquals(before + 8 * mss, cc.cwnd, "plain slow start growth again")
        assertEquals(Long.MAX_VALUE, cc.ssthresh)
    }

    @Test fun idleTimeIsNotPartOfTheCubicEpoch() {
        // RFC 9438 section 4.2: "The elapsed time t in Figure 1 MUST NOT include periods during which cwnd has not been updated due to
        // application-limited behavior". After a loss and 30 s with nothing in flight, the curve resumes where it stopped (just
        // after the reduction, concave below W_max), it does not jump 30 s ahead to the 1.5 x cwnd clamp of the convex region
        val cc = afterFirstLoss()
        val t = ackWindows(cc, t0 + 30.seconds, 1)
        assertTrue(cc.cwnd < 8400L * 11 / 10, "one window 30 s after the loss: cwnd ${cc.cwnd}")
        ackWindows(cc, t, 1)
        assertTrue(cc.cwnd < 8400L * 12 / 10, "two windows: cwnd ${cc.cwnd}")
    }

    @Test fun applicationLimitedTimeIsNotPartOfTheCubicEpoch() {
        // the same for ACKs that arrive while the sender is application-limited (quic-go resets the epoch in OnApplicationLimited)
        val cc = afterFirstLoss()
        var t = t0 + srtt * 2
        repeat(300) {
            sendAndAck(cc, mss, t, t + srtt, appLimited = true)
            t += srtt
        } // 30 s of a trickle
        assertEquals(8400L, cc.cwnd)
        ackWindows(cc, t, 1)
        assertTrue(cc.cwnd < 8400L * 11 / 10, "one window after 30 s of application-limited ACKs: cwnd ${cc.cwnd}")
    }

    @Test fun renoFriendlyAlphaBecomesOneAtThePriorWindow() {
        // RFC 9438 section 4.3: "Once W_est has grown to reach the cwnd at the time of most recently setting ssthresh -- that is,
        // W_est >= cwnd_prior -- the sender SHOULD set alpha_cubic to 1": Reno's one datagram per RTT from then on
        val cc = afterFirstLoss()
        var t = t0 + srtt + 1.milliseconds
        while (cc.cwnd < 12000L) t = ackWindows(cc, t, 1, rtt = 1.milliseconds)
        val before = cc.cwnd
        ackWindows(cc, t, 10, rtt = 1.milliseconds)
        val grown = cc.cwnd - before
        assertTrue(grown >= 9L * mss, "10 RTTs above cwnd_prior grow by about 10 datagrams, not 10 x 0.529: $grown")
    }
}
