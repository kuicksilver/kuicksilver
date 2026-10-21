// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.Bbr
import io.kuicksilver.quic.CongestionController
import io.kuicksilver.quic.Cubic
import io.kuicksilver.quic.NewReno
import io.kuicksilver.quic.TimeMark
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalKuicksilverApi::class)
class PacerTest {
    private val t0 = TimeMark(7_000_000_000L)

    @Test fun rateIs125PercentOfCwndPerSrtt() = assertEquals(150_000L, NewReno(1200).pacingRate(100.milliseconds))

    @Test fun burstUpToTenDatagrams() {
        val cc = NewReno(1200)
        val p = Pacer()
        repeat(10) {
            assertEquals(TimeMark.NEVER, p.nextSendTime(t0, 1200, cc, 100.milliseconds), "datagram ${it + 1} of the burst")
            p.onSent(t0, 1200)
        }
        val next = p.nextSendTime(t0, 1200, cc, 100.milliseconds)
        assertNotEquals(TimeMark.NEVER, next)
        assertEquals(t0 + 8.milliseconds, next) // 1200 B at 150 000 B/s
        assertEquals(TimeMark.NEVER, p.nextSendTime(next, 1200, cc, 100.milliseconds))
    }

    @Test fun noPacingBelow1msSrtt() {
        val cc = NewReno(1200)
        val p = Pacer()
        repeat(50) {
            assertEquals(TimeMark.NEVER, p.nextSendTime(t0, 1200, cc, 0.5.milliseconds))
            p.onSent(t0, 1200)
        }
    }

    /**
     * A bucket last refilled long ago is full, however long ago: rate x elapsed overflowed a Long (here 7.5 MB/s x 2000 s; in
     * the soak 115 MB/s x 80 s, after the loopback's smoothed RTT stayed below 1 ms, unpaced, for minutes and then reached it),
     * the negative refill was dropped without moving the refill time, and the pacer answered "a moment later" forever: the
     * sender stopped until the idle timeout (found by the soak harness on Linux).
     */
    @Test fun bucketRefillsAfterALongGap() {
        val cc = NewReno(1200)
        val p = Pacer()
        repeat(10) {
            p.nextSendTime(t0, 1200, cc, 2.milliseconds)
            p.onSent(t0, 1200)
        }
        assertNotEquals(TimeMark.NEVER, p.nextSendTime(t0, 1200, cc, 2.milliseconds), "the burst is spent")
        val later = t0 + 2000.seconds
        assertEquals(TimeMark.NEVER, p.nextSendTime(later, 1200, cc, 2.milliseconds), "a full bucket after the gap")
        repeat(10) {
            assertEquals(TimeMark.NEVER, p.nextSendTime(later, 1200, cc, 2.milliseconds), "datagram ${it + 1} of the new burst")
            p.onSent(later, 1200)
        }
    }

    @Test fun sendQuantumCapped() {
        assertEquals(12000, NewReno(1200).sendQuantum)
        assertTrue(NewReno(65527).sendQuantum <= 65_536)
    }

    /** A controller with a fixed pacing rate, as a 10 Gbit/s path would give any of them. */
    private class FixedRate(
        private val rate: Long,
    ) : CongestionController {
        override fun onPacketSent(
            now: TimeMark,
            bytes: Int,
        ) {}

        override fun onAck(
            now: TimeMark,
            sentTime: TimeMark,
            bytes: Int,
            smoothedRtt: Duration,
            appLimited: Boolean,
        ) {}

        override fun onLoss(
            now: TimeMark,
            lostBytes: Int,
            largestLostSentTime: TimeMark,
            persistentCongestion: Boolean,
        ) {}

        override fun onEcnCe(
            now: TimeMark,
            sentTime: TimeMark,
        ) {}

        override fun onMtuUpdate(maxDatagramSize: Int) {}

        override fun onDiscarded(bytes: Int) {}

        override val cwnd: Long = Long.MAX_VALUE / 4
        override val bytesInFlight: Long = 0

        override fun pacingRate(smoothedRtt: Duration): Long = rate

        override val sendQuantum: Int = 65_536
    }

    private fun drainThenIdle(
        cc: CongestionController,
        idle: Duration,
    ) {
        val p = Pacer()
        var now = t0
        var sent = 0L
        while (p.nextSendTime(now, 1200, cc, 10.milliseconds) == TimeMark.NEVER) {
            p.onSent(now, 1200)
            sent += 1200
        }
        assertTrue(sent <= 65_536 + 1200, "first burst $sent bytes")
        now += idle
        // rate x idle overflows a Long here (1.25e9 B/s x 1e10 ns): the bucket must still refill, to the burst and no more
        var burst = 0L
        while (p.nextSendTime(now, 1200, cc, 10.milliseconds) == TimeMark.NEVER) {
            p.onSent(now, 1200)
            burst += 1200
            assertTrue(burst <= 65_536 + 1200, "the bucket overflowed: $burst bytes at once after $idle idle")
        }
        assertTrue(burst >= 60_000, "after $idle idle only $burst bytes may leave at once: the pacer stalled")
        val next = p.nextSendTime(now, 1200, cc, 10.milliseconds)
        assertTrue(next > now && next <= now + 1.milliseconds, "next send at $next, now $now")
    }

    @Test fun aLongIdleGapAtTenGbitPerSecondRefillsTheBucket() {
        drainThenIdle(FixedRate(1_250_000_000L), 10.seconds) // BBR review: rate x elapsed wrapped negative and never refilled
        drainThenIdle(FixedRate(12_500_000_000L), 100.seconds) // 100 Gbit/s
    }

    @Test fun cubicAfterALongIdleGapSendsAtOnce() {
        val cc = Cubic(1200)
        val p = Pacer()
        p.onSent(t0, 1200)
        assertEquals(TimeMark.NEVER, p.nextSendTime(t0 + 20_000.seconds, 1200, cc, 10.milliseconds))
    }

    @Test fun bbrIsPacedEvenBelow1msSrtt() {
        // BBR review: at 0.2 ms the window-only exemption made BBR's pacing gains do nothing on a LAN
        val cc = Bbr(1200)
        val p = Pacer()
        val srtt = 0.2.milliseconds
        var n = 0
        while (p.nextSendTime(t0, 1200, cc, srtt) == TimeMark.NEVER && n < 1000) {
            p.onSent(t0, 1200)
            n++
        }
        assertTrue(n * 1200 <= cc.sendQuantum + 1200, "$n datagrams at once at 0.2 ms")
        assertNotEquals(TimeMark.NEVER, p.nextSendTime(t0, 1200, cc, srtt))
    }
}
