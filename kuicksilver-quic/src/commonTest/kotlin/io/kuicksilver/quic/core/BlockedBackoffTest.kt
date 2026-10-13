// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.TestFrame
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.nullOneRttFrames
import io.kuicksilver.quic.quicConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * How often a sender blocked by flow control repeats DATA_BLOCKED / STREAM_DATA_BLOCKED ([onBlockedRepeatTimer]): as fast as
 * before for the first [BLOCKED_FAST_REPEATS] repeats at a limit (a lost MAX_DATA is found quickly), then at doubling gaps up
 * to a third of the idle timeout, so a receiver that stops reading costs a few reports per idle period instead of one every
 * 8 PTO, and the reports still keep the connection from idling out.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class BlockedBackoffTest {
    @Test fun repeatGapsStayFastThenDoubleUpToAThirdOfTheIdleTimeout() {
        val pto = 100.milliseconds
        val idle = 30.seconds
        val gaps = (0 until 200).map { blockedRepeatGap(it, pto, idle) / pto }
        assertEquals(listOf(1.0, 2.0, 4.0), gaps.take(3), "the first repeats as before: 1, 2 and 4 PTO")
        assertTrue(gaps.subList(3, BLOCKED_FAST_REPEATS).all { it == 8.0 }, "then 8 PTO through repeat $BLOCKED_FAST_REPEATS: $gaps")
        assertEquals(listOf(16.0, 32.0, 64.0, 100.0, 100.0), gaps.subList(BLOCKED_FAST_REPEATS, BLOCKED_FAST_REPEATS + 5))
        assertTrue(gaps.drop(BLOCKED_FAST_REPEATS + 3).all { it == 100.0 }, "and at most idle / 3 = 10 s from then on: $gaps")
        assertEquals(10.seconds, blockedRepeatGap(Int.MAX_VALUE, pto, idle), "no overflow however long the block")
    }

    @Test fun repeatGapCapFollowsTheIdleTimeout() {
        val pto = 100.milliseconds
        assertEquals(10.seconds, blockedRepeatCap(30.seconds))
        assertEquals(1.seconds, blockedRepeatCap(3.seconds))
        // no idle timeout on either side: nothing to keep alive, the gap still stops growing at a fixed 10 s
        assertEquals(BLOCKED_REPEAT_CAP_WITHOUT_IDLE, blockedRepeatCap(Duration.INFINITE))
        assertEquals(10.seconds, BLOCKED_REPEAT_CAP_WITHOUT_IDLE)
        assertEquals(10.seconds, blockedRepeatGap(1000, pto, Duration.INFINITE))
        // the effective idle timeout is at least 3 PTO (RFC 9000 section 10.1): then every gap is one PTO, early ones included
        assertTrue((0 until 50).all { blockedRepeatGap(it, pto, pto * 3) == pto })
    }

    /** A client whose server never reads: the times of the client's datagrams carrying a *_BLOCKED report. */
    private class Blocked(
        val p: CorePair,
        val id: Long,
    ) {
        val reports = ArrayList<TimeMark>()
        var frames = 0

        /** When the client last sent STREAM data. */
        var lastDataAt = TimeMark.NEVER
        val data = ByteArray(65536)

        init {
            p.filterToServer = { _, b ->
                val f = nullOneRttFrames(b).orEmpty()
                if (f.any { it is TestFrame.Stream }) lastDataAt = p.now
                val n = f.count { it is TestFrame.DataBlocked || it is TestFrame.StreamDataBlocked }
                if (n > 0) {
                    reports += p.now
                    frames += n
                }
                true
            }
        }

        fun write() {
            while (p.client.writeStream(id, data, 0, data.size, false) > 0) Unit
        }

        fun run(limit: Duration) {
            p.runUntil(limit) {
                write()
                false
            }
        }

        fun gapsSince(i: Int): List<Duration> = (i + 1 until reports.size).map { reports[it] - reports[it - 1] }
    }

    private fun blocked(idle: Duration): Blocked {
        val q = quicConfig { maxIdleTimeout = idle }
        val p = CorePair(clientQuic = q, serverQuic = q)
        assertTrue(p.handshake())
        return Blocked(p, p.client.openStream(bidi = true, StreamPriority.Default))
    }

    @Test fun aLongBlockSendsAFewReportsPerIdlePeriodAndDoesNotIdleOut() {
        val b = blocked(30.seconds)
        try {
            b.run(10.minutes)
            val p = b.p
            assertNull(p.closedReason(p.clientEvents), "the reports keep the client open")
            assertNull(p.closedReason(p.serverEvents), "and the server")
            val gaps = b.gapsSince(0)
            val pto = p.client.pto()
            val tick = 5.milliseconds
            // each gap at least the previous one (PTO wobbles a little: one tick and a few ms of slack), never above the cap
            for (i in 1 until gaps.size) assertTrue(gaps[i] >= gaps[i - 1] - tick * 2, "gaps grow: $gaps")
            assertTrue(gaps.all { it <= 10.seconds + tick }, "no gap above idle / 3: $gaps")
            assertTrue(gaps.takeLast(20).all { it >= 10.seconds - tick }, "the last ones at the cap: $gaps")
            assertTrue(gaps.take(BLOCKED_FAST_REPEATS).all { it <= pto * 8 + tick * 2 }, "the first ones as fast as before: $gaps")
            // the schedule's count over 10 min: 1 report, 32 fast repeats (239 PTO, 8.6 s at 36 ms), at most 5 doubling ones
            // below the cap (16..256 PTO) and one every 10 s for what is left; 8 PTO repeats (2 000 of them) before
            assertTrue(b.reports.size <= 1 + BLOCKED_FAST_REPEATS + 5 + 60, "reports in 10 min: ${b.reports.size}, gaps $gaps")
            assertEquals(b.reports.size, b.frames, "one stream blocked: one frame per report")
        } finally {
            b.p.close()
        }
    }

    @Test fun aRaisedLimitThenANewBlockStartsTheFastScheduleAgain() {
        val b = blocked(30.seconds)
        try {
            b.run(3.minutes)
            val p = b.p
            assertTrue(b.gapsSince(0).last() >= 10.seconds - 5.milliseconds, "backed off to the cap: ${b.gapsSince(0)}")
            // the server reads a window's worth: MAX_STREAM_DATA lets the client send, and it blocks at the new limit
            val buf = ByteArray(65536)
            val s = p.server!!
            while (s.readStream(b.id, buf, 0, buf.size) > 0) Unit
            val before = b.reports.size
            b.run(2.seconds)
            val fresh = b.reports.subList(before, b.reports.size)
            // the window's worth of data takes a few hundred ms to send; the new limit goes out with its last bytes
            assertTrue(fresh.isNotEmpty() && fresh[0] - b.lastDataAt <= 5.milliseconds, "reported at once: $fresh, data ${b.lastDataAt}")
            val gaps = b.gapsSince(before)
            val pto = p.client.pto()
            val tick = 5.milliseconds
            assertTrue(gaps.size >= 4, "fast again: ${gaps.size} repeats in 2 s")
            for ((i, f) in listOf(1, 2, 4, 8).withIndex()) {
                assertTrue(gaps[i] >= pto * f - tick * 2 && gaps[i] <= pto * f + tick * 2, "gap $i about $f PTO ($pto): $gaps")
            }
        } finally {
            b.p.close()
        }
    }

    @Test fun aBlockedConnectionWithAShortIdleTimeoutDoesNotIdleOut() {
        // 100 ms idle: the effective timeout is 3 PTO (about 108 ms), shorter than the 4 and 8 PTO repeat gaps of old
        val b = blocked(100.milliseconds)
        try {
            b.run(5.seconds)
            val p = b.p
            assertNull(p.closedReason(p.clientEvents), "client open")
            assertNull(p.closedReason(p.serverEvents), "server open")
            assertTrue(b.reports.size > 20, "repeats at the 1 PTO cap: ${b.reports.size}")
        } finally {
            b.p.close()
        }
    }

    @Test fun withoutIdleTimeoutTheGapStopsAtTheFixedCap() {
        val b = blocked(Duration.ZERO)
        try {
            b.run(3.minutes)
            val gaps = b.gapsSince(0)
            assertTrue(gaps.takeLast(5).all { it in (10.seconds - 5.milliseconds)..(10.seconds + 5.milliseconds) }, "$gaps")
        } finally {
            b.p.close()
        }
    }
}
