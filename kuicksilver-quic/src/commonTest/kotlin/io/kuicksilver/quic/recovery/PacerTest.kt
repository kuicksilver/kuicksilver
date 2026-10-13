// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.NewReno
import io.kuicksilver.quic.TimeMark
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
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
}
