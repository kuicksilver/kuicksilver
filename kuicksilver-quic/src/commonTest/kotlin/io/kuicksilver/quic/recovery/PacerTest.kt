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

    @Test fun sendQuantumCapped() {
        assertEquals(12000, NewReno(1200).sendQuantum)
        assertTrue(NewReno(65527).sendQuantum <= 65_536)
    }
}
