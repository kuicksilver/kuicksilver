// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

class TimeMarkTest {
    @Test fun plusSaturatesInsteadOfWrapping() {
        val late = TimeMark(Long.MAX_VALUE - 10)
        assertEquals(TimeMark.NEVER, late + 1.seconds)
        assertEquals(
            TimeMark.NEVER,
            TimeMark(5) + Duration.INFINITE,
        )
        assertEquals(TimeMark.NEVER, TimeMark.NEVER + 1.seconds)
    }

    @Test fun plusMinusRoundTrip() {
        val t = TimeMark(1_000_000_000L)
        val later = t + 1.5.seconds
        assertEquals(2_500_000_000L, later.nanos)
        assertEquals(1.5.seconds, later - t)
        assertEquals(t, later - 1.5.seconds)
    }

    @Test fun comparesByNanos() {
        assertTrue(TimeMark(1) < TimeMark(2))
        assertTrue(TimeMark(5) + 1.milliseconds > TimeMark(5))
        assertEquals(0, TimeMark(7).compareTo(TimeMark(7)))
    }
}
