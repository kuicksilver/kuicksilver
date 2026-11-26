// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.config

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class RateLimitTest {
    @Test
    fun smallestValuesAreOne() {
        val limit = RateLimit(1, 1)
        assertEquals(1, limit.perSecond)
        assertEquals(1, limit.burst)
    }

    @Test
    fun zeroOrNegativeRateIsRefusedWithItsName() {
        val e = assertFailsWith<IllegalArgumentException> { RateLimit(0, 10) }
        assertTrue("perSecond" in e.message.orEmpty(), e.message)
        assertFailsWith<IllegalArgumentException> { RateLimit(-1, 10) }
    }

    @Test
    fun zeroOrNegativeBurstIsRefusedWithItsName() {
        val e = assertFailsWith<IllegalArgumentException> { RateLimit(10, 0) }
        assertTrue("burst" in e.message.orEmpty(), e.message)
        assertFailsWith<IllegalArgumentException> { RateLimit(10, Int.MIN_VALUE) }
    }

    @Test
    fun equalityIsByValue() {
        assertEquals(RateLimit(33, 1000), RateLimit(33, 1000))
        assertEquals(RateLimit(33, 1000).hashCode(), RateLimit(33, 1000).hashCode())
        assertNotEquals(RateLimit(33, 1000), RateLimit(1000, 33))
        assertEquals("RateLimit(perSecond=33, burst=1000)", RateLimit(33, 1000).toString())
    }
}
