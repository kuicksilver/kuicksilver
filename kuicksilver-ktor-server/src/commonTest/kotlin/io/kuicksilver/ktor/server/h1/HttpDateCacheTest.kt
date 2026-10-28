// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

import io.ktor.http.toHttpDate
import io.ktor.util.date.GMTDate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertSame

/**
 * The Date field value (RFC 9110 section 6.6.1, IMF-fixdate, one-second resolution) is formatted once per second, as
 * nginx and Go do, not for every response.
 */
class HttpDateCacheTest {
    @Test fun oneFormattingPerSecond() {
        var now = 1_793_000_000_123L
        val cache = HttpDateCache { now }
        val first = cache.now()
        assertEquals(GMTDate(now).toHttpDate(), first)
        now += 876 // the same second
        assertSame(first, cache.now(), "formatted again within the second")
        now += 1 // the next second
        val next = cache.now()
        assertNotEquals(first, next)
        assertEquals(GMTDate(now).toHttpDate(), next)
    }
}
