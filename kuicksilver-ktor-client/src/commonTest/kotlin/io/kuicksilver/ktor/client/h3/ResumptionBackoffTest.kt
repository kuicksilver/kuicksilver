// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h3

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The "no resumption" backoff after a `ServerConnectionIdChanged` on a resumed handshake (an msquic server, msquic#4905): the
 * broken alternatives' schedule, 5 minutes doubling at each new mark up to 2 days, per host, forgotten on a network change,
 * ended by whichever clock passes it first.
 */
class ResumptionBackoffTest {
    private var now = 1_000_000L
    private var wall = 5_000_000L

    private fun backoff() = ResumptionBackoff({ now }, { wall })

    private fun pass(ms: Long) {
        now += ms
        wall += ms
    }

    @Test fun theBackoffDoublesUpToTwoDaysAndEnds() {
        val b = backoff()
        assertFalse(b.avoids("a"))
        var period = ResumptionBackoff.BASE_MILLIS
        repeat(12) { i ->
            b.mark("a")
            assertEquals(i, b.levelForTest("a"))
            assertTrue(b.avoids("a"), "level $i")
            pass(period - 1)
            assertTrue(b.avoids("a"), "level $i: still within $period ms")
            pass(1)
            assertFalse(b.avoids("a"), "level $i: over after $period ms")
            period = minOf(period * 2, ResumptionBackoff.MAX_MILLIS)
        }
        assertEquals(ResumptionBackoff.MAX_MILLIS, period, "capped at 2 days")
        assertFalse(b.avoids("b"), "per host")
    }

    @Test fun negative_aNetworkChangeForgetsTheBackoff() {
        val b = backoff()
        b.mark("a")
        b.mark("a")
        b.onNetworkChanged()
        assertFalse(b.avoids("a"))
        assertEquals(-1, b.levelForTest("a"), "the level starts again")
    }

    @Test fun eitherClockEndsTheBackoff() {
        val b = backoff()
        b.mark("a")
        wall += ResumptionBackoff.BASE_MILLIS // the device slept: the monotonic clock stood still
        assertFalse(b.avoids("a"))
        val c = backoff()
        c.mark("a")
        now += ResumptionBackoff.BASE_MILLIS // the wall clock was stepped back meanwhile
        wall -= 10_000
        assertFalse(c.avoids("a"))
    }

    /** At most MAX_HOSTS hosts are kept: a new one evicts the least recently marked; a mark again makes a host the newest. */
    @Test fun negative_theHostListIsBounded() {
        val b = backoff()
        for (i in 0 until ResumptionBackoff.MAX_HOSTS) b.mark("h$i")
        b.mark("h0") // the oldest, marked again: now the newest
        b.mark("new")
        assertTrue(b.avoids("h0") && b.avoids("new"))
        assertFalse(b.avoids("h1"), "the least recently marked went")
        assertEquals(-1, b.levelForTest("h1"))
        assertEquals(1, b.levelForTest("h0"))
        assertTrue(b.avoids("h${ResumptionBackoff.MAX_HOSTS - 1}"))
    }

    @Test fun clearForgetsOneHost() {
        val b = backoff()
        b.mark("a")
        b.mark("b")
        b.clear("a")
        assertFalse(b.avoids("a"))
        assertEquals(-1, b.levelForTest("a"))
        assertTrue(b.avoids("b"))
    }
}
