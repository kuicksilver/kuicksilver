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
        pass(ResumptionBackoff.BASE_MILLIS)
        b.mark("a")
        assertEquals(1, b.levelForTest("a"))
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

    /** At most MAX_HOSTS hosts are kept: a new one evicts the least recently marked. */
    @Test fun negative_theHostListIsBounded() {
        val b = backoff()
        for (i in 0 until ResumptionBackoff.MAX_HOSTS) b.mark("h$i")
        b.mark("new")
        assertTrue(b.avoids("new"))
        assertFalse(b.avoids("h0"), "the least recently marked went")
        assertEquals(-1, b.levelForTest("h0"))
        assertTrue(b.avoids("h1") && b.avoids("h${ResumptionBackoff.MAX_HOSTS - 1}"))
    }

    /**
     * A mark while the host's backoff lives is the same failure seen again (the call's failure path and the handshake watcher
     * both report it; nothing resumes during a backoff): it changes neither the level nor the end.
     */
    @Test fun negative_aMarkWhileTheBackoffLivesChangesNothing() {
        val b = backoff()
        b.mark("a")
        pass(ResumptionBackoff.BASE_MILLIS - 10)
        b.mark("a")
        assertEquals(0, b.levelForTest("a"), "not doubled")
        pass(10)
        assertFalse(b.avoids("a"), "the first mark's end stands")
        b.mark("a")
        assertEquals(1, b.levelForTest("a"), "a new failure after the end doubles")
    }

    @Test fun theForgettingCallsNameTheHostsThatHadAMark() {
        val b = backoff()
        b.mark("a")
        b.mark("b")
        assertEquals(true, b.clear("a"))
        assertEquals(false, b.clear("a"))
        assertEquals(listOf("b"), b.onNetworkChanged())
        assertEquals(emptyList(), b.onNetworkChanged())
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

    /**
     * The end of each backoff period is seen once (the pool then drops the tickets stored during the period, so the first
     * connection after it is a full handshake): not while the mark lives, once after it, not again until a new mark ended.
     */
    @Test fun negative_theEndOfAPeriodIsSettledOnce() {
        val b = backoff()
        assertFalse(b.settleExpired("a"), "no mark")
        b.mark("a")
        assertFalse(b.settleExpired("a"), "the period runs")
        pass(ResumptionBackoff.BASE_MILLIS)
        assertTrue(b.settleExpired("a"), "the period ended")
        assertFalse(b.settleExpired("a"), "once")
        assertEquals(0, b.levelForTest("a"), "the level stays for the next mark")
        b.mark("a")
        assertFalse(b.settleExpired("a"))
        pass(2 * ResumptionBackoff.BASE_MILLIS)
        assertTrue(b.settleExpired("a"), "a new period ends again")
        b.expireForTest("a")
        assertTrue(b.settleExpired("a"), "the tests' early end too")
    }
}
