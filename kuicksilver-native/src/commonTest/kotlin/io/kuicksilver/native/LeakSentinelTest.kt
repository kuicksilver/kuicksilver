// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.native

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.testing.sentinel.LeakAllowEntry
import io.kuicksilver.testing.sentinel.LeakSentinel
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TestTimeSource
import kotlin.time.TimeSource

/**
 * The leak sentinel itself (docs/process.md, "The leak sentinel"): it is installed in every test run, names what a test
 * left open, waits for a close that comes after the test, and an allow entry tolerates only the kinds it names. The
 * negative controls leak on purpose inside their own scope and close what they leaked before they end.
 */
class LeakSentinelTest {
    private val short = 200.milliseconds

    /** The stepped tests run on a test clock ([LeakRegistry.clockForTest]); every test ends on the monotonic one. */
    @AfterTest fun monotonicClock() {
        LeakRegistry.clockForTest = TimeSource.Monotonic
    }

    @Test fun negative_anObjectLeftOpenIsNamedWithItsKindAndCount() {
        val scope = LeakSentinel.begin()
        val a = LeakRegistry.open("test.thing")
        val b = LeakRegistry.open("test.thing")
        try {
            val leak = assertNotNull(LeakSentinel.end(scope, "C", "t", allow = emptyList(), wait = short))
            assertContains(leak, "leak sentinel: C.t left open")
            assertContains(leak, "test.thing x2")
        } finally {
            LeakRegistry.close(a)
            LeakRegistry.close(b)
        }
        assertNull(LeakSentinel.end(scope, "C", "t", allow = emptyList(), wait = short))
    }

    @Test fun negative_aNativeKeyLeftOpenIsCounted() {
        KslLoader.ensureLoaded()
        val scope = LeakSentinel.begin()
        val key = Ksl.keyRandom(KslConst.EKEY_TOKEN)
        try {
            assertContains(assertNotNull(LeakSentinel.end(scope, "C", "t", allow = emptyList(), wait = short)), "ksl.key x1")
        } finally {
            Ksl.keyFree(key)
        }
        assertNull(LeakSentinel.end(scope, "C", "t", allow = emptyList(), wait = short))
    }

    /** Opened before the scope began: a class's fixture, not the test's. */
    @Test fun anObjectOpenedBeforeTheTestIsNotItsLeak() {
        val fixture = LeakRegistry.open("test.fixture")
        try {
            val scope = LeakSentinel.begin()
            assertNull(LeakSentinel.end(scope, "C", "t", allow = emptyList(), wait = short))
        } finally {
            LeakRegistry.close(fixture)
        }
    }

    /** A close on another thread, before or while the sentinel waits (asynchronous teardown), is no leak: the wait wakes on it. */
    @OptIn(DelicateCoroutinesApi::class)
    @Test
    fun aCloseAfterTheTestIsWaitedFor() {
        val scope = LeakSentinel.begin()
        val id = LeakRegistry.open("test.async")
        val go = CompletableDeferred<Unit>()
        GlobalScope.launch(Dispatchers.Default) {
            go.await()
            LeakRegistry.close(id)
        }
        go.complete(Unit)
        assertNull(LeakSentinel.end(scope, "C", "t", allow = emptyList()))
    }

    @Test fun negative_anAllowEntryToleratesOnlyItsKinds() {
        val scope = LeakSentinel.begin()
        val allowed = LeakRegistry.open("test.allowed")
        val other = LeakRegistry.open("test.other")
        try {
            val allow = listOf(LeakAllowEntry("allow", "C.t", listOf("test.allowed")))
            val leak = assertNotNull(LeakSentinel.end(scope, "C", "t", allow = allow, wait = short))
            assertContains(leak, "test.other x1")
            assertEquals(false, "test.allowed" in leak)
            LeakRegistry.close(other)
            assertNull(LeakSentinel.end(scope, "C", "t", allow = allow, wait = short))
            // another test of the class is not covered by an entry naming one test; the class's own check is
            assertNotNull(LeakSentinel.end(scope, "C", "u", allow = allow, wait = short))
            assertNull(LeakSentinel.end(scope, "C", null, allow = allow, wait = short))
        } finally {
            LeakRegistry.close(allowed)
            LeakRegistry.close(other)
        }
    }

    /** A close that comes only after the sentinel looked is waited for; slow, it is reported, and strict mode fails on it. */
    @OptIn(DelicateCoroutinesApi::class)
    @Test
    fun negative_aSlowCloseFailsInStrictMode() {
        for (strict in listOf(false, true)) {
            val scope = LeakSentinel.begin()
            val id = LeakRegistry.open("test.slow")
            val go = CompletableDeferred<Unit>()
            GlobalScope.launch(Dispatchers.Default) {
                go.await()
                LeakRegistry.close(id)
            }
            val r =
                LeakSentinel.end(scope, "C", "t", allow = emptyList(), slow = Duration.ZERO, strict = strict, afterFirstLookForTest = {
                    go.complete(Unit)
                })
            if (strict) {
                assertContains(assertNotNull(r), "leak sentinel: C.t took")
                assertContains(r, "to close test.slow x1")
            } else {
                assertNull(r, "a slow close that ended is only reported")
            }
        }
    }

    /** A test that frees a native object it did not make is said so: such a drop could hide a leak of the same kind. */
    @Test fun negative_aNativeObjectFreedThatTheTestDidNotMakeIsSaid() {
        KslLoader.ensureLoaded()
        val key = Ksl.keyRandom(KslConst.EKEY_TOKEN) // an earlier test's, say
        val scope = LeakSentinel.begin()
        Ksl.keyFree(key)
        assertContains(assertNotNull(LeakSentinel.freedBefore(scope)), "ksl.key -1")
        assertNull(LeakSentinel.end(scope, "C", "t", allow = emptyList(), wait = short), "not a failure")
    }

    /**
     * Teardown stepped on a test clock ([LeakRegistry.clockForTest] for the test's duration): [kinds] are opened inside the scope and
     * [keys] native keys made, then [steps] run after the sentinel's looks 0, 1, 2, ... with the clock and the ids (each
     * step's close or closing mark wakes the next look); 100 ms slow bound, strict. What is still open at the end is closed
     * and freed.
     */
    private fun stepped(
        vararg kinds: String,
        keys: Int = 0,
        steps: List<(TestTimeSource, Ids) -> Unit>,
    ): String? {
        val clock = TestTimeSource()
        val previous = LeakRegistry.clockForTest
        LeakRegistry.clockForTest = clock
        if (keys > 0) KslLoader.ensureLoaded()
        val scope = LeakSentinel.begin()
        val ids = Ids(kinds.map { LeakRegistry.open(it) }, ArrayList((0 until keys).map { Ksl.keyRandom(KslConst.EKEY_TOKEN) }))
        try {
            return LeakSentinel.end(
                scope,
                "C",
                "t",
                allow = emptyList(),
                wait = 30.seconds,
                slow = 100.milliseconds,
                strict = true,
                afterLookForTest = { n -> steps.getOrNull(n)?.invoke(clock, ids) },
            )
        } finally {
            LeakRegistry.clockForTest = previous
            for (id in ids.objects) LeakRegistry.close(id)
            ids.freeKeys()
        }
    }

    /** The registry ids a stepped teardown opened and the native keys it made, freed once ([freeKeys]). */
    private class Ids(
        val objects: List<Long>,
        private val keys: MutableList<Long>,
    ) {
        operator fun get(i: Int): Long = objects[i]

        fun freeKeys() {
            for (k in keys) Ksl.keyFree(k)
            keys.clear()
        }
    }

    /** At look 0: 10 ms on, [ids] objects enter a closing period of [left] each, set from [pto] (3 x it, as QUIC's). */
    private fun periods(
        left: Duration,
        vararg which: Int,
        pto: Duration? = left / 3,
    ): (TestTimeSource, Ids) -> Unit =
        { clock, ids ->
            clock += 10.milliseconds
            for (i in which) LeakRegistry.closing(ids[i], left, pto)
        }

    /**
     * A QUIC connection's closing or draining period (RFC 9000 section 10.2: 3 x PTO, about 3 s before the first RTT sample,
     * as an in-process server's connection whose client left mid-handshake) is waited for but is no slow teardown
     * (HttpTimeoutTest.testGetRequestTimeoutPerRequestAttributes failed on it in CI, 3009 ms, 2026-11-26).
     */
    @Test fun aCloseWithinItsClosingPeriodIsNotSlow() {
        val r =
            stepped(
                "test.draining",
                steps =
                    listOf(
                        periods(2997.milliseconds, 0),
                        { clock, ids ->
                            clock += 2997.milliseconds + 50.milliseconds // the period's own end, a timer's lateness after it
                            LeakRegistry.close(ids[0])
                        },
                    ),
            )
        assertNull(r, "the wait was the period's")
    }

    /** A connection that stays past the end its period named, by more than the slow bound, is slow teardown. */
    @Test fun negative_aClosingPeriodOverstayedIsSlow() {
        val r =
            stepped(
                "test.draining",
                steps =
                    listOf(
                        periods(2.seconds, 0),
                        { clock, ids ->
                            clock += 2.seconds + 200.milliseconds
                            LeakRegistry.close(ids[0])
                        },
                    ),
            )
        assertContains(assertNotNull(r), "took 2210 ms to close test.draining x1")
    }

    /** One connection's overstay is not hidden by another's later period: each object is judged by its own end. */
    @Test fun negative_anOverstayIsSlowBesideALaterPeriod() {
        val r =
            stepped(
                "test.short",
                "test.long",
                steps =
                    listOf(
                        { clock, ids ->
                            clock += 10.milliseconds
                            LeakRegistry.closing(ids[0], 99.milliseconds, 33.milliseconds)
                            LeakRegistry.closing(ids[1], 2.seconds, 2.seconds / 3)
                        },
                        { clock, ids ->
                            clock += 1.seconds // 900 ms past its own end
                            LeakRegistry.close(ids[0])
                        },
                        { clock, ids ->
                            clock += 1.seconds // on time
                            LeakRegistry.close(ids[1])
                        },
                    ),
            )
        assertContains(assertNotNull(r), "test.short x1 closed after 100 ms")
    }

    /** An object outside any closing period that closes after the slow bound is slow, whatever drains beside it. */
    @Test fun negative_aSlowObjectBesideAClosingPeriodIsSlow() {
        val r =
            stepped(
                "test.draining",
                "test.slow",
                steps =
                    listOf(
                        periods(2.seconds, 0),
                        { clock, ids ->
                            clock += 500.milliseconds // past the slow bound, outside a period
                            LeakRegistry.close(ids[1])
                        },
                        { clock, ids ->
                            clock += 1500.milliseconds
                            LeakRegistry.close(ids[0])
                        },
                    ),
            )
        assertContains(assertNotNull(r), "test.slow x1 closed after 100 ms")
    }

    /**
     * An object opened and closed between two looks (an open wakes no look) is still judged: it closed after the slow bound
     * outside a period.
     */
    @Test fun negative_anObjectOpenedAndClosedBetweenLooksIsJudged() {
        val r =
            stepped(
                "test.draining",
                steps =
                    listOf(
                        periods(2.seconds, 0),
                        { clock, _ ->
                            val brief = LeakRegistry.open("test.brief")
                            clock += 500.milliseconds
                            LeakRegistry.close(brief)
                        },
                        { clock, ids ->
                            clock += 1500.milliseconds
                            LeakRegistry.close(ids[0])
                        },
                    ),
            )
        assertContains(assertNotNull(r), "test.brief x1 closed after 100 ms")
    }

    /**
     * Fails closed: a close the log did not record (logging cut short) has no known time, so nothing explains the wait and
     * it is slow, not taken for an object that closed within the bound.
     */
    @Test fun negative_aLateCloseThatWasNotLoggedIsSlow() {
        val r =
            stepped(
                "test.unlogged",
                steps =
                    listOf(
                        { clock, ids ->
                            LeakRegistry.logCloses(false)
                            clock += 2.seconds
                            LeakRegistry.close(ids[0])
                        },
                    ),
            )
        assertContains(assertNotNull(r), "nothing logged explains 2000 ms")
    }

    /** A second sentinel cannot start logging while one waits: it would take or end the other's log. */
    @Test fun negative_aSecondLogCannotStartWhileOneRuns() {
        LeakRegistry.logCloses(true)
        try {
            assertFailsWith<IllegalStateException> { LeakRegistry.logCloses(true) }
        } finally {
            LeakRegistry.logCloses(false)
        }
    }

    /** One that enters its period only after the slow bound was slow until then. */
    @Test fun negative_aClosingPeriodThatStartsLateIsSlow() {
        val r =
            stepped(
                "test.draining",
                steps =
                    listOf(
                        { clock, ids ->
                            clock += 400.milliseconds
                            LeakRegistry.closing(ids[0], 999.milliseconds, 333.milliseconds)
                        },
                        { clock, ids ->
                            clock += 1.seconds
                            LeakRegistry.close(ids[0])
                        },
                    ),
            )
        assertContains(assertNotNull(r), "took 1400 ms to close")
    }

    /**
     * A period set from an RTT sample a starved host inflated is as long as the RFC makes it (3 x PTO) and is excused: a
     * 500 ms first sample gives a PTO of 500 + 4 x 250 = 1500 ms and a 4.5 s period (1 run in 120 under four CPU burners
     * failed so, 4693 ms, against a fixed cap of 3 x 999 ms).
     */
    @Test fun aPeriodFromAnInflatedRttIsNotSlow() {
        val r =
            stepped(
                "test.draining",
                steps =
                    listOf(
                        periods(4500.milliseconds, 0, pto = 1500.milliseconds),
                        { clock, ids ->
                            clock += 4500.milliseconds + 50.milliseconds // the period, a timer's lateness after it
                            LeakRegistry.close(ids[0])
                        },
                    ),
            )
        assertNull(r, "a period of 3 x its PTO")
    }

    /**
     * A period that ended by its own deadline, whose timer ran late because the loop was held up (a GC pause, a starved
     * host: 1 run in 300 under four CPU burners closed 2094 ms after its period), is no slow teardown: the connection
     * measured that lateness itself.
     */
    @Test fun aPeriodWhoseTimerRanLateOnAHeldUpLoopIsNotSlow() {
        val r =
            stepped(
                "test.draining",
                steps =
                    listOf(
                        periods(3.seconds, 0),
                        { clock, ids ->
                            clock += 3.seconds + 2094.milliseconds
                            LeakRegistry.close(ids[0], 2090.milliseconds)
                        },
                    ),
            )
        assertNull(r, "the lateness was the loop's, measured by the connection")
    }

    /** Lateness beyond what the connection's own timer measured is still slow. */
    @Test fun negative_anOverstayBeyondItsTimersLatenessIsSlow() {
        val r =
            stepped(
                "test.draining",
                steps =
                    listOf(
                        periods(3.seconds, 0),
                        { clock, ids ->
                            clock += 3.seconds + 2094.milliseconds
                            LeakRegistry.close(ids[0], 1.seconds)
                        },
                    ),
            )
        assertContains(assertNotNull(r), "closed 2094 ms after its period, its timer 1000 ms late")
    }

    /** A period of 6 x the PTO it reports (a doubled period or PTO) is longer than the RFC allows: no excuse, whatever the RTT. */
    @Test fun negative_aPeriodOfSixPtoIsSlow() {
        val r =
            stepped(
                "test.draining",
                steps =
                    listOf(
                        periods(3.seconds, 0, pto = 500.milliseconds),
                        { clock, ids ->
                            clock += 3.seconds
                            LeakRegistry.close(ids[0])
                        },
                    ),
            )
        assertContains(assertNotNull(r), "more than 3 x its PTO of 500 ms")
    }

    /** A runaway PTO: a period longer than the sentinel's own wait bound is never excused, even at 3 x its PTO. */
    @Test fun negative_aPeriodOverTheWaitBoundIsSlow() {
        val r =
            stepped(
                "test.draining",
                steps =
                    listOf(
                        periods(36.seconds, 0, pto = 12.seconds),
                        { clock, ids ->
                            clock += 36.seconds
                            LeakRegistry.close(ids[0])
                        },
                    ),
            )
        assertContains(assertNotNull(r), "longer than the 30000 ms wait")
    }

    /** A period whose record names no PTO cannot be checked against the RFC: no excuse. */
    @Test fun negative_aPeriodWithoutItsPtoIsSlow() {
        val r =
            stepped(
                "test.draining",
                steps =
                    listOf(
                        periods(2.seconds, 0, pto = null),
                        { clock, ids ->
                            clock += 2.seconds
                            LeakRegistry.close(ids[0])
                        },
                    ),
            )
        assertContains(assertNotNull(r), "a period without its PTO")
    }

    /** A period noted on another clock than [LeakRegistry.clockForTest] is no excuse (its marks cannot be compared). */
    @Test fun negative_aPeriodOnAnotherClockExcusesNothing() {
        val r =
            stepped(
                "test.draining",
                steps =
                    listOf(
                        { clock, ids ->
                            clock += 10.milliseconds
                            LeakRegistry.clockForTest = TestTimeSource()
                            try {
                                LeakRegistry.closing(ids[0], 2.seconds, 2.seconds / 3)
                            } finally {
                                LeakRegistry.clockForTest = clock
                            }
                        },
                        { clock, ids ->
                            clock += 2.seconds
                            LeakRegistry.close(ids[0])
                        },
                    ),
            )
        assertContains(assertNotNull(r), "test.draining x1 closed after 100 ms")
    }

    /** A closing connection's TLS session and keys are excused beside its period, freed with it. */
    @Test fun nativeKeysBesideAClosingPeriodAreNotSlow() {
        val r =
            stepped(
                "test.closing",
                keys = 2,
                steps =
                    listOf(
                        periods(2.seconds, 0),
                        { clock, ids ->
                            clock += 2.seconds
                            ids.freeKeys()
                            LeakRegistry.close(ids[0])
                        },
                    ),
            )
        assertNull(r)
    }

    /** More keys than one closing connection holds are not excused by its period. */
    @Test fun negative_moreKeysThanAPeriodHoldsAreSlow() {
        val r =
            stepped(
                "test.closing",
                keys = LeakSentinel.KEYS_PER_PERIOD + 1,
                steps =
                    listOf(
                        periods(2.seconds, 0),
                        { clock, ids ->
                            clock += 2.seconds
                            ids.freeKeys()
                            LeakRegistry.close(ids[0])
                        },
                    ),
            )
        assertContains(assertNotNull(r), "ksl counters until 2010 ms")
    }

    /** ksl's counters belong to no object: with no closing period beside them, their slow free is slow. */
    @Test fun negative_aNativeObjectFreedLateWithoutAClosingPeriodIsSlow() {
        val r =
            stepped(
                keys = 1,
                steps =
                    listOf(
                        { clock, ids ->
                            clock += 3.seconds
                            ids.freeKeys()
                        },
                    ),
            )
        assertContains(assertNotNull(r), "took 3000 ms to close ksl.key x1")
    }

    /** A closing mark of 0 (tracking off) or of a closed id changes nothing; on an open one it sets the end and when it was noted. */
    @Test fun closingMarksOnlyAnOpenEntry() {
        val clock = TestTimeSource()
        LeakRegistry.clockForTest = clock
        try {
            LeakRegistry.closing(0L, 1.seconds, 333.milliseconds)
            val mark = LeakRegistry.mark()
            val id = LeakRegistry.open("test.closing")
            val entry = LeakRegistry.openSince(mark).single { it.id == id }
            assertNull(entry.closingUntil)
            val now = clock.markNow()
            LeakRegistry.closing(id, 1.seconds, 333.milliseconds)
            assertEquals(333.milliseconds, entry.closingPto)
            assertEquals(now, entry.closingNoted)
            assertEquals(now + 1.seconds, entry.closingUntil)
            clock += 5.milliseconds
            LeakRegistry.logCloses(true)
            LeakRegistry.close(id)
            val closed = LeakRegistry.takeClosed().single { it.id == id }
            assertEquals(now + 5.milliseconds, closed.closedAt)
            assertEquals(now + 1.seconds, closed.closingUntil)
            assertEquals(now, closed.closingNoted)
            assertEquals(333.milliseconds, closed.closingPto)
            LeakRegistry.closing(id, 2.seconds, 666.milliseconds) // closed: nothing to mark, no failure
            assertEquals(now + 1.seconds, entry.closingUntil)
            assertTrue(LeakRegistry.openSince(mark).none { it.id == id })
        } finally {
            LeakRegistry.logCloses(false)
            LeakRegistry.clockForTest = TimeSource.Monotonic
        }
    }

    /** Closes are logged only while a sentinel waits ([LeakRegistry.logCloses]): none is kept otherwise. */
    @Test fun closesAreLoggedOnlyWhileASentinelWaits() {
        val outside = LeakRegistry.open("test.outside")
        LeakRegistry.close(outside)
        LeakRegistry.logCloses(true)
        try {
            assertTrue(LeakRegistry.takeClosed().isEmpty(), "a close before logging began is not kept")
            val inside = LeakRegistry.open("test.inside")
            LeakRegistry.close(inside)
            assertEquals(listOf(inside), LeakRegistry.takeClosed().map { it.id })
        } finally {
            LeakRegistry.logCloses(false)
        }
        val after = LeakRegistry.open("test.after")
        LeakRegistry.close(after)
        LeakRegistry.logCloses(true)
        try {
            assertTrue(LeakRegistry.takeClosed().isEmpty(), "a close after logging stopped is not kept")
        } finally {
            LeakRegistry.logCloses(false)
        }
    }
}
