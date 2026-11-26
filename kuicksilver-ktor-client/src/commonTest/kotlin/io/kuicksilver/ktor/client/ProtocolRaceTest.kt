// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.client

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

class ProtocolRaceTest {
    private val race = ProtocolRace(RaceHeadStart.Adaptive)

    @Test fun h3WinsWithoutStartingH1() =
        runTest {
            var h1Started = false
            val r =
                race.race({
                    delay(50)
                    "h3"
                }, {
                    h1Started = true
                    "h1"
                }, srtt = null, quicConfirmed = true)
            assertEquals(Protocol.H3, r.winner)
            assertEquals("h3", r.value)
            assertFalse(h1Started)
            assertNull(r.h3Failure)
        }

    @Test fun h1StartsAtHardDelay() =
        runTest {
            var startedAt = -1L
            val r =
                race.race({ awaitCancellation() }, {
                    startedAt = currentTime
                    "h1"
                }, srtt = null, quicConfirmed = true)
            assertEquals(Protocol.H1, r.winner)
            assertEquals(250L, startedAt)
        }

    @Test fun headStartFromSrttClamped() {
        assertEquals(100.milliseconds, race.headStart(10.milliseconds, true))
        assertEquals(2.seconds, race.headStart(5.seconds, true))
        assertEquals(600.milliseconds, race.headStart(400.milliseconds, true))
        assertEquals(250.milliseconds, race.headStart(null, true))
        assertEquals(700.milliseconds, ProtocolRace(RaceHeadStart.Fixed(700.milliseconds)).headStart(10.milliseconds, true))
    }

    @Test fun h1StartsImmediatelyOnH3Failure() =
        runTest {
            var startedAt = -1L
            val r =
                race.race({
                    delay(20)
                    throw IOException("udp blocked")
                }, {
                    startedAt = currentTime
                    "h1"
                }, srtt = null, quicConfirmed = true)
            assertEquals(20L, startedAt)
            assertEquals(Protocol.H1, r.winner)
            assertNotNull(r.h3Failure)
        }

    /**
     * On a network where QUIC was never confirmed HTTP/1.1 starts after the minimum delay of RFC 8305 section 5, not
     * together with HTTP/3: "a subsequent connection MUST NOT be started within 10 milliseconds of the previous attempt".
     * Before, both started at once.
     */
    @Test fun minimumHeadStartOnUnconfirmedNetwork() =
        runTest {
            var startedAt = -1L
            race.race({
                delay(1000)
                "h3"
            }, {
                startedAt = currentTime
                delay(10)
                "h1"
            }, srtt = null, quicConfirmed = false)
            assertEquals(10L, startedAt)
            assertEquals(10.milliseconds, race.headStart(null, false))
            assertEquals(10.milliseconds, ProtocolRace(RaceHeadStart.Fixed(700.milliseconds)).headStart(null, false))
        }

    /**
     * A `RaceHeadStart.Fixed` head start keeps the bounds of RFC 8305 section 5 (at least 10 ms, MUST; at most 2 s,
     * SHOULD), as `network { happyEyeballsDelay }` does, and the refusal names the option. `Fixed(Duration.INFINITE)` is
     * refused too: `RaceHeadStart.NoRace` is the one name for TCP only after HTTP/3 failed.
     */
    @Test fun negative_fixedHeadStartOutsideRfc8305BoundsIsRefused() {
        for (d in listOf(Duration.ZERO, 9.milliseconds, 2001.milliseconds, Duration.INFINITE, (-1).milliseconds)) {
            val e = assertFailsWith<IllegalArgumentException>("$d") { ProtocolRace(RaceHeadStart.Fixed(d)) }
            assertTrue("http3 { expert { raceHeadStart = RaceHeadStart.Fixed(d) } }" in e.message.orEmpty(), e.message)
            assertTrue("hardDelay" !in e.message.orEmpty(), e.message)
        }
        for (d in listOf(10.milliseconds, 2.seconds)) ProtocolRace(RaceHeadStart.Fixed(d))
        ProtocolRace(RaceHeadStart.NoRace)
        ProtocolRace(RaceHeadStart.Adaptive)
    }

    /**
     * `RaceHeadStart.NoRace` is "TCP only after HTTP/3 failed" on every network, also one where QUIC was
     * never confirmed: no second attempt runs at the same time, which RFC 8305 section 5 allows (it bounds how soon the
     * next attempt starts, not how late). Before, such a network got the 10 ms head start anyway.
     */
    @Test fun noRaceWaitsForHttp3OnAnUnconfirmedNetwork() =
        runTest {
            val race = ProtocolRace(RaceHeadStart.NoRace)
            assertEquals(Duration.INFINITE, race.headStart(null, false))
            var h1Started = false
            val result =
                race.race({
                    delay(5_000)
                    "h3"
                }, {
                    h1Started = true
                    "h1"
                }, srtt = null, quicConfirmed = false)
            assertEquals("h3", result.value)
            assertFalse(h1Started, "HTTP/1.1 started while HTTP/3 was still connecting")
        }

    /** An h1 setup that completed just as h3 won is handed to [onLoser] (the engine closes it) instead of being leaked. */
    @Test fun losingH1ResultIsHandedToOnLoser() =
        runTest {
            val lost = ArrayList<String>()
            val r =
                race.race({
                    delay(30)
                    "h3"
                }, {
                    withContext(NonCancellable) { delay(30) }
                    "h1"
                }, null, quicConfirmed = false, onLoser = { lost += it })
            assertEquals(Protocol.H3, r.winner)
            assertEquals(listOf("h1"), lost)
        }

    /** A caller cancelled while an h1 setup completes (it cannot be interrupted) still hands the connection to [onLoser]. */
    @Test fun loserIsHandedOverWhenCallerIsCancelled() =
        runTest {
            val lost = ArrayList<String>()
            val h1Started = CompletableDeferred<Unit>()
            val gate = CompletableDeferred<Unit>()
            val caller =
                launch {
                    race.race(
                        { awaitCancellation() },
                        {
                            withContext(NonCancellable) {
                                h1Started.complete(Unit)
                                gate.await()
                                "h1"
                            }
                        },
                        null,
                        quicConfirmed = false,
                        onLoser = { lost += it },
                    )
                }
            h1Started.await()
            caller.cancel()
            gate.complete(Unit)
            caller.join()
            assertEquals(listOf("h1"), lost)
        }

    /**
     * HTTP/1.1 won, and the caller is cancelled while the race still waits for the cancelled HTTP/3 setup to end: the
     * winner, which no caller receives, goes to [onLoser] (the engine recycles it) instead of being dropped with its
     * connection (a TLS connection left open for good: the leak sentinel's tcp.socket and ksl.ssl).
     */
    @Test fun negative_anH1WinnerTheCallerNeverGotIsHandedToOnLoser() =
        runTest {
            val lost = ArrayList<String>()
            val h3Cancelled = CompletableDeferred<Unit>()
            val h3Gate = CompletableDeferred<Unit>()
            val caller =
                launch {
                    race.race(
                        {
                            try {
                                awaitCancellation()
                            } finally {
                                // a setup that takes a while to end once cancelled (a QUIC close in flight)
                                withContext(NonCancellable) {
                                    h3Cancelled.complete(Unit)
                                    h3Gate.await()
                                }
                            }
                        },
                        { "h1" },
                        null,
                        quicConfirmed = false,
                        onLoser = { lost += it },
                    )
                    error("the caller is cancelled before the race returns")
                }
            h3Cancelled.await() // HTTP/1.1 won: the race's scope waits for the HTTP/3 setup now
            caller.cancel()
            h3Gate.complete(Unit)
            caller.join()
            assertEquals(listOf("h1"), lost)
        }

    @Test fun bothFailThrowsH1Failure() =
        runTest {
            val e = assertFailsWith<IOException> { race.race<String>({ throw IOException("h3") }, { throw IOException("h1") }, null, true) }
            assertEquals("h1", e.message)
        }

    /** Both setups failed: the HTTP/1.1 failure is thrown and carries the HTTP/3 one, so a failed call still says why HTTP/3 failed. */
    @Test fun bothFailKeepsTheHttp3FailureSuppressed() =
        runTest {
            val h3 = IOException("h3")
            val e = assertFailsWith<IOException> { race.race<String>({ throw h3 }, { throw IOException("h1") }, null, true) }
            // kotlinx.coroutines' stack trace recovery (tests run with assertions on) may hand out a copy whose cause is the original
            assertEquals(listOf<Throwable>(h3), generateSequence<Throwable>(e) { it.cause }.flatMap { it.suppressedExceptions }.toList())
        }
}

class BrokenAltSvcTest {
    private var now = 0L
    private val broken = BrokenAltSvc({ now })

    /**
     * A mark ends on whichever clock gets there first: the monotonic one (a backward step of the wall clock does not
     * extend it) or the wall clock (a device asleep, whose monotonic clock stopped, does not get the backoff stretched over
     * the sleep). Before, the engine gave the marks the wall clock alone, and then the monotonic clock alone.
     */
    @Test fun negative_markEndsOnEitherClock() {
        var mono = 0L
        var wall = 1_000_000_000L
        val b = BrokenAltSvc({ mono }, { wall })
        b.markBroken("o", "a") // 5 minutes
        wall += 3_600_000 // an hour asleep: the monotonic clock did not move
        assertFalse(b.isBroken("o", "a"), "the sleep counts")
        b.markBroken("o", "a") // 10 minutes
        wall -= 86_400_000 // the wall clock stepped back a day
        mono += 600_000
        assertFalse(b.isBroken("o", "a"), "the step back does not extend it")
        assertEquals(null, b.brokenReason("o", "a"))
    }

    @Test fun backoffDoublesTo2Days() {
        val expected = listOf(5.minutes, 10.minutes, 20.minutes, 40.minutes)
        for (d in expected) {
            broken.markBroken("o", "a")
            assertTrue(broken.isBroken("o", "a"))
            now += d.inWholeMilliseconds - 1
            assertTrue(broken.isBroken("o", "a"))
            now +=
                1
            assertFalse(broken.isBroken("o", "a"))
        }
        repeat(20) { broken.markBroken("o", "a") }
        now += 2 * 86_400_000L - 1
        assertTrue(broken.isBroken("o", "a"))
        now += 1
        assertFalse(broken.isBroken("o", "a")) // capped at 2 days
    }

    @Test fun markedPerOriginAndAlternative() {
        broken.markBroken("o", "a")
        assertFalse(broken.isBroken("o", "b"))
        assertFalse(broken.isBroken("p", "a"))
    }

    @Test fun workingResetsBackoff() {
        broken.markBroken("o", "a")
        broken.markWorking("o", "a")
        assertFalse(broken.isBroken("o", "a"))
        broken.markBroken("o", "a")
        now +=
            5.minutes.inWholeMilliseconds
        assertFalse(broken.isBroken("o", "a"))
    }

    /**
     * A stall (a network that cuts UDP flows after the handshake) keeps its backoff across the handshakes that work: each
     * new stall doubles it, where a handshake would otherwise start the backoff again at 5 minutes.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun stallBackoffSurvivesAWorkingHandshake() {
        broken.markBroken("o", "a", FallbackReason.QuicStalled)
        now += 5.minutes.inWholeMilliseconds
        assertFalse(broken.isBroken("o", "a"))
        broken.markWorking("o", "a") // the next handshake completes...
        assertFalse(broken.isBroken("o", "a"))
        broken.markBroken("o", "a", FallbackReason.QuicStalled) // ...and the request after it stalls again
        now += 5.minutes.inWholeMilliseconds
        assertTrue(broken.isBroken("o", "a"), "10 minutes the second time")
        now += 5.minutes.inWholeMilliseconds
        assertFalse(broken.isBroken("o", "a"))
    }

    /**
     * Review finding 4: a stall's backoff walks back down. Each connection that carried a whole exchange without a stall
     * takes one level off an expired stall mark, and at level 0 the mark goes.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun stallBackoffWalksBackDown() {
        repeat(3) {
            broken.markBroken("o", "a", FallbackReason.QuicStalled)
            now += 1_000_000_000L // past any mark
        }
        broken.decayStall("o", "a") // level 2 -> 1
        broken.markBroken("o", "a", FallbackReason.QuicStalled) // level 2: 20 minutes
        now += 15.minutes.inWholeMilliseconds
        assertTrue(broken.isBroken("o", "a"))
        now += 1_000_000_000L
        repeat(3) { broken.decayStall("o", "a") } // 2 -> 1 -> 0 -> gone
        assertNull(broken.brokenReason("o", "a"))
        broken.markBroken("o", "a", FallbackReason.QuicStalled)
        now += 5.minutes.inWholeMilliseconds
        assertFalse(broken.isBroken("o", "a"), "back at 5 minutes")
    }

    /** A live stall mark is not decayed: nothing went over HTTP/3 to that alternative meanwhile. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun negative_aLiveStallMarkDoesNotDecay() {
        broken.markBroken("o", "a", FallbackReason.QuicStalled)
        broken.decayStall("o", "a")
        assertTrue(broken.isBroken("o", "a"))
    }

    /** A live stall mark is not lifted by a handshake that completed (the race's background attempt, say). */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun negative_handshakeDoesNotLiftAStall() {
        broken.markBroken("o", "a", FallbackReason.QuicStalled)
        broken.markWorking("o", "a")
        assertEquals(FallbackReason.QuicStalled, broken.brokenReason("o", "a"))
        broken.onNetworkChanged()
        assertNull(broken.brokenReason("o", "a"), "a new network forgets it")
    }

    /** A peer cycling origins (or networks) cannot grow the marks without bound: the oldest go past `MAX_ORIGINS` (threat-model 3.18). */
    @Test fun negative_brokenMarksBounded() {
        val n = AltSvcCache.MAX_ORIGINS + 500
        for (i in 0 until n) {
            broken.markBroken("o$i", "a")
            broken.confirmQuic("net$i")
        }
        assertFalse(broken.isBroken("o0", "a"), "the oldest mark was evicted")
        assertTrue(broken.isBroken("o${n - 1}", "a"))
        assertEquals(AltSvcCache.MAX_ORIGINS, (0 until n).count { broken.isBroken("o$it", "a") })
        assertFalse(broken.quicConfirmedOn("net0"))
        assertEquals(AltSvcCache.MAX_ORIGINS, (0 until n).count { broken.quicConfirmedOn("net$it") })
    }

    /** A mark remembers why the alternative broke, for the diagnostics of the calls it sends to HTTP/1.1. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun markRemembersItsReason() {
        broken.markBroken("o", "a", FallbackReason.HandshakeTimeout)
        assertEquals(FallbackReason.HandshakeTimeout, broken.brokenReason("o", "a"))
        broken.markBroken("o", "a", FallbackReason.TlsFailure)
        assertEquals(FallbackReason.TlsFailure, broken.brokenReason("o", "a"))
        now += 10.minutes.inWholeMilliseconds
        assertNull(broken.brokenReason("o", "a"), "an expired mark says nothing")
    }

    @Test fun networkChangeResets() {
        broken.markBroken("o", "a")
        broken.confirmQuic("wifi")
        assertTrue(broken.quicConfirmedOn("wifi"))
        broken.onNetworkChanged()
        assertFalse(broken.isBroken("o", "a"))
        assertFalse(broken.quicConfirmedOn("wifi"))
    }
}
