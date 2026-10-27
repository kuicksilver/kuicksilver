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
    private val race = ProtocolRace(hardDelay = null)

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

    @Test fun hardDelayFromSrttClamped() {
        assertEquals(100.milliseconds, race.headStart(10.milliseconds, true))
        assertEquals(2.seconds, race.headStart(5.seconds, true))
        assertEquals(600.milliseconds, race.headStart(400.milliseconds, true))
        assertEquals(250.milliseconds, race.headStart(null, true))
        assertEquals(700.milliseconds, ProtocolRace(700.milliseconds).headStart(10.milliseconds, true))
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
            assertEquals(10.milliseconds, ProtocolRace(700.milliseconds).headStart(null, false))
        }

    /**
     * An explicit `hardDelay` keeps the bounds of RFC 8305 section 5 (at least 10 ms, MUST; at most 2 s, SHOULD), as
     * `connectionAttemptDelay` does; `Duration.INFINITE` (HTTP/1.1 only after HTTP/3 failed) stays allowed. Before, any
     * value was used as is, zero included.
     */
    @Test fun negative_hardDelayOutsideRfc8305BoundsIsRefused() {
        for (d in listOf(Duration.ZERO, 9.milliseconds, 2001.milliseconds)) {
            assertFailsWith<IllegalArgumentException>("$d") { ProtocolRace(d) }
        }
        for (d in listOf(10.milliseconds, 2.seconds, Duration.INFINITE)) ProtocolRace(d)
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

    @Test fun bothFailThrowsH1Failure() =
        runTest {
            val e = assertFailsWith<IOException> { race.race<String>({ throw IOException("h3") }, { throw IOException("h1") }, null, true) }
            assertEquals("h1", e.message)
        }
}

class BrokenAltSvcTest {
    private var now = 0L
    private val broken = BrokenAltSvc { now }

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

    @Test fun networkChangeResets() {
        broken.markBroken("o", "a")
        broken.confirmQuic("wifi")
        assertTrue(broken.quicConfirmedOn("wifi"))
        broken.onNetworkChanged()
        assertFalse(broken.isBroken("o", "a"))
        assertFalse(broken.quicConfirmedOn("wifi"))
    }
}
