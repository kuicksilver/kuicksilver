// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The fairness scheme of draft-ietf-webtrans-http3-16 section 8 ([WtFairQueue]): the sessions waiting for one of the
 * connection's shared resources take turns by deficit round robin within an urgency, the more urgent first, by cost
 * (bytes, or one per stream opened), however many writers or openers a session has.
 */
class WtTurnsTest {
    private val order = ArrayList<String>()

    /** [key] asks for a turn of [cost] at [urgency]; the turn records [label]. */
    private fun CoroutineScope.ask(
        q: WtFairQueue,
        key: String,
        label: String = key,
        cost: Long = 10,
        urgency: Int = 3,
        hold: CompletableDeferred<Unit>? = null,
    ): Job =
        launch(start = CoroutineStart.UNDISPATCHED) {
            q.inTurn(key, urgency, cost) {
                order += label
                hold?.await()
            }
        }

    @Test fun aSessionWithManyWritersDoesNotStarveAnother() =
        runBlocking {
            val q = WtFairQueue(10)
            val release = CompletableDeferred<Unit>()
            // at urgency 7 a round is one quantum, one turn here
            val jobs =
                listOf(
                    ask(q, "A", "A1", urgency = 7, hold = release),
                    ask(q, "A", "A2", urgency = 7),
                    ask(q, "A", "A3", urgency = 7),
                    ask(q, "B", "B1", urgency = 7),
                )
            release.complete(Unit)
            jobs.forEach { it.join() }
            // A1 left A's queue empty, so A2 joined the ring again, ahead of B, which asked after it; A's third writer then
            // waits for B's turn: a round each, whatever A has queued
            assertEquals(listOf("A1", "A2", "B1", "A3"), order)
        }

    /**
     * Section 3.4 with RFC 9218: a more urgent session gets the larger share (8 - urgency quanta a round), whatever the
     * order the sessions asked in.
     */
    @Test fun aMoreUrgentSessionGetsTheLargerShare() =
        runBlocking {
            val q = WtFairQueue(10)
            val release = CompletableDeferred<Unit>()
            val jobs = ArrayList<Job>()
            jobs += ask(q, "Z", hold = release)
            repeat(20) { jobs += ask(q, "L", urgency = 6) } // two quanta a round
            repeat(20) { jobs += ask(q, "H", urgency = 2) } // six quanta a round
            release.complete(Unit)
            jobs.forEach { it.join() }
            val first = order.drop(1).take(16)
            assertEquals(listOf("L", "L") + List(6) { "H" } + listOf("L", "L") + List(6) { "H" }, first)
        }

    /**
     * Urgency is a preference, never strict (RFC 9218 sections 10 and 13.1): a session at the lowest urgency still gets its
     * turn in every round against a flood at the highest.
     */
    @Test fun negative_theLeastUrgentSessionProgressesAgainstAFlood() =
        runBlocking {
            val q = WtFairQueue(10)
            val release = CompletableDeferred<Unit>()
            val jobs = ArrayList<Job>()
            jobs += ask(q, "Z", hold = release)
            repeat(100) { jobs += ask(q, "F", urgency = 0) }
            jobs += ask(q, "S", urgency = 7)
            release.complete(Unit)
            jobs.forEach { it.join() }
            // a round: eight turns of the flood, then the slow session's one
            assertEquals(9, order.indexOf("S"))
        }

    /** A PRIORITY_UPDATE takes effect while a session keeps waiting: the weight is read again at every request. */
    @Test fun aChangedUrgencyTakesEffectWhileTheSessionWaits() =
        runBlocking {
            val q = WtFairQueue(10)
            val release = CompletableDeferred<Unit>()
            val jobs = ArrayList<Job>()
            jobs += ask(q, "Z", hold = release)
            repeat(10) { jobs += ask(q, "A", urgency = 7) }
            repeat(10) { jobs += ask(q, "B", urgency = 7) }
            // A's session moved to urgency 0 while ten of its writers wait at 7: its rounds take eight turns from now on
            jobs += ask(q, "A", urgency = 0)
            release.complete(Unit)
            jobs.forEach { it.join() }
            assertEquals(List(8) { "A" } + listOf("B") + List(3) { "A" } + List(9) { "B" }, order.drop(1))
        }

    /** By bytes: a session of small writes gets as many bytes per round as one of large writes. */
    @Test fun turnsAreSharedByCost() =
        runBlocking {
            val q = WtFairQueue(10)
            val release = CompletableDeferred<Unit>()
            val jobs = ArrayList<Job>()
            jobs += ask(q, "Z", hold = release)
            repeat(5) { jobs += ask(q, "A", "a", cost = 2) }
            repeat(2) { jobs += ask(q, "B", "B", cost = 10) }
            release.complete(Unit)
            jobs.forEach { it.join() }
            assertEquals(listOf("Z", "a", "a", "a", "a", "a", "B", "B"), order)
        }

    /** A waiter that gives up leaves the queue; one that gives up once granted passes the turn on. */
    @Test fun negative_aCancelledWaiterHoldsNothing() =
        runBlocking {
            val q = WtFairQueue(10)
            val release = CompletableDeferred<Unit>()
            val first = ask(q, "A", "A1", hold = release)
            val gone = ask(q, "B", "B1")
            val after = ask(q, "C", "C1")
            gone.cancel()
            release.complete(Unit)
            first.join()
            after.join()
            assertEquals(listOf("A1", "C1"), order)
            // and the queue still works
            ask(q, "B", "B2").join()
            assertEquals(listOf("A1", "C1", "B2"), order)
        }

    /**
     * Randomized and dynamic: sessions at random urgencies join at random moments and leave when done, each writer asking
     * again right after its turn, at random costs. Between two turns of a session that keeps asking, the others together
     * get at most what two rounds give them (a session that ran dry rejoins at the end of the ring): no session, of
     * whatever urgency, waits longer than that. Every request is served, and the queue ends idle.
     */
    @Test fun randomizedDynamicSessionsAllProgress() =
        runBlocking {
            repeat(50) { seed ->
                val rnd = Random(seed)
                val quantum = 16L
                val q = WtFairQueue(quantum)
                val n = rnd.nextInt(2, 7)
                val urgency = IntArray(n) { rnd.nextInt(0, 8) }
                val delays = IntArray(n) { rnd.nextInt(0, 30) }
                val rounds = IntArray(n) { rnd.nextInt(5, 40) }
                val costs = Array(n) { LongArray(rounds[it]) { rnd.nextLong(1, quantum + 1) } }
                val grants = ArrayList<Pair<Int, Long>>()
                val asked = IntArray(n)
                val served = IntArray(n)
                val jobs =
                    (0 until n).map { i ->
                        launch {
                            repeat(delays[i]) { yield() } // joins at a random moment
                            for (cost in costs[i]) {
                                asked[i]++
                                q.inTurn(i, urgency[i], cost) {
                                    grants += i to cost
                                    served[i]++
                                    yield()
                                }
                            }
                        }
                    }
                jobs.forEach { it.join() }
                assertTrue(asked.contentEquals(served) && served.contentEquals(rounds), "seed $seed: every request served")
                // what one round can give everyone, with the deficit a session carries in
                val round = (0 until n).sumOf { (8 - urgency[it] + 1) * quantum }
                for (i in 0 until n) {
                    var others = 0L
                    var left = served[i]
                    var seen = false
                    for ((who, cost) in grants) {
                        if (who == i) {
                            seen = true
                            others = 0
                            if (--left == 0) break
                        } else if (seen) {
                            others += cost
                            assertTrue(others <= 2 * round, "seed $seed: session $i (urgency ${urgency[i]}) waited $others bytes")
                        }
                    }
                }
                assertTrue(q.idleForTest, "seed $seed")
            }
        }

    @Test fun negative_costOverTheQuantumIsRefused() {
        runBlocking {
            kotlin.test.assertFailsWith<IllegalArgumentException> { WtFairQueue(10).inTurn("A", 3, 11) {} }
        }
    }

    /**
     * Randomized: sessions with random numbers of waiters and random costs at urgency 7 (one quantum a round); while two
     * sessions both still have waiters, the bytes granted to them differ by at most two quanta (the deficit round robin
     * bound).
     */
    @Test fun randomizedSharesStayWithinTwoQuanta() =
        runBlocking {
            repeat(100) { seed ->
                val rnd = Random(seed)
                val quantum = 16L
                val q = WtFairQueue(quantum)
                val n = rnd.nextInt(2, 6)
                val asks = (0 until n).flatMap { i -> List(rnd.nextInt(3, 12)) { i to rnd.nextLong(1, quantum + 1) } }.shuffled(rnd)
                val left = IntArray(n)
                for ((i, _) in asks) left[i]++
                val granted = LongArray(n)
                val release = CompletableDeferred<Unit>()
                val hold = launch(start = CoroutineStart.UNDISPATCHED) { q.inTurn("hold", 3, 1) { release.await() } }
                val jobs =
                    asks.map { (i, cost) ->
                        launch(start = CoroutineStart.UNDISPATCHED) {
                            q.inTurn(i, 7, cost) {
                                granted[i] += cost
                                left[i]--
                                for (a in 0 until n) {
                                    for (b in 0 until n) {
                                        if (a != b && left[a] > 0 && left[b] > 0) {
                                            assertTrue(granted[a] - granted[b] <= 2 * quantum, "seed $seed: ${granted.toList()}")
                                        }
                                    }
                                }
                                yield()
                            }
                        }
                    }
                release.complete(Unit)
                hold.join()
                jobs.forEach { it.join() }
                assertTrue(left.all { it == 0 }, "seed $seed")
            }
        }
}
