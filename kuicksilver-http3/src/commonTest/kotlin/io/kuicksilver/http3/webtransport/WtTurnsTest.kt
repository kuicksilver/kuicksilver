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
            val jobs = listOf(ask(q, "A", "A1", hold = release), ask(q, "A", "A2"), ask(q, "A", "A3"), ask(q, "B", "B1"))
            release.complete(Unit)
            jobs.forEach { it.join() }
            // A1 left A's queue empty, so A2 joined the ring again, ahead of B, which asked after it; A's third writer then
            // waits for B's turn: a round each, whatever A has queued
            assertEquals(listOf("A1", "A2", "B1", "A3"), order)
        }

    /** Section 3.4 with RFC 9218: a more urgent session goes before less urgent ones, whatever the order they asked in. */
    @Test fun aMoreUrgentSessionGoesFirst() =
        runBlocking {
            val q = WtFairQueue(10)
            val release = CompletableDeferred<Unit>()
            val jobs = listOf(ask(q, "Z", hold = release), ask(q, "B", urgency = 3), ask(q, "C", urgency = 1), ask(q, "D", urgency = 7))
            release.complete(Unit)
            jobs.forEach { it.join() }
            assertEquals(listOf("Z", "C", "B", "D"), order)
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

    @Test fun negative_costOverTheQuantumIsRefused() {
        runBlocking {
            kotlin.test.assertFailsWith<IllegalArgumentException> { WtFairQueue(10).inTurn("A", 3, 11) {} }
        }
    }

    /**
     * Randomized: sessions with random numbers of waiters and random costs at one urgency; while two sessions both still
     * have waiters, the bytes granted to them differ by at most two quanta (the deficit round robin bound).
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
                            q.inTurn(i, 3, cost) {
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
