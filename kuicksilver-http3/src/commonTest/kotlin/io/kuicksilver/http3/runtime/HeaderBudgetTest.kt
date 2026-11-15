// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.kuicksilver.http3.forAllSeeded
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** [HeaderBudget]: reserved bytes never exceed the capacity, waiters are served in order, and nothing leaks. */
class HeaderBudgetTest {
    @Test fun grantsInOrderAndNeverAboveCapacity() =
        runBlocking {
            val b = HeaderBudget(10)
            b.reserve(6)
            val order = mutableListOf<Int>()
            val big = launch(start = CoroutineStart.UNDISPATCHED) { b.reserve(8).also { order += 8 } }
            // a small one fits now but waits behind the big one: it is not overtaken forever
            val small = launch(start = CoroutineStart.UNDISPATCHED) { b.reserve(2).also { order += 2 } }
            yield()
            assertEquals(2, b.waiting)
            assertEquals(6, b.reserved)
            b.release(6)
            big.join()
            small.join()
            assertEquals(listOf(8, 2), order)
            assertEquals(10, b.reserved)
            b.release(8)
            b.release(2)
            assertEquals(0, b.reserved)
        }

    /** A waiter cancelled while in line leaves it, and the next one gets in when it fits. */
    @Test fun negative_cancelledWaiterLeavesTheLine() =
        runBlocking {
            val b = HeaderBudget(10)
            b.reserve(5)
            val first = launch(start = CoroutineStart.UNDISPATCHED) { b.reserve(10) }
            val second = launch(start = CoroutineStart.UNDISPATCHED) { b.reserve(5) }
            yield()
            assertEquals(2, b.waiting)
            first.cancel()
            second.join() // the head of the line left: the 5 behind it fit at once
            assertEquals(0, b.waiting)
            assertEquals(10, b.reserved)
            assertTrue(first.isCancelled)
        }

    /** A waiter granted and cancelled before it resumed gives its reservation back. */
    @Test fun negative_grantedThenCancelledReturnsTheReservation() =
        runBlocking {
            val b = HeaderBudget(10)
            b.reserve(10)
            val w = launch(start = CoroutineStart.UNDISPATCHED) { b.reserve(4) }
            b.release(10) // grants the waiter, which has not resumed yet (the test holds this thread)
            assertEquals(4, b.reserved)
            w.cancel()
            w.join()
            assertEquals(0, b.reserved)
        }

    /**
     * A waiter whose stream ends with a reset wakes at once (no polling), gives up with that reason, leaves the line, and
     * the next one gets in.
     */
    @Test fun negative_abandonedWaiterLeavesTheLineWithItsReason() =
        runBlocking {
            val b = HeaderBudget(10)
            b.reserve(8)
            val end = kotlinx.coroutines.CompletableDeferred<Long>()
            val reason = IllegalStateException("stream reset")
            val watch = EndWatch(end, Job()) { if (end.isCompleted) reason else null }
            val gone = kotlinx.coroutines.CompletableDeferred<Throwable>()
            val first =
                launch(start = CoroutineStart.UNDISPATCHED) { gone.complete(runCatching { b.reserve(10, watch) }.exceptionOrNull()!!) }
            val second = launch(start = CoroutineStart.UNDISPATCHED) { b.reserve(2) }
            yield()
            assertEquals(2, b.waiting)
            end.complete(10)
            assertEquals(reason, gone.await())
            first.join()
            second.join()
            assertEquals(0, b.waiting)
            assertEquals(10, b.reserved)
        }

    /** A FIN is no reason to give up (the head's bytes are all there): the waiter stays in line and gets its grant. */
    @Test fun aFinishedStreamKeepsWaitingForItsGrant() =
        runBlocking {
            val b = HeaderBudget(10)
            b.reserve(8)
            val end = kotlinx.coroutines.CompletableDeferred<Long>()
            val w = launch(start = CoroutineStart.UNDISPATCHED) { b.reserve(5, EndWatch(end, Job()) { null }) }
            end.complete(5)
            repeat(5) { yield() }
            assertEquals(1, b.waiting)
            b.release(8)
            w.join()
            assertEquals(5, b.reserved)
        }

    /** The connection's end wakes a waiter that then gives up with the connection's reason; a lost stream gives its own. */
    @Test fun negative_connectionEndAndStreamLossEndTheWait() =
        runBlocking {
            val b = HeaderBudget(10)
            b.reserve(10)
            val connection = Job()
            val closedReason = IllegalStateException("connection closed")
            val a =
                async(start = CoroutineStart.UNDISPATCHED) {
                    runCatching { b.reserve(1, EndWatch(null, connection) { if (connection.isCompleted) closedReason else null }) }
                }
            val lost = kotlinx.coroutines.CompletableDeferred<Long>()
            val c = async(start = CoroutineStart.UNDISPATCHED) { runCatching { b.reserve(1, EndWatch(lost, Job()) { null }) } }
            yield()
            assertEquals(2, b.waiting)
            connection.complete()
            val lossReason = IllegalStateException("stream lost")
            lost.completeExceptionally(lossReason)
            assertEquals(closedReason, a.await().exceptionOrNull())
            assertEquals(lossReason, c.await().exceptionOrNull())
            assertEquals(0, b.waiting)
            assertEquals(10, b.reserved)
        }

    @Test fun negative_aReservationAboveTheCapacityIsRefused() =
        runBlocking<Unit> {
            assertFailsWith<IllegalArgumentException> { HeaderBudget(10).reserve(11) }
        }

    /** Random reservations, releases and cancellations: the invariant holds at every step and everything comes back. */
    @Test fun randomUseKeepsTheInvariant() =
        runBlocking {
            forAllSeeded(20, 0x4842L) { rnd, _ ->
                val b = HeaderBudget(100)
                val holders = mutableListOf<Pair<Job, Long>>()
                val held = mutableListOf<Long>()
                repeat(500) {
                    when (rnd.nextInt(3)) {
                        0 -> {
                            val n = rnd.nextLong(0, 101)
                            holders +=
                                launch(start = CoroutineStart.UNDISPATCHED) {
                                    b.reserve(n)
                                    held += n
                                } to n
                        }

                        1 -> {
                            if (held.isNotEmpty()) b.release(held.removeAt(rnd.nextInt(held.size)))
                        }

                        else -> {
                            holders
                                .filter { it.first.isActive }
                                .randomOrNull(rnd)
                                ?.first
                                ?.cancel()
                        }
                    }
                    // a cancelled waiter that was granted gives back and grants the next in line, which resume in turn
                    repeat(20) { yield() }
                    assertTrue(b.reserved in 0..100, "reserved ${b.reserved}")
                    assertEquals(held.sum(), b.reserved, "reserved equals what the holders hold")
                }
                holders.forEach { it.first.cancel() }
                holders.forEach { it.first.join() }
                held.forEach { b.release(it) }
                assertEquals(0, b.reserved)
                assertEquals(0, b.waiting)
            }
        }
}
