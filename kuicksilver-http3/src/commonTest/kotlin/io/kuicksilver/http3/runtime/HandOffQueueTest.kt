// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.channels.ClosedSendChannelException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The lossless hand-off: nothing is lost to a cancelled receiver or sender, and back-pressure holds. */
class HandOffQueueTest {
    private fun test(block: suspend kotlinx.coroutines.CoroutineScope.() -> Unit) =
        runBlocking { withTimeout(30.seconds) { withContext(Dispatchers.Default) { block() } } }

    /** One consumer whose every receive may be cancelled at its resumption: all elements, once each, in order. */
    @Test fun negative_aCancelledReceiverLosesNothingAndKeepsTheOrder() =
        test {
            val d = CancellingDispatcher(Random.nextLong())
            val q = HandOffQueue<Int>(4)
            val n = 1_000
            // every other element goes once the one before it was taken, so the consumer often waits for one (and is then
            // resumed through the cancelling dispatcher); the others may queue up
            val taken = MutableStateFlow(0)
            launch {
                for (i in 0 until n) {
                    if (i % 2 == 0) taken.first { it >= i }
                    q.send(i)
                }
                q.close()
            }
            var next = 0
            while (true) {
                val job = async(d, start = CoroutineStart.UNDISPATCHED) { q.receive() }
                val r = runCatching { job.await() }
                if (r.isFailure && job.isCancelled) {
                    currentCoroutineContext().ensureActive() // the test's own timeout ends the loop
                    continue
                }
                val got = r.getOrThrow() ?: break
                assertEquals(next, got, "$d")
                next++
                taken.value = next
            }
            assertEquals(n, next, "$d")
            assertTrue(d.cancelled > 0)
        }

    /** Several consumers and producers, all of them randomly cancelled at resumption: every element is taken exactly once. */
    @Test fun negative_concurrentCancelledReceiversAndSendersLoseNothing() =
        test {
            val d = CancellingDispatcher(Random.nextLong())
            val q = HandOffQueue<Int>(3)
            val producers = 4
            val per = 500
            val taken = Array(producers * per) { 0 }
            val senders =
                (0 until producers).map { p ->
                    launch {
                        for (i in 0 until per) {
                            val v = p * per + i
                            // a send cancelled while it waits for room did not add the element: it is sent again
                            while (true) {
                                val job = async(d, start = CoroutineStart.UNDISPATCHED) { q.send(v) }
                                if (runCatching { job.await() }.isSuccess) break
                                currentCoroutineContext().ensureActive()
                            }
                        }
                    }
                }
            val consumers =
                (0 until 3).map {
                    async {
                        val mine = ArrayList<Int>()
                        while (true) {
                            val job = async(d, start = CoroutineStart.UNDISPATCHED) { q.receive() }
                            val r = runCatching { job.await() }
                            if (r.isFailure && job.isCancelled) {
                                currentCoroutineContext().ensureActive()
                                continue
                            }
                            mine += r.getOrThrow() ?: break
                        }
                        mine
                    }
                }
            senders.forEach { it.join() }
            q.close()
            for (v in consumers.awaitAll().flatten()) taken[v]++
            assertEquals(List(producers * per) { 1 }, taken.toList(), "$d: an element lost or taken twice")
            assertTrue(d.cancelled > 0)
        }

    /**
     * The one wake-up for an element goes to a waiter that is cancelled before it runs: it is passed on, so the other waiter
     * takes the element instead of sleeping next to it.
     */
    @Test fun negative_aWakeUpTakenByACancelledWaiterIsPassedOn() =
        test {
            val q = HandOffQueue<Int>()
            val steps = StepDispatcher()
            val first = launch(steps, start = CoroutineStart.UNDISPATCHED) { q.receive() }
            val second = async(start = CoroutineStart.UNDISPATCHED) { q.receive() }
            assertTrue(q.offer(1))
            val resumed = steps.tasks.receive() // the wake-up went to the first waiter
            first.cancel()
            resumed.run()
            assertTrue(first.isCancelled)
            assertEquals(1, withTimeoutOrNull(5.seconds) { second.await() }, "the second waiter slept next to the element")
        }

    /**
     * A collector of [HandOffQueue.asFlow] whose job is cancelled while it handles element 1 leaves element 2 in the queue
     * (a `flow {}` builder took it first and then dropped it in `emit`).
     */
    @Test fun negative_aCollectorCancelledWhileHandlingAnElementLeavesTheNextQueued() =
        test {
            val q = HandOffQueue<Int>()
            q.offer(1)
            q.offer(2)
            val got = ArrayList<Int>()
            launch {
                q.asFlow().collect {
                    got += it
                    if (it == 1) currentCoroutineContext().job.cancel()
                }
            }.join()
            assertEquals(listOf(1), got)
            assertEquals(2, q.tryTake(), "element 2 was taken and dropped")
        }

    /**
     * Collectors of [HandOffQueue.asFlow] cancelled by another thread at arbitrary moments, against a producer that is
     * sometimes ahead and sometimes behind: every element handed to a collector arrives, once, in order.
     */
    @Test fun negative_collectorsCancelledAtAnyTimeLoseNothing() =
        test {
            val k = Killer(Random.nextLong())
            val q = HandOffQueue<Int>(3)
            val n = 3_000
            val taken = MutableStateFlow(0)
            launch {
                for (i in 0 until n) {
                    if (i % 3 == 0) taken.first { it >= i }
                    q.send(i)
                }
                q.close()
            }
            val got = ArrayList<Int>()
            k.run(this) {
                q.asFlow().collect {
                    got += it
                    taken.value = got.size
                }
            }
            assertEquals((0 until n).toList(), got, "$k")
            assertTrue(k.kills > 0, "$k cancelled no collector")
        }

    /** A full queue holds its sender back until a receiver takes one; it never holds more than its capacity. */
    @Test fun sendWaitsForRoom() =
        test {
            val q = HandOffQueue<Int>(2)
            q.send(1)
            q.send(2)
            val third = launch(start = CoroutineStart.UNDISPATCHED) { q.send(3) }
            assertFalse(third.isCompleted)
            assertFalse(q.offer(4), "a full queue took an offer")
            assertEquals(1, q.receive())
            third.join()
            assertEquals(2, q.receive())
            assertEquals(3, q.receive())
            assertNull(q.tryTake())
        }

    /** What is held when the queue closes is still received; then the end, or the cause. */
    @Test fun closeKeepsWhatIsHeldThenEnds() =
        test {
            val q = HandOffQueue<Int>()
            assertTrue(q.offer(1))
            val cause = IOException("gone")
            assertTrue(q.close(cause))
            assertFalse(q.close(), "a second close took effect")
            assertFalse(q.offer(2))
            assertFalse(q.putBack(2))
            assertFailsWith<ClosedSendChannelException> { q.send(2) }
            assertEquals(1, q.receive())
            assertSame(cause, assertFailsWith<IOException> { q.receive() })
            val clean = HandOffQueue<Int>()
            clean.close()
            assertNull(clean.receive())
        }

    /** A waiting receiver and a waiting sender both see the close. */
    @Test fun closeWakesEveryWaiter() =
        test {
            val empty = HandOffQueue<Int>()
            val receivers = List(3) { async(start = CoroutineStart.UNDISPATCHED) { empty.receive() } }
            empty.close()
            assertEquals(listOf(null, null, null), receivers.awaitAll())
            val full = HandOffQueue<Int>(1)
            full.send(0)
            val senders = List(3) { async(start = CoroutineStart.UNDISPATCHED) { runCatching { full.send(1) }.exceptionOrNull() } }
            full.close()
            senders.awaitAll().forEach { assertTrue(it is ClosedSendChannelException, "$it") }
        }

    /** An element put back goes ahead of everything queued, even past the capacity. */
    @Test fun putBackGoesFirst() =
        test {
            val q = HandOffQueue<Int>(1)
            q.send(2)
            assertTrue(q.putBack(1))
            assertEquals(1, q.receive())
            assertEquals(2, q.receive())
        }
}
