// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.client.h1.ConnectionPool
import io.kuicksilver.ktor.client.h1.PoolLimits
import io.kuicksilver.ktor.client.h1.PooledConnection
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** [ConnectionPool] on its own: fake connections and a clock the test moves (no sockets, no waiting on real time). */
class ConnectionPoolTest {
    private class FakeConn(
        route: String,
        createdAt: Long,
    ) : PooledConnection(route, createdAt) {
        val transportCloses = AtomicInt(0)
        var peerClosed = false

        override val isOpen: Boolean get() = !closed && !peerClosed

        override fun closeTransport() {
            transportCloses.addAndFetch(1)
        }
    }

    private var now = 0L

    private fun pool(
        maxTotal: Int = 1000,
        maxPerRoute: Int = 100,
        maxIdle: Int = 5,
        idle: Long = 300_000,
        lifetime: Long = Long.MAX_VALUE,
    ) = ConnectionPool<FakeConn>(PoolLimits(maxTotal, maxPerRoute, maxIdle, idle, lifetime)) { now }

    /** A connection for [route]: the idle one the pool hands out, or a new one opened under the permit. */
    private suspend fun ConnectionPool<FakeConn>.get(route: String): FakeConn = acquire(route) ?: FakeConn(route, now).also { adopt(it) }

    private fun test(block: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(30.seconds) { block() } }

    @Test fun limitsHoldUnderConcurrency() =
        test {
            val p = pool(maxTotal = 3, maxPerRoute = 2, maxIdle = 1)
            val perRoute = mapOf("a" to AtomicInt(0), "b" to AtomicInt(0))
            val total = AtomicInt(0)
            val maxSeen = AtomicInt(0)
            val routeMaxSeen = AtomicInt(0)
            coroutineScope {
                repeat(400) { i ->
                    launch(Dispatchers.Default) {
                        val route = if (i % 2 == 0) "a" else "b"
                        val c = p.get(route)
                        val t = total.addAndFetch(1)
                        val r = perRoute.getValue(route).addAndFetch(1)
                        while (true) {
                            val m = maxSeen.load()
                            if (t <= m || maxSeen.compareAndSet(m, t)) break
                        }
                        while (true) {
                            val m = routeMaxSeen.load()
                            if (r <= m || routeMaxSeen.compareAndSet(m, r)) break
                        }
                        yield()
                        perRoute.getValue(route).addAndFetch(-1)
                        total.addAndFetch(-1)
                        if (Random.nextBoolean()) p.release(c) else c.close()
                    }
                }
            }
            assertTrue(maxSeen.load() <= 3, "at most 3 connections in use, saw ${maxSeen.load()}")
            assertTrue(routeMaxSeen.load() <= 2, "at most 2 per route, saw ${routeMaxSeen.load()}")
            assertEquals(0, p.waiterCount)
            assertEquals(p.idleCount, p.liveCount, "only idle connections are left, each counted once")
            assertTrue(p.liveCount <= 2)
        }

    @Test fun waitersAreServedInArrivalOrder() =
        test {
            val p = pool(maxPerRoute = 1)
            val held = p.get("a")
            val order = ArrayList<Int>()
            coroutineScope {
                for (i in 0 until 5) {
                    launch {
                        val c = p.get("a")
                        order += i
                        p.release(c)
                    }
                    while (p.waiterCount < i + 1) yield() // each one queued before the next arrives
                }
                p.release(held)
            }
            assertEquals(listOf(0, 1, 2, 3, 4), order)
            assertEquals(1, p.liveCount)
        }

    @Test fun aFullRouteDoesNotHoldUpOthers() =
        test {
            val p = pool(maxTotal = 10, maxPerRoute = 1)
            val a = p.get("a")
            val blocked = async { p.get("a") }
            while (p.waiterCount < 1) yield()
            val b = p.get("b") // another route has room: no queueing behind the waiter of "a"
            assertEquals("b", b.route)
            p.release(a)
            assertSame(a, blocked.await())
        }

    @Test fun cancelledWaiterTakesNothingAndLosesNothing() =
        test {
            val p = pool(maxPerRoute = 1)
            val held = p.get("a")
            val waiter = launch { p.get("a") }
            while (p.waiterCount < 1) yield()
            waiter.cancel()
            waiter.join()
            assertEquals(0, p.waiterCount)
            assertEquals(1, p.liveCount)
            held.close()
            assertEquals(0, p.liveCount)
            assertEquals(0, p.routeCount)
            assertNull(p.acquire("a")) // the route has room again: a permit
            p.releasePermit("a")
            assertEquals(0, p.liveCount)
        }

    /** Cancellation racing the hand-over: whatever the waiter was given goes back exactly once. */
    @Test fun cancellationRacingReleaseNeverCountsTwice() =
        test {
            val p = pool(maxTotal = 2, maxPerRoute = 2, maxIdle = 2)
            repeat(300) {
                val a = p.get("r")
                val b = p.get("r")
                var got: FakeConn? = null // kept as soon as acquire returns: a cancelled coroutine's result is dropped
                val waiter = launch(Dispatchers.Default) { got = p.get("r") }
                while (p.waiterCount < 1) yield()
                val canceller = launch(Dispatchers.Default) { waiter.cancel() }
                p.release(a)
                canceller.join()
                waiter.join()
                got?.let { p.release(it) }
                b.close()
                assertEquals(0, p.waiterCount)
                assertEquals(p.idleCount, p.liveCount, "round $it")
            }
            assertTrue(p.liveCount <= 2)
        }

    @Test fun closingTwiceReturnsTheSlotOnce() =
        test {
            val p = pool(maxPerRoute = 2)
            val c = p.get("a")
            p.get("a")
            c.close()
            c.close()
            p.release(c) // a late release of a closed connection is ignored
            assertEquals(1, p.liveCount)
            assertEquals(1, c.transportCloses.load())
        }

    @Test fun permitWhoseConnectFailedComesBack() =
        test {
            val p = pool(maxPerRoute = 1)
            assertNull(p.acquire("a"))
            val waiter = async { p.get("a") }
            while (p.waiterCount < 1) yield()
            p.releasePermit("a") // the connect failed: the waiter gets the permit
            val c = waiter.await()
            assertEquals(1, p.liveCount)
            c.close()
            assertEquals(0, p.routeCount)
        }

    @Test fun idleConnectionsExpire() =
        test {
            val p = pool(idle = 1000)
            val c = p.get("a")
            now = 50
            p.release(c)
            now = 1049
            assertEquals(1L, p.evictExpired())
            assertEquals(1, p.idleCount)
            now = 1050
            assertNull(p.evictExpired())
            assertEquals(0, p.liveCount)
            assertEquals(0, p.routeCount)
            assertEquals(1, c.transportCloses.load())
        }

    @Test fun connectionsPastTheirLifetimeAreNotReused() =
        test {
            val p = pool(lifetime = 100)
            val c = p.get("a")
            now = 100
            p.release(c)
            assertTrue(c.closed)
            assertEquals(0, p.liveCount)
            val d = p.get("a")
            now = 150
            p.release(d)
            now = 200
            assertNull(p.acquire("a"), "an idle connection past its lifetime is closed, not handed out")
            assertTrue(d.closed)
        }

    @Test fun staleIdleConnectionIsReplaced() =
        test {
            val p = pool()
            val c = p.get("a")
            p.release(c)
            c.peerClosed = true
            assertNull(p.acquire("a")) // a permit for a new connection
            assertTrue(c.closed)
            assertEquals(1, p.liveCount)
        }

    @Test fun fullTotalClosesAnotherRoutesIdleConnection() =
        test {
            val p = pool(maxTotal = 1)
            val a = p.get("a")
            p.release(a)
            val b = p.get("b")
            assertTrue(a.closed)
            assertEquals("b", b.route)
            assertEquals(1, p.liveCount)
        }

    @Test fun releaseWithWaitersOfOtherRoutesFreesTheSlot() =
        test {
            val p = pool(maxTotal = 1)
            val a = p.get("a")
            val waiter = async { p.get("b") }
            while (p.waiterCount < 1) yield()
            p.release(a) // not kept idle: route "b" needs the slot
            assertTrue(a.closed)
            assertEquals("b", waiter.await().route)
        }

    /** The route map holds routes with connections or waiters only: 10k origins leave a bounded map. */
    @Test fun tenThousandOriginsLeaveABoundedMap() =
        test {
            val p = pool(maxTotal = 100, idle = 1000)
            for (i in 0 until 10_000) p.release(p.get("origin-$i"))
            assertTrue(p.routeCount <= 100, "routes: ${p.routeCount}")
            assertTrue(p.liveCount <= 100)
            now = 1000
            p.evictExpired()
            assertEquals(0, p.routeCount)
            assertEquals(0, p.liveCount)
            for (i in 0 until 10_000) p.get("closed-$i").close()
            assertEquals(0, p.routeCount)
        }

    @Test fun shutdownFailsWaitersAndClosesIdle() =
        test {
            val p = pool(maxPerRoute = 1)
            val a = p.get("a")
            val b = p.get("b")
            p.release(b)
            val waiter = async { runCatching { p.get("a") } }
            while (p.waiterCount < 1) yield()
            p.shutdown()
            assertTrue(waiter.await().isFailure)
            assertTrue(b.closed)
            a.close()
            assertEquals(0, p.liveCount)
            assertNotNull(runCatching { p.acquire("c") }.exceptionOrNull())
        }

    @Test fun waitersOfManyRoutesAllComplete() =
        test {
            val p = pool(maxTotal = 4, maxPerRoute = 2, maxIdle = 1)
            val results =
                (0 until 200).map { i ->
                    async(Dispatchers.Default) {
                        val c = p.get("r${i % 7}")
                        yield()
                        p.release(c)
                        i
                    }
                }
            assertEquals(200, results.awaitAll().size)
            assertTrue(p.liveCount <= 4)
        }

    /**
     * A waiter cancelled while [ConnectionPool.shutdown] fails the waiters (after it left the queue, before its own failure
     * arrived) ends with a CancellationException like the others, not "This job has not completed yet".
     */
    @Test fun waiterCancelledDuringShutdownGetsCancellation() =
        test {
            val p = pool(maxPerRoute = 1)
            val held = p.get("a")
            var secondFailure: Throwable? = null
            lateinit var second: Job
            // Unconfined: the first waiter's failure runs inside shutdown() and cancels the second before shutdown reaches it
            val first =
                launch(Dispatchers.Unconfined) {
                    try {
                        p.get("a")
                    } finally {
                        second.cancel()
                    }
                }
            second =
                launch(Dispatchers.Unconfined) {
                    try {
                        p.get("a")
                    } catch (e: Throwable) {
                        secondFailure = e
                    }
                }
            assertEquals(2, p.waiterCount)
            p.shutdown()
            first.join()
            second.join()
            assertTrue(secondFailure is CancellationException, "the second waiter failed with $secondFailure")
            held.close()
            assertEquals(0, p.liveCount)
        }
}
