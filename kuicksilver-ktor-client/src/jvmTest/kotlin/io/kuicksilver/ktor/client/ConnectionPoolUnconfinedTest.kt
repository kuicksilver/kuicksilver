// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.client.h1.ConnectionPool
import io.kuicksilver.ktor.client.h1.PoolLimits
import io.kuicksilver.ktor.client.h1.PooledConnection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/**
 * [ConnectionPool] under `Dispatchers.Unconfined` (an engine `dispatcher` a user may pick): a waiter resumes inline in the
 * thread that hands it a connection. The hand-over must not happen inside the pool's spin lock, or a waiter that touches the
 * pool again before suspending (its connection fails at once, its connect fails synchronously) spins on the lock its own
 * thread holds. JVM only: the test needs a thread it can give up on when it deadlocks.
 */
class ConnectionPoolUnconfinedTest {
    private class Conn(
        route: String,
    ) : PooledConnection(route, 0) {
        override val isOpen: Boolean get() = !closed

        override fun closeTransport() = Unit
    }

    private fun inThread(block: suspend kotlinx.coroutines.CoroutineScope.() -> Unit) {
        var failure: Throwable? = null
        val t =
            Thread {
                try {
                    runBlocking { block() }
                } catch (e: Throwable) {
                    failure = e
                }
            }
        t.isDaemon = true // a deadlocked thread must not keep the test JVM alive
        t.start()
        t.join(30_000)
        assertFalse(t.isAlive, "deadlock: the thread still spins on the pool's lock")
        failure?.let { throw it }
    }

    @Test fun handedConnectionClosedAtOnceDoesNotDeadlock() =
        inThread {
            val p = ConnectionPool<Conn>(PoolLimits(10, 1, 1, 300_000, Long.MAX_VALUE)) { 0L }
            assertEquals(null, p.acquire("a")) // a permit: the route's one slot
            val held = Conn("a").also { p.adopt(it) }
            val waiter =
                launch(Dispatchers.Unconfined) {
                    val c = p.acquire("a")!!
                    c.close() // fails at once: gives its slot back, which takes the pool's lock
                }
            p.release(held) // the waiter resumes inline here
            waiter.join()
            assertEquals(0, p.liveCount)
        }

    @Test fun permitWhoseConnectFailsSynchronouslyDoesNotDeadlock() =
        inThread {
            val p = ConnectionPool<Conn>(PoolLimits(10, 1, 1, 300_000, Long.MAX_VALUE)) { 0L }
            assertEquals(null, p.acquire("a"))
            val held = Conn("a").also { p.adopt(it) }
            val waiter =
                launch(Dispatchers.Unconfined) {
                    assertEquals(null, p.acquire("a"))
                    p.releasePermit("a") // the connect failed before suspending
                }
            held.close() // its slot goes to the waiter as a permit, inline
            waiter.join()
            assertEquals(0, p.liveCount)
        }
}
