// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * What the accept loop hands a connection's coroutine (the accepted socket, the TLS session its handshake made) is released
 * however that coroutine ends, also when it never runs or a timeout drops the session.
 */
class ConnectionHandOverTest {
    /**
     * A handshake that completes as the request-head deadline fires: kotlinx's `withTimeoutOrNull` answers null and drops
     * the result, whose native TLS session nobody would close. The block here has suspended once (as a handshake does;
     * a block that never suspends keeps its result) and finishes without suspending again after the deadline fired on
     * another thread, which is exactly that window.
     */
    @Test fun aResultMadeAsTheDeadlineFiresIsReleased(): Unit =
        runBlocking {
            // a run whose deadline fired before the block resumed from its suspension did not reach the race: the next one
            // tries with the deadline doubled
            var deadline = 50L
            repeat(6) {
                val released = mutableListOf<String>()
                var reached = false
                val result =
                    withContext(Dispatchers.Default) {
                        withTimeoutOrRelease(deadline.milliseconds, { released += it }) {
                            yield() // returns through a resumption; throws once the deadline fired
                            reached = true
                            // the deadline fires meanwhile, on another thread: the block never suspends again, and finishes
                            // once its job is cancelled (a state that stays), not after a guess of how long that takes
                            val job = currentCoroutineContext().job
                            val giveUp = TimeSource.Monotonic.markNow() + 30.seconds
                            @Suppress("ControlFlowWithEmptyBody")
                            while (!job.isCancelled && giveUp.hasNotPassedNow()) {
                            }
                            "session"
                        }
                    }
                if (reached) {
                    assertNull(result)
                    assertEquals(listOf("session"), released)
                    return@runBlocking
                }
                deadline *= 2
            }
            fail("no run reached the race")
        }

    @Test fun aResultInTimeIsReturnedNotReleased(): Unit =
        runBlocking {
            val released = mutableListOf<String>()
            assertEquals("session", withTimeoutOrRelease(5000.milliseconds, { released += it }) { "session" })
            assertTrue(released.isEmpty())
        }

    /**
     * A stop between `accept()` and the connection's launch: the scope is cancelled, and a plain `launch` never ran its
     * body (nor its `finally`), so the accepted socket and its `tcp { maxConnections }` slot stayed taken.
     */
    @Test fun aLaunchOnACancelledScopeStillReleases(): Unit =
        runBlocking {
            val scope = CoroutineScope(Job().apply { cancel() })
            var released = false
            var ran = false
            scope.launchOrElse(onCancelled = { released = true }) { ran = true }.join()
            assertTrue(released)
            assertFalse(ran)
        }

    @Test fun aLaunchOnALiveScopeRunsTheBlock(): Unit =
        runBlocking {
            var released = false
            var ran = false
            launchOrElse(onCancelled = { released = true }) { ran = true }.join()
            assertTrue(ran)
            assertFalse(released)
        }
}
