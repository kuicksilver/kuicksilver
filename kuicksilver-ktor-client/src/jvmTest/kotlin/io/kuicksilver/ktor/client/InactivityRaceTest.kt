// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.concurrent.Volatile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * A tick the inactivity watchdog sees as its timeout fires (the timeout lands on another thread after the wait for the tick
 * returned, before the timeout's scope completed) is progress: the block goes on and the watchdog waits again. Before, the
 * tick was dropped with the wait's result and the exchange was cut as inactive although data had moved.
 */
class InactivityRaceTest {
    @Volatile private var reached = false

    @Test fun negative_aTickSeenAsTheTimeoutFiresIsProgress(): Unit =
        runBlocking {
            var millis = 200L
            // a run whose watchdog did not see the tick before its timeout (a cold or loaded JVM) does not reach the race:
            // it is repeated with the timeout doubled, and only a run that reached it is judged
            repeat(6) {
                val activity = Activity()
                val raced = CompletableDeferred<Unit>()
                reached = false
                activity.tickSeenForTest = {
                    yield() // returns through a resumption, as a wait for a tick does; throws once the timeout fired
                    reached = true
                    val job = currentCoroutineContext().job
                    val giveUp = TimeSource.Monotonic.markNow() + 30.seconds
                    while (!job.isCancelled && giveUp.hasNotPassedNow()) Thread.onSpinWait() // the timeout fires meanwhile
                    activity.tickSeenForTest = null
                    raced.complete(Unit)
                }
                val outcome =
                    withContext(Dispatchers.Default) {
                        runCatching {
                            activity.within(millis, { IllegalStateException("inactive", it) }) {
                                activity.watchingForTest.first { it > 0 } // the watchdog waits for a tick
                                activity.tick()
                                withTimeout(30.seconds) { raced.await() }
                                // the watchdog that took the tick for progress waits for the next one: it watches again
                                activity.watchingForTest.first { it > 0 }
                                "done"
                            }
                        }
                    }
                if (!reached) {
                    millis *= 2
                    return@repeat
                }
                assertEquals("done", outcome.getOrThrow(), "the tick seen as the timeout fired is progress")
                return@runBlocking
            }
            fail("no run reached the race")
        }
}
