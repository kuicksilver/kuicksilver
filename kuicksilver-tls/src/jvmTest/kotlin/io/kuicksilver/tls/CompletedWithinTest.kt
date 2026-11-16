// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.milliseconds

/** [completedWithin]: a block that returned is never reported as timed out. */
class CompletedWithinTest {
    /**
     * The block returns after the deadline fired but before the timeout's scope completed (it does not suspend, so the
     * cancellation cannot stop it): its result is kept. `withTimeoutOrNull` gives null here, and a session whose critical
     * streams were opened and typed was closed for not having opened them.
     */
    @Test fun negative_aResultThatRacesTheDeadlineIsKept() =
        runBlocking {
            // the yield before the race must end within the deadline (a loaded host may hold it longer): a run that did not
            // reach the race does not count, and the next one gets the deadline doubled
            var d = 50.milliseconds
            repeat(8) {
                var reached = false
                val got =
                    completedWithin(d) {
                        // suspended once, so the block completes through a resumption, as the critical streams' attempt
                        // does (a block that never suspends is returned as is)
                        kotlinx.coroutines.yield()
                        reached = true
                        val job = currentCoroutineContext().job
                        while (!job.isCancelled) Thread.onSpinWait() // the deadline fires meanwhile, on another thread
                        42
                    }
                if (reached) {
                    assertEquals(42, got)
                    return@runBlocking
                }
                d *= 2
            }
            kotlin.test.fail("the yield never ended within ${d / 2}")
        }

    /** A block that is still waiting when the deadline fires gives null. */
    @Test fun aBlockStillWaitingGivesNull() =
        runBlocking {
            assertNull(completedWithin(20.milliseconds) { kotlinx.coroutines.awaitCancellation() })
        }
}
