// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.milliseconds

/** [completedWithin], the deadline of the critical streams: a block that returned is never reported as timed out. */
class CompletedWithinTest {
    /**
     * The block returns after the deadline fired but before the timeout's scope completed (it does not suspend, so the
     * cancellation cannot stop it): its result is kept. `withTimeoutOrNull` gives null here, and a session whose critical
     * streams were opened and typed was closed for not having opened them.
     */
    @Test fun negative_aResultThatRacesTheDeadlineIsKept() =
        runBlocking {
            val got =
                completedWithin(50.milliseconds) {
                    // suspended once, so the block completes through a resumption, as the critical streams' attempt does (a
                    // block that never suspends is returned as is)
                    kotlinx.coroutines.yield()
                    val job = currentCoroutineContext().job
                    while (!job.isCancelled) Thread.onSpinWait() // the deadline fires meanwhile, on another thread
                    42
                }
            assertEquals(42, got)
        }

    /** A block that is still waiting when the deadline fires gives null. */
    @Test fun aBlockStillWaitingGivesNull() =
        runBlocking {
            assertNull(completedWithin(20.milliseconds) { kotlinx.coroutines.awaitCancellation() })
        }
}
