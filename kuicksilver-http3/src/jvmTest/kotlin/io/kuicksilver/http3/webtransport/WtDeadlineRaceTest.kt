// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** [io.kuicksilver.http3.runtime.H3Session.withinWtDeadline]: a block that completed is never reported as timed out. */
class WtDeadlineRaceTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * The deadline is chosen first (the timer completes while the block still runs), and the block completes before its
     * cancellation reaches it, as a CONNECT whose answer was read in that window: its result (a session that exists on
     * both sides) is returned, not dropped.
     */
    @Test fun negative_aBlockThatCompletesAfterTheDeadlineWasChosenKeepsItsResult() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val session = p.client.session
                val started = CompletableDeferred<Unit>()
                val timerFired = CompletableDeferred<Unit>()
                session.wtTimer = {
                    started.await()
                    timerFired.complete(Unit) // the block resumes after this timer completes and the select chose it
                }
                // one thread: the order of the resumptions is the one above, every time
                val got =
                    runBlocking {
                        session.withinWtDeadline {
                            started.complete(Unit)
                            withContext(NonCancellable) { timerFired.await() }
                            42
                        }
                    }
                assertEquals(42, got)
            }
        }

    /** A block still waiting when the deadline passes gives null. */
    @Test fun aBlockStillWaitingGivesNull() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val session = p.client.session
                session.wtTimer = {}
                assertNull(runBlocking { session.withinWtDeadline<Int> { awaitCancellation() } })
            }
        }
}
