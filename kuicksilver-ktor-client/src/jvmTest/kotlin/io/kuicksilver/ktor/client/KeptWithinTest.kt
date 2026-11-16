// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.yield
import kotlin.concurrent.Volatile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.fail
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * [keptWithin], the bound of the platform lookups (Android's HTTPS and address queries through DnsResolver, the Apple PAC
 * evaluation, its host lookups, script runs and downloads): an answer the block returned as the timeout fired (the timeout
 * lands on another thread after the block returned, before the timeout's scope completed) is the answer. Those platform
 * paths run only on their targets; this is the code they share, run here.
 */
class KeptWithinTest {
    @Volatile private var reached = false

    @Test fun negative_anAnswerReturnedAsTheTimeoutFiresIsKept(): Unit =
        runBlocking {
            var timeout = 200L
            repeat(6) {
                reached = false
                val answer = CompletableDeferred<String>()
                val got =
                    withContext(Dispatchers.Default) {
                        coroutineScope {
                            // the wait starts first, then the answer comes (from another thread, as a platform callback's)
                            val wait =
                                async(start = CoroutineStart.UNDISPATCHED) {
                                    keptWithin(timeout.milliseconds, {
                                        yield() // returns through a resumption; throws once the timeout fired
                                        reached = true
                                        val job = currentCoroutineContext().job
                                        val giveUp = TimeSource.Monotonic.markNow() + 30.seconds
                                        while (!job.isCancelled && giveUp.hasNotPassedNow()) Thread.onSpinWait()
                                    }) { answer.await() }
                                }
                            answer.complete("answer")
                            wait.await()
                        }
                    }
                if (reached) {
                    assertEquals("answer", got)
                    return@runBlocking
                }
                timeout *= 2
            }
            fail("no run reached the race")
        }

    @Test fun aBlockThatGivesNullOrRunsOutGivesNull(): Unit =
        runBlocking {
            assertNull(keptWithin(1.seconds) { null })
            assertNull(keptWithin(10.milliseconds) { awaitCancellation() })
        }
}
