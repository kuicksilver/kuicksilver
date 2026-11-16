// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.yield
import kotlin.concurrent.Volatile
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.fail
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * A DNS answer that came as the query's timeout fired (the timeout lands on another thread after the wait for the lookup
 * returned, before the timeout's scope completed) is the answer: before, the query reported no answer although the lookup
 * had one. A run whose lookup did not answer before the timeout is repeated with the timeout doubled.
 */
class KslDnsRaceTest {
    @Volatile private var reached = false

    @AfterTest fun reset() {
        KslDns.queryForTest = null
    }

    @Test fun negative_anAnswerThatCameAsTheTimeoutFiresIsTheAnswer(): Unit =
        runBlocking {
            KslDns.queryForTest = { _, _, _, _ -> ByteArray(0) } // an answer without records
            var timeout = 200L
            repeat(6) {
                reached = false
                val answer =
                    withContext(Dispatchers.Default) {
                        KslDns.query("example.test", 1, timeout.milliseconds, null) {
                            yield() // returns through a resumption, as the wait does; throws once the timeout fired
                            reached = true
                            val job = currentCoroutineContext().job
                            val giveUp = TimeSource.Monotonic.markNow() + 30.seconds
                            while (!job.isCancelled && giveUp.hasNotPassedNow()) Thread.onSpinWait() // the timeout fires
                        }
                    }
                if (reached) {
                    assertNotNull(answer, "the lookup had answered")
                    return@runBlocking
                }
                timeout *= 2
            }
            fail("no run reached the race")
        }
}
