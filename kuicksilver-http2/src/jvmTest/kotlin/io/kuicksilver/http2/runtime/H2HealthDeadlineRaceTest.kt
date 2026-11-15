// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.runtime

import io.ktor.utils.io.ByteChannel
import io.kuicksilver.http2.Http2Settings
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import kotlin.concurrent.Volatile
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration

/**
 * A health check whose PING acknowledgement was read as the check's bound fired (the timeout lands on another thread after
 * the answer, before the bound's scope completed) reports a live connection: a "dead" verdict there retired a healthy one.
 * A run whose hook was not reached before the bound (a cold JVM's first PING round trip) is repeated with the bound doubled.
 */
class H2HealthDeadlineRaceTest {
    @Volatile private var reached = false

    @Test fun negative_aPingAnsweredAsTheBoundFiresIsALiveConnection() {
        var bound = 200L
        repeat(7) {
            reached = false
            val alive = check(bound)
            if (reached) {
                assertTrue(alive, "the PING was answered")
                return
            }
            bound *= 2
        }
        fail("the PING round trip never ended within ${bound / 2} ms")
    }

    private fun check(bound: Long): Boolean =
        runBlocking {
            val toServer = ByteChannel()
            val toClient = ByteChannel()
            val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
            try {
                val close = {
                    toServer.close()
                    toClient.close()
                }
                H2ServerConnection.start(toServer, toClient, Http2Settings(), scope, close)
                val client = H2ClientConnection.start(toClient, toServer, Http2Settings(), scope, Duration.INFINITE, close)
                client.rt.healthAnsweredForTest = {
                    yield() // throws when the bound already fired: the run does not count
                    reached = true
                    val job = currentCoroutineContext().job
                    while (!job.isCancelled) Thread.onSpinWait()
                }
                client.checkHealth(bound)
            } finally {
                scope.cancel()
            }
        }
}
