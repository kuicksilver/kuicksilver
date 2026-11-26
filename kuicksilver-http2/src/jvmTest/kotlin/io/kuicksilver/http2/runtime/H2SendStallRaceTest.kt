// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.runtime

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readBuffer
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.http2Settings
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.concurrent.Volatile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * A request body held up by the server's window: a window update taken as the send-stall bound fires (the timeout lands on
 * another thread after the wait returned, before the bound's scope completed) is progress, and the body goes on. Before,
 * the stream failed as stalled for a peer that had opened its window in time. A run whose window update did not come
 * before the bound (a cold JVM) is repeated with the bound doubled.
 */
class H2SendStallRaceTest {
    @Volatile private var reached = false

    @Test fun negative_aWindowTakenAsTheStallBoundFiresIsProgress() {
        var bound = 300L
        repeat(6) {
            reached = false
            val outcome = send(bound)
            if (reached) {
                assertEquals(2 * WINDOW, outcome.getOrThrow(), "the whole body arrived")
                return
            }
            bound *= 2
        }
        fail("no run reached the race")
    }

    private fun send(bound: Long): Result<Int> =
        runBlocking {
            val toServer = ByteChannel()
            val toClient = ByteChannel()
            val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
            try {
                val close = {
                    toServer.close()
                    toClient.close()
                }
                val settings =
                    http2Settings {
                        initialStreamWindow = WINDOW.toLong()
                        maxStreamWindow = WINDOW.toLong()
                    }
                val server = H2ServerConnection.start(toServer, toClient, settings, scope, close)
                val client = H2ClientConnection.start(toClient, toServer, Http2Settings.Default, scope, Duration.INFINITE, close)
                val received =
                    scope.async {
                        val r = server.requests.receive()
                        r.body
                            .readBuffer()
                            .size
                            .toInt()
                            .also { r.respond(204, endStream = true) }
                    }
                var raced = false
                client.rt.stallWaitedForTest = {
                    if (!raced) {
                        raced = true
                        yield() // returns through a resumption, as the wait does; throws once the bound fired
                        reached = true
                        val job = currentCoroutineContext().job
                        val giveUp = TimeSource.Monotonic.markNow() + 30.seconds
                        while (!job.isCancelled && giveUp.hasNotPassedNow()) Thread.onSpinWait() // the bound fires
                    }
                }
                check(client.tryReserve())
                val s = client.open("POST", "https", "example.com", "/", listOf("content-length" to "${2 * WINDOW}"), endStream = false)
                val sent =
                    withContext(Dispatchers.Default) {
                        runCatching { s.sendBody(ByteReadChannel(ByteArray(2 * WINDOW)), stallMillis = bound) { error("stalled") } }
                    }
                sent.mapCatching { withTimeout(30.seconds) { received.await() } }
            } finally {
                scope.cancel()
            }
        }

    private companion object {
        const val WINDOW = 16_384
    }
}
