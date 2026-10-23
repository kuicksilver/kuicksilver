// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.seconds

/**
 * The socket timeout as an inactivity timeout over a request body as its sender takes it (the HTTP/3 request path:
 * `Http3Connection.request` sends the body and returns at the response head), under virtual time.
 */
class InactivityTest {
    private class Timeout : Exception()

    /** Takes [body] 1 KiB at a time, [every] ms apart, as a flow-controlled stream would; then waits for [answerAfter]. */
    private suspend fun send(
        body: ByteReadChannel,
        every: Long,
        answerAfter: Long = 0,
    ): Int {
        val buf = ByteArray(1024)
        var total = 0
        while (true) {
            val n = body.readAvailable(buf, 0, buf.size)
            if (n < 0) break
            total += n
            delay(every)
        }
        delay(answerAfter)
        return total
    }

    /** 24 KiB taken 1 KiB per 100 ms (2.4 s) under a 1 s timeout: never 1 s without progress. */
    @Test fun bodyTakenSteadilyNeverTimesOut() =
        runTest(timeout = 20.seconds) {
            val activity = Activity()
            val body = ConsumedBody(ByteReadChannel(ByteArray(24 * 1024)), activity, step = 1024)
            val sent = activity.within(1_000, { Timeout() }) { send(body, every = 100) }
            assertEquals(24 * 1024, sent)
            assertEquals(2_400L, currentTime)
        }

    /** A response head that does not come within 1 s of the body's end times out then. */
    @Test fun negative_silenceAfterTheBodyTimesOut() =
        runTest(timeout = 20.seconds) {
            val activity = Activity()
            val body = ConsumedBody(ByteReadChannel(ByteArray(4 * 1024)), activity, step = 1024)
            assertFailsWith<Timeout> { activity.within(1_000, { Timeout() }) { send(body, every = 100, answerAfter = 5_000) } }
            assertEquals(300L + 1_000L, currentTime) // the last piece was taken at 300 ms
        }

    /** A sender that stops taking the body (flow control, a peer that does not read) times out 1 s after it stopped. */
    @Test fun negative_stalledSenderTimesOut() =
        runTest(timeout = 20.seconds) {
            val activity = Activity()
            val body = ConsumedBody(ByteReadChannel(ByteArray(24 * 1024)), activity, step = 1024)
            assertFailsWith<Timeout> {
                activity.within(1_000, { Timeout() }) {
                    val buf = ByteArray(1024)
                    repeat(3) {
                        body.readAvailable(buf, 0, buf.size)
                        delay(100)
                    }
                    awaitCancellation()
                }
            }
            assertEquals(200L + 1_000L, currentTime)
        }

    /** An application that stops writing its body times out 1 s after its last write. */
    @Test fun negative_stalledApplicationTimesOut() =
        runTest(timeout = 20.seconds) {
            val activity = Activity()
            val app = ByteChannel()
            backgroundScope.launch {
                repeat(2) {
                    app.writeFully(ByteArray(1024))
                    app.flush()
                    delay(100)
                }
                awaitCancellation()
            }
            val body = ConsumedBody(app, activity, step = 1024)
            assertFailsWith<Timeout> { activity.within(1_000, { Timeout() }) { send(body, every = 0) } }
            assertEquals(100L + 1_000L, currentTime)
        }

    /** The caller's own cancellation is not a timeout. */
    @Test fun callerCancellationIsNotATimeout() =
        runTest(timeout = 20.seconds) {
            val activity = Activity()
            val job = launch { activity.within(1_000, { Timeout() }) { awaitCancellation() } }
            delay(500)
            job.cancel()
            job.join()
            assertEquals(true, job.isCancelled)
            assertEquals(500L, currentTime)
        }

    /**
     * A block that returns at the deadline, after the timer fired but before the watchdog ran, keeps its result: the
     * expiry is not reported, and [Activity.within]'s `onExpiry` (which closes the connection) does not run.
     */
    @Test fun blockReturningAsTheTimerFiresKeepsItsResult() =
        runTest(timeout = 20.seconds) {
            val activity = Activity()
            var expiries = 0
            val result =
                activity.within(1_000, { Timeout() }, onExpiry = { expiries++ }) {
                    yield() // the watchdog arms its timer first, so it fires first at 1 s
                    delay(1_000)
                    "done"
                }
            assertEquals("done", result)
            assertEquals(0, expiries)
            assertEquals(1_000L, currentTime)
        }
}
