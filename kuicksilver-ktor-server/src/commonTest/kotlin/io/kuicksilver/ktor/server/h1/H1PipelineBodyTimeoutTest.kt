// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

import io.ktor.http.cio.Request
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.readRemaining
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.io.readString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * The inactivity deadline of a request body (slow POST, R.U.D.Y.): a client that stops sending the body it announced
 * must not hold its handler for ever. No byte for the idle timeout fails the handler's read of the body; a body that
 * keeps moving, however slowly, is read in full. In-memory channels, virtual time.
 */
class H1PipelineBodyTimeoutTest {
    private val idle = 45.seconds

    private class Conn(
        val toServer: ByteChannel,
        val job: Job,
    )

    /** What the handler saw: the body it read, or the failure of the read, and when. */
    private class Seen {
        var body: String? = null
        var failure: Throwable? = null
        var at: Long = -1
    }

    private fun TestScope.pipeline(handler: suspend H1RequestScope.(Request) -> Unit): Conn {
        val toServer = ByteChannel()
        val fromServer = ByteChannel()
        val job = backgroundScope.startH1Pipeline(H1Connection(toServer, fromServer, null, null), idle, 30.seconds, handler = handler)
        backgroundScope.launch { runCatching { fromServer.readRemaining() } } // a client that reads its responses
        runCurrent()
        return Conn(toServer, job)
    }

    private fun TestScope.readingBody(seen: Seen): suspend H1RequestScope.(Request) -> Unit =
        { request ->
            request.release()
            try {
                seen.body = input.readRemaining().readString()
            } catch (e: Throwable) {
                seen.failure = e
            }
            seen.at = currentTime
            respondOk()
        }

    private suspend fun Conn.send(text: String) {
        toServer.writeStringUtf8(text)
        toServer.flush()
    }

    /** Part of a Content-Length body, then silence: the read fails at the idle timeout, not before. */
    @Test fun negative_contentLengthBodyThatStopsFailsAtTheIdleTimeout() =
        runTest {
            val seen = Seen()
            val c = pipeline(readingBody(seen))
            c.send("POST / HTTP/1.1\r\nHost: s\r\nContent-Length: 10\r\n\r\nabcd")
            advanceTimeBy(idle - 1.milliseconds)
            assertEquals(-1L, seen.at, "the body read ended before the deadline")
            advanceTimeBy(2.milliseconds)
            assertNotNull(seen.failure, "a body that stopped still holds its handler after ${idle + 1.milliseconds}")
            assertTrue(isBodyTimeout(seen.failure), "not the body deadline: ${seen.failure}")
            runCurrent()
            assertTrue(c.job.isCompleted, "the connection is kept after a body timeout")
        }

    /** The same for a chunked body that stops between chunks. */
    @Test fun negative_chunkedBodyThatStopsFailsAtTheIdleTimeout() =
        runTest {
            val seen = Seen()
            val c = pipeline(readingBody(seen))
            c.send("POST / HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n")
            advanceTimeBy(idle + 1.milliseconds)
            assertTrue(isBodyTimeout(seen.failure), "a chunked body that stopped still holds its handler: ${seen.failure}")
        }

    /** Inactivity, not total time: a byte every 30 s (inside the 45 s) for 5 minutes, and the body is read in full. */
    @Test fun slowButMovingBodyIsReadInFull() =
        runTest {
            val seen = Seen()
            val body = "0123456789"
            val c = pipeline(readingBody(seen))
            c.send("POST / HTTP/1.1\r\nHost: s\r\nContent-Length: ${body.length}\r\n\r\n")
            backgroundScope.trickle(c.toServer, body, every = 30.seconds)
            advanceTimeBy(6.minutes)
            assertNull(seen.failure)
            assertEquals(body, seen.body)
        }

    /**
     * `Expect: 100-continue`: the client sends the body only after `100 Continue`, which goes out when the handler starts
     * to read it, so the deadline starts then; a handler that takes a minute before reading does not time the client out.
     */
    @Test fun expectContinueDeadlineStartsWhenContinueIsSent() =
        runTest {
            val seen = Seen()
            val ready = CompletableDeferred<Unit>()
            val c =
                pipeline { request ->
                    ready.await()
                    output.writeStringUtf8("HTTP/1.1 100 Continue\r\n\r\n")
                    output.flush()
                    continueSent?.complete()
                    readingBody(seen)(request)
                }
            c.send("POST / HTTP/1.1\r\nHost: s\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n")
            advanceTimeBy(60.seconds)
            assertEquals(-1L, seen.at, "the body deadline ran before 100 Continue")
            ready.complete(Unit)
            runCurrent()
            val sentAt = currentTime
            advanceTimeBy(idle + 1.milliseconds)
            assertTrue(isBodyTimeout(seen.failure), "no deadline after 100 Continue: ${seen.failure}")
            assertTrue(seen.at - sentAt in idle.inWholeMilliseconds..idle.inWholeMilliseconds + 1)
        }

    /**
     * `Expect: 100-continue` to a handler that answers without reading the body (a 401, a 413): the client may never
     * send it; the body deadline then starts when the handler is done (and the idle timeout would end it too), so the
     * connection does not wait for ever.
     */
    @Test fun expectContinueWithoutAReadStillEnds() =
        runTest {
            val c = pipeline { request -> respondOk(request) }
            c.send("POST / HTTP/1.1\r\nHost: s\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n")
            advanceTimeBy(idle + 1.seconds)
            assertTrue(c.job.isCompleted, "a client that never sends the body holds the connection")
        }

    /** An upgraded connection has no body deadline: its bytes are the protocol's, quiet as long as it likes. */
    @Test fun upgradedConnectionHasNoBodyDeadline() =
        runTest {
            val c =
                pipeline { request ->
                    request.release()
                    output.writeStringUtf8("HTTP/1.1 101 Switching Protocols\r\nUpgrade: test\r\nConnection: Upgrade\r\n\r\n")
                    output.flush()
                    upgraded!!.complete(true)
                    input.readRemaining() // until the client closes
                }
            c.send("GET /ws HTTP/1.1\r\nHost: s\r\nUpgrade: test\r\nConnection: Upgrade\r\n\r\nhi")
            advanceTimeBy(10.minutes)
            assertTrue(c.job.isActive, "an upgraded connection was closed while quiet")
        }

    private fun CoroutineScope.trickle(
        to: ByteChannel,
        text: String,
        every: Duration,
    ) = launch {
        for (ch in text) {
            delay(every)
            to.writeStringUtf8(ch.toString())
            to.flush()
        }
    }

    private companion object {
        const val OK = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

        fun isBodyTimeout(e: Throwable?): Boolean = generateSequence(e) { it.cause }.any { it is RequestBodyTimeout }

        suspend fun H1RequestScope.respondOk() {
            output.writeStringUtf8(OK)
            output.flush()
        }

        @OptIn(InternalAPI::class)
        suspend fun H1RequestScope.respondOk(request: Request) {
            request.release()
            respondOk()
        }
    }
}
