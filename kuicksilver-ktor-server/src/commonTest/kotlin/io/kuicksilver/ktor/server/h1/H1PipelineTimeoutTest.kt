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
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.io.readString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The request-head deadline and the idle timeout of the HTTP/1.1 pipeline, on in-memory channels under virtual time. A
 * connection whose client stays silent or trickles a head must not be held open forever (slowloris).
 */
class H1PipelineTimeoutTest {
    private val idle = 45.seconds
    private val header = 30.seconds

    /** The pipeline of one in-memory connection: the client writes to [toServer] and reads [fromServer]. */
    private class Conn(
        val toServer: ByteChannel,
        val fromServer: ByteChannel,
        val job: Job,
    ) {
        /** What the server sent; call once the pipeline has ended (the writer closes [fromServer]). */
        suspend fun received(): String = fromServer.readRemaining().readString()
    }

    private fun TestScope.pipeline(
        headerTimeout: Duration = header,
        idleTimeout: Duration = idle,
        handler: suspend H1RequestScope.(Request) -> Unit = { respondOk(it) },
    ): Conn {
        val toServer = ByteChannel()
        val fromServer = ByteChannel()
        val job =
            backgroundScope.startH1Pipeline(H1Connection(toServer, fromServer, null, null), idleTimeout, headerTimeout, handler = handler)
        runCurrent()
        return Conn(toServer, fromServer, job)
    }

    /** A client that connects and sends nothing is closed at the header deadline, without a response. */
    @Test fun negative_silentClientIsClosedAtTheHeaderDeadline() =
        runTest {
            val c = pipeline()
            advanceTimeBy(header - 1.milliseconds)
            assertTrue(c.job.isActive, "closed before the deadline")
            advanceTimeBy(2.milliseconds)
            assertTrue(c.job.isCompleted, "a silent client still holds the connection after ${header + 1.milliseconds}")
            assertEquals("", c.received(), "nothing of a request arrived: no response")
        }

    /**
     * A client that sends one byte of the head every 10 s (more often than the 45 s idle timeout) gets 408 and the
     * connection closes at the header deadline: trickling does not extend it.
     */
    @Test fun negative_tricklingHeadGets408AtTheHeaderDeadline() =
        runTest {
            val c = pipeline()
            backgroundScope.trickle(c.toServer, "GET / HTTP/1.1\r\nHost: s\r\nX-Slow: " + "a".repeat(100), every = 10.seconds)
            advanceTimeBy(header - 1.milliseconds)
            assertTrue(c.job.isActive, "closed before the deadline")
            advanceTimeBy(2.milliseconds)
            assertTrue(c.job.isCompleted, "a trickling client still holds the connection after ${header + 1.milliseconds}")
            val response = c.received()
            assertTrue(response.startsWith("HTTP/1.1 408 Request Timeout\r\n"), response)
            assertTrue(response.contains("\r\nConnection: close\r\n"), response)
        }

    /** On a keep-alive connection the deadline of the next head starts when the previous response has been written. */
    @Test fun negative_idleKeepAliveConnectionClosesSilentlyAfterTheHeaderDeadline() =
        runTest {
            val handled = CompletableDeferred<Unit>()
            val c =
                pipeline { request ->
                    handled.await()
                    respondOk(request)
                }
            c.toServer.writeStringUtf8("GET / HTTP/1.1\r\nHost: s\r\n\r\n")
            c.toServer.flush()
            // the handler runs 60 s: no deadline while the client waits for its response
            advanceTimeBy(60.seconds)
            assertTrue(c.job.isActive, "closed while a response was pending")
            handled.complete(Unit)
            runCurrent()
            advanceTimeBy(header - 1.milliseconds)
            assertTrue(c.job.isActive, "the deadline did not start at the end of the response")
            advanceTimeBy(2.milliseconds)
            assertTrue(c.job.isCompleted, "an idle keep-alive connection is still open")
            assertEquals(OK, c.received(), "an idle keep-alive connection closes without a 408")
        }

    /** A pipelined head the client left unfinished behind a slow request gets 408 at the deadline after that response. */
    @Test fun negative_partialPipelinedHeadGets408AfterThePreviousResponse() =
        runTest {
            val handled = CompletableDeferred<Unit>()
            val c =
                pipeline { request ->
                    handled.await()
                    respondOk(request)
                }
            c.toServer.writeStringUtf8("GET / HTTP/1.1\r\nHost: s\r\n\r\nGET /next HTTP/1.1\r\nHo")
            c.toServer.flush()
            advanceTimeBy(60.seconds)
            assertTrue(c.job.isActive, "closed while a response was pending")
            handled.complete(Unit)
            runCurrent()
            advanceTimeBy(header - 1.milliseconds)
            assertTrue(c.job.isActive, "closed before the deadline that starts at the end of the first response")
            advanceTimeBy(2.milliseconds)
            assertTrue(c.job.isCompleted, "an unfinished pipelined head still holds the connection")
            val response = c.received()
            assertTrue(response.startsWith(OK + "HTTP/1.1 408 Request Timeout\r\n"), response)
        }

    /** A complete request within the deadline is served and the connection stays open for the next one. */
    @Test fun headWithinTheDeadlineIsServed() =
        runTest {
            val c = pipeline()
            advanceTimeBy(header - 1.seconds)
            c.toServer.writeStringUtf8("GET / HTTP/1.1\r\nHost: s\r\n\r\n")
            c.toServer.flush()
            runCurrent()
            assertTrue(c.job.isActive)
            // the next head has its own full deadline from the end of this response
            advanceTimeBy(header - 1.milliseconds)
            assertTrue(c.job.isActive)
            c.toServer.writeStringUtf8("GET / HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n")
            c.toServer.flush()
            advanceTimeBy(1.milliseconds)
            assertTrue(c.job.isCompleted, "Connection: close was not honoured")
            assertEquals(OK + OK, c.received())
        }

    /**
     * The idle timeout closes the whole connection, not only its output: with no header deadline in the way (a long
     * one), a silent connection ends after [idle]. Before, the writer closed its side and the reader waited forever.
     */
    @Test fun negative_idleTimeoutClosesTheWholeConnection() =
        runTest {
            val c = pipeline(headerTimeout = idle * 10)
            advanceTimeBy(idle - 1.milliseconds)
            assertTrue(c.job.isActive)
            advanceTimeBy(2.milliseconds)
            assertFalse(c.job.isActive, "the connection is still read after the idle timeout")
        }

    private fun CoroutineScope.trickle(
        to: ByteChannel,
        text: String,
        every: Duration,
    ) = launch {
        for (ch in text) {
            to.writeStringUtf8(ch.toString())
            to.flush()
            delay(every)
        }
    }

    private companion object {
        const val OK = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

        @OptIn(InternalAPI::class)
        suspend fun H1RequestScope.respondOk(request: Request) {
            request.release()
            output.writeStringUtf8(OK)
            output.flush()
        }
    }
}
