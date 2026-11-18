// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.server.h1

import io.ktor.http.cio.Request
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.io.IOException
import kotlinx.io.Source
import kotlinx.io.readString
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.hours

/**
 * The two races of the HTTP/1.1 pipeline between work it started and an event from outside, each outcome forced through
 * a hook inside the started work: the wait for the first byte of a request head against the server's stop
 * ([requestStartForTest]), and the read of a request body against the handler's end ([bodyReadForTest]). In each test the
 * side that is not to win cannot: its hook never returns, or the other side's event comes only once the race is decided.
 * In-memory channels under virtual time.
 */
class H1PipelineSelectRaceTest {
    @AfterTest fun reset() {
        requestStartForTest = null
        bodyReadForTest = null
    }

    private class Conn(
        val toServer: ByteChannel,
        val fromServer: ByteChannel,
        val job: Job,
    )

    /** The paths of the requests whose handlers ran, in order. */
    private val handled = mutableListOf<String>()

    private fun TestScope.pipeline(
        draining: Job?,
        input: (ByteChannel) -> ByteReadChannel = { it },
        handler: suspend H1RequestScope.(Request) -> Unit,
    ): Conn {
        val toServer = ByteChannel()
        val fromServer = ByteChannel()
        val connection = H1Connection(input(toServer), fromServer, null, null)
        val job =
            backgroundScope.startH1Pipeline(connection, 1.hours, 1.hours, draining = draining) {
                handled += it.uri.toString()
                handler(it)
            }
        runCurrent()
        return Conn(toServer, fromServer, job)
    }

    private suspend fun H1RequestScope.respond(body: String) {
        output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n$body")
        output.flush()
    }

    private suspend fun Conn.send(text: String) {
        toServer.writeStringUtf8(text)
        toServer.flush()
    }

    /**
     * The stop wins the race against a head that already arrived (the wait for it never returns here): the request is still
     * read and answered, as the pipeline's contract says of a head that has started to arrive, and the connection ends
     * after it. Before, the stop's side returned "no request" and the connection closed over the unread head, without an
     * answer.
     */
    @Test fun negative_aHeadThatArrivedAsTheServerStoppedIsAnswered() =
        runTest {
            val draining = Job()
            val arrived = CompletableDeferred<Unit>()
            val c = pipeline(draining) { respond("late") }
            requestStartForTest = {
                if (it === c.toServer) {
                    arrived.complete(Unit)
                    awaitCancellation()
                }
            }
            c.send("GET /late HTTP/1.1\r\nHost: s\r\n\r\n")
            runCurrent()
            assertTrue(arrived.isCompleted, "the head never reached the wait for it")
            draining.complete()
            runCurrent()
            assertTrue(c.job.isCompleted, "the connection stayed open after the stop")
            val got = c.fromServer.readBuffer().readString()
            assertTrue(got.endsWith("late"), "the request whose head had arrived was not answered: '$got'")
            assertEquals(listOf("/late"), handled)
        }

    /**
     * The socket's input as a socket that is slow to hand over: its wait for bytes never returns, while the bytes that came
     * sit in its buffer, as when the stop cancels a wait whose bytes arrived but whose resumption had not run yet.
     */
    @OptIn(InternalAPI::class)
    private class NeverWakes(
        private val inner: ByteChannel,
    ) : ByteReadChannel {
        override val closedCause: Throwable? get() = inner.closedCause
        override val isClosedForRead: Boolean get() = inner.isClosedForRead
        override val readBuffer: Source get() = inner.readBuffer

        override suspend fun awaitContent(min: Int): Boolean = awaitCancellation()

        override fun cancel(cause: Throwable?) = inner.cancel(cause)
    }

    /**
     * The path the stop's side takes in production: the wait for the head is cancelled while it waits in the socket's own
     * awaitContent, with the head's bytes already in the socket's buffer (not yet moved into the pipeline's). The request is
     * read from there and answered. A recheck of the pipeline's buffer alone missed them and closed without an answer.
     */
    @Test fun negative_aHeadInTheSocketsBufferAsTheServerStoppedIsAnswered() =
        runTest {
            val draining = Job()
            val c = pipeline(draining, input = { NeverWakes(it) }) { respond("buffered") }
            c.send("GET /buffered HTTP/1.1\r\nHost: s\r\n\r\n")
            runCurrent()
            assertEquals(emptyList(), handled, "the wait handed the head over")
            draining.complete()
            runCurrent()
            assertTrue(c.job.isCompleted, "the connection stayed open after the stop")
            val got = c.fromServer.readBuffer().readString()
            assertTrue(got.endsWith("buffered"), "the request in the socket's buffer was not answered: '$got'")
            assertEquals(listOf("/buffered"), handled)
        }

    /** The client closed its side as the server stopped (an end, nothing to read): the connection ends, unanswered. */
    @Test fun aClientThatClosedAsTheServerStoppedEndsTheConnection() =
        runTest {
            val draining = Job()
            val reached = CompletableDeferred<Unit>()
            val c = pipeline(draining) { respond("never") }
            requestStartForTest = {
                if (it === c.toServer) {
                    reached.complete(Unit)
                    awaitCancellation() // the stop is the only side that can win
                }
            }
            c.toServer.flushAndClose()
            runCurrent()
            assertTrue(reached.isCompleted, "the wait never saw the end of the input")
            draining.complete()
            runCurrent()
            assertTrue(c.job.isCompleted, "the connection stayed open after the stop")
            assertEquals(emptyList(), handled, "a request was read from an input that ended")
        }

    /**
     * The client's side failed while the wait was in the socket's awaitContent (which never hands back here) and the server
     * stopped: the stop's side sees the failure, and the connection ends without a request read from it.
     */
    @Test fun aClientThatFailedAsTheServerStoppedEndsTheConnection() =
        runTest {
            val draining = Job()
            val c = pipeline(draining, input = { NeverWakes(it) }) { respond("never") }
            c.toServer.cancel(IOException("reset by the peer"))
            runCurrent()
            draining.complete()
            runCurrent()
            assertTrue(c.job.isCompleted, "the connection stayed open after the stop")
            assertEquals(emptyList(), handled, "a request was read from an input that failed")
        }

    /**
     * The head wins the race (the stop comes only once its request is being served): the request is answered on the
     * keep-alive connection, and the stop then ends the connection without waiting for another head.
     */
    @Test fun aHeadThatWonTheRaceIsAnsweredAndTheStopClosesTheConnection() =
        runTest {
            val draining = Job()
            val arrived = CompletableDeferred<Unit>()
            val c = pipeline(draining) { respond("first") }
            requestStartForTest = { if (it === c.toServer) arrived.complete(Unit) }
            c.send("GET /first HTTP/1.1\r\nHost: s\r\n\r\n")
            runCurrent()
            assertTrue(arrived.isCompleted, "the head never reached the wait for it")
            assertEquals(listOf("/first"), handled)
            assertTrue(c.job.isActive, "a keep-alive connection closed before the stop")
            draining.complete()
            runCurrent()
            assertTrue(c.job.isCompleted, "the idle connection stayed open after the stop")
            assertTrue(
                c.fromServer
                    .readBuffer()
                    .readString()
                    .endsWith("first"),
            )
        }

    /**
     * The handler's end wins the race against the read of a body that is complete (the read's outcome is held until the
     * handler ended): the pipeline settles the body as read, and the connection carries the next request. A complete body
     * is never abandoned, whichever side the race picked.
     */
    @Test fun aBodyReadWhenTheHandlerEndedKeepsTheConnection() =
        runTest {
            val held = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val c =
                pipeline(null) {
                    respond(input.readBuffer().readString())
                }
            bodyReadForTest = {
                if (it === c.toServer) {
                    held.complete(Unit)
                    release.await()
                }
            }
            c.send("POST /a HTTP/1.1\r\nHost: s\r\nContent-Length: 5\r\n\r\nhello" + "GET /b HTTP/1.1\r\nHost: s\r\n\r\n")
            runCurrent()
            assertTrue(held.isCompleted, "the body's read never ended")
            // the handler of /a ended while the read's outcome was held: the next request waits for the body's settlement
            assertEquals(listOf("/a"), handled)
            release.complete(Unit)
            runCurrent()
            assertEquals(listOf("/a", "/b"), handled)
            assertTrue(c.job.isActive, "the connection ended after a complete body")
        }

    /**
     * The read of the body wins the race (the handler cannot end before the read's outcome was taken): the connection
     * carries the next request, as when the handler's end wins.
     */
    @Test fun aBodyReadBeforeTheHandlerEndedKeepsTheConnection() =
        runTest {
            val read = CompletableDeferred<Unit>()
            val gate = CompletableDeferred<Unit>()
            val c =
                pipeline(null) {
                    val body = input.readBuffer().readString()
                    gate.await()
                    respond(body)
                }
            bodyReadForTest = { if (it === c.toServer) read.complete(Unit) }
            c.send("POST /a HTTP/1.1\r\nHost: s\r\nContent-Length: 5\r\n\r\nhello" + "GET /b HTTP/1.1\r\nHost: s\r\n\r\n")
            runCurrent()
            assertTrue(read.isCompleted, "the body's read never ended")
            assertEquals(listOf("/a"), handled)
            gate.complete(Unit)
            runCurrent()
            assertEquals(listOf("/a", "/b"), handled)
            assertTrue(c.job.isActive, "the connection ended after a complete body")
        }
}
