// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.server.h1

import io.ktor.http.cio.Request
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A response whose handler failed before the writer reached it (it waited behind an earlier pipelined response) ends the
 * connection. The writer copied responses with a loop on `isClosedForRead`, which a channel failed with a cause also
 * answers: the failed response wrote nothing and the writer went on to the next one, so the client took the third
 * request's response for the second's ([a, c] before). In-memory channels, virtual time.
 */
class H1PipelineFailedResponseTest {
    private fun TestScope.pipeline(handler: suspend H1RequestScope.(Request) -> Unit): Pair<ByteChannel, ByteChannel> {
        val toServer = ByteChannel()
        val fromServer = ByteChannel()
        backgroundScope.startH1Pipeline(H1Connection(toServer, fromServer, null, null), 45.seconds, 30.seconds, handler = handler)
        runCurrent()
        return toServer to fromServer
    }

    /**
     * The failed response wrote nothing, so the connection ends cleanly (KTOR-10037, as upstream Ktor since 516fe19e4): the
     * response before it arrives whole, then the end of the stream, not a failure that could take it with it (RFC 9112
     * section 9.6: close in stages); the one after it is never sent, so it cannot stand in for the failed one.
     */
    @Test fun negative_aFailedPipelinedResponseIsNotSkipped() =
        runTest {
            val firstMayAnswer = Job()
            val (toServer, fromServer) =
                pipeline { request ->
                    val path = request.uri.toString()
                    request.release()
                    when (path) {
                        "/a" -> {
                            firstMayAnswer.join()
                            output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na")
                        }

                        "/b" -> {
                            output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
                            throw IOException("the handler failed")
                        }

                        else -> {
                            output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nc")
                        }
                    }
                    output.flush()
                }
            toServer.writeStringUtf8(
                "GET /a HTTP/1.1\r\nHost: s\r\n\r\nGET /b HTTP/1.1\r\nHost: s\r\n\r\nGET /c HTTP/1.1\r\nHost: s\r\n\r\n",
            )
            toServer.flush()
            runCurrent() // /b failed and /c answered while /a waits
            firstMayAnswer.complete()
            val (seen, failed) = fromServer.readToEnd()
            assertEquals("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na", seen, "what the client got for /a, /b and /c")
            assertFalse(failed, "the connection ended with a failure, not cleanly, after a response that wrote nothing")
        }

    /** The same with nothing pipelined behind the failed response, the client still connected: the output still ends cleanly. */
    @Test fun aFailedLastResponseEndsTheConnectionCleanly() =
        runTest {
            val (toServer, fromServer) =
                pipeline { request ->
                    val path = request.uri.toString()
                    request.release()
                    if (path == "/b") throw IOException("the handler failed")
                    output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na")
                    output.flush()
                }
            toServer.writeStringUtf8("GET /a HTTP/1.1\r\nHost: s\r\n\r\nGET /b HTTP/1.1\r\nHost: s\r\n\r\n")
            toServer.flush()
            val (seen, failed) = fromServer.readToEnd()
            assertEquals("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na", seen)
            assertFalse(failed, "the connection ended with a failure after a response that wrote nothing")
        }

    /**
     * A response that failed after part of it went out cannot be ended cleanly: the client would take what it got for the
     * whole response (a close-delimited or chunked one). The connection ends with the failure, as before KTOR-10037.
     */
    @Test fun negative_aResponseCutAfterItsFirstBytesEndsTheConnectionWithItsFailure() =
        runTest {
            val cut = Job()
            val (toServer, fromServer) =
                pipeline { request ->
                    request.release()
                    output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab")
                    output.flush()
                    cut.join()
                    throw IOException("the handler failed")
                }
            toServer.writeStringUtf8("GET /a HTTP/1.1\r\nHost: s\r\n\r\n")
            toServer.flush()
            runCurrent() // the head and "ab" are out
            cut.complete()
            val (_, failed) = fromServer.readToEnd()
            assertTrue(failed, "a response cut after its first bytes ended the connection cleanly")
        }

    /**
     * Each connection's pipeline leaves nothing on the listener-wide draining job once it ended (review M1): the completion
     * handler it registered is disposed, so connections do not pile up on a long-lived listener.
     */
    @Test fun aFinishedPipelineLeavesNoHandlerOnDraining() =
        runTest {
            val draining = CountingJob(Job())
            repeat(50) {
                val toServer = ByteChannel()
                val fromServer = ByteChannel()
                val job =
                    backgroundScope.startH1Pipeline(
                        H1Connection(toServer, fromServer, null, null),
                        45.seconds,
                        30.seconds,
                        draining = draining,
                    ) {
                        it.release()
                        output.writeStringUtf8("HTTP/1.1 204 No Content\r\n\r\n")
                        output.flush()
                    }
                toServer.writeStringUtf8("GET / HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n")
                toServer.flushAndClose()
                fromServer.readToEnd()
                job.join()
            }
            assertEquals(0, draining.live, "completion handlers left on the draining job")
        }

    /** [delegate], counting the completion handlers registered on it and not disposed yet. */
    @OptIn(kotlinx.coroutines.InternalCoroutinesApi::class)
    private class CountingJob(
        private val delegate: kotlinx.coroutines.CompletableJob,
    ) : kotlinx.coroutines.CompletableJob by delegate {
        @kotlin.concurrent.Volatile var live = 0

        override fun invokeOnCompletion(handler: kotlinx.coroutines.CompletionHandler): kotlinx.coroutines.DisposableHandle =
            counted(delegate.invokeOnCompletion(handler))

        override fun invokeOnCompletion(
            onCancelling: Boolean,
            invokeImmediately: Boolean,
            handler: kotlinx.coroutines.CompletionHandler,
        ): kotlinx.coroutines.DisposableHandle = counted(delegate.invokeOnCompletion(onCancelling, invokeImmediately, handler))

        private fun counted(h: kotlinx.coroutines.DisposableHandle): kotlinx.coroutines.DisposableHandle {
            live++
            var disposed = false
            return kotlinx.coroutines.DisposableHandle {
                if (!disposed) {
                    disposed = true
                    live--
                }
                h.dispose()
            }
        }
    }

    /**
     * An upgraded connection (a WebSocket) whose client side fails (a reset) fails the handler's input, which the engine
     * copies from the connection with ktor's `copyAndClose`: that copy rethrows a cause after its loop, so the input is
     * not closed as if the client had ended it. The control for the class of bug above, on the upgraded path.
     */
    @Test fun aResetUnderAnUpgradedConnectionFailsTheHandlersInput() =
        runTest {
            val ended = CompletableDeferred<String>()
            val (toServer, _) =
                pipeline { request ->
                    request.release()
                    output.writeStringUtf8("HTTP/1.1 101 Switching Protocols\r\nUpgrade: test\r\nConnection: Upgrade\r\n\r\n")
                    output.flush()
                    upgraded!!.complete(true)
                    val outcome =
                        try {
                            val buf = ByteArray(4096)
                            while (true) {
                                val n = input.readAvailable(buf, 0, buf.size)
                                if (n < 0) break
                            }
                            input.closedCause?.let { "a failure: ${it.message}" } ?: "a clean end"
                        } catch (e: Exception) {
                            "a failure: ${e.message}"
                        }
                    ended.complete(outcome)
                }
            toServer.writeStringUtf8("GET /ws HTTP/1.1\r\nHost: s\r\nUpgrade: test\r\nConnection: Upgrade\r\n\r\nsome bytes")
            toServer.flush()
            runCurrent()
            toServer.cancel(IOException("connection reset"))
            val outcome = ended.await()
            assertTrue(outcome.startsWith("a failure"), "the handler of an upgraded connection that was reset saw $outcome")
        }

    /** What the client got before the connection ended, and whether it ended with a failure. */
    private suspend fun ByteReadChannel.readToEnd(): Pair<String, Boolean> {
        val out = StringBuilder()
        val buf = ByteArray(4096)
        while (true) {
            val n =
                try {
                    readAvailable(buf, 0, buf.size)
                } catch (_: Exception) {
                    return out.toString() to true
                }
            if (n < 0) return out.toString() to (closedCause != null)
            out.append(buf.decodeToString(0, n))
        }
    }
}
