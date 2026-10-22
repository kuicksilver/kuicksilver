// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

import io.ktor.http.cio.Request
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.Job
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A response whose handler failed before the writer reached it (it waited behind an earlier pipelined response) ends the
 * connection with its failure. The writer copied responses with a loop on `isClosedForRead`, which a channel failed
 * with a cause also answers: the failed response wrote nothing and the writer went on to the next one, so the client
 * took the third request's response for the second's ([a, c] before). In-memory channels, virtual time.
 */
class H1PipelineFailedResponseTest {
    private fun TestScope.pipeline(handler: suspend H1RequestScope.(Request) -> Unit): Pair<ByteChannel, ByteChannel> {
        val toServer = ByteChannel()
        val fromServer = ByteChannel()
        backgroundScope.startH1Pipeline(H1Connection(toServer, fromServer, null, null), 45.seconds, 30.seconds, handler = handler)
        runCurrent()
        return toServer to fromServer
    }

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
            val responses = Regex("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n(.)").findAll(seen).map { it.groupValues[1] }.toList()
            // /a's response may be cut by the reset that ends the connection; /c's must never stand in for /b's
            assertTrue(responses == listOf("a") || responses.isEmpty(), "the client got these bodies for /a, /b and /c: $responses")
            assertTrue(failed, "the connection ended cleanly after a failed response")
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
