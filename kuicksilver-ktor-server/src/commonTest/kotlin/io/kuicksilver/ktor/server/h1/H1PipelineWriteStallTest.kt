// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

import io.ktor.http.cio.Request
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.Job
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * Send-side slowloris: a client that asks for a large response and never reads it. The response writer then waits for
 * the socket for ever and holds the connection and its handler; it must give up after [stall] without progress, and only
 * without progress: a client that reads slowly keeps its response. The engine sees progress about 1 MiB at a time (the
 * `ByteChannel` in front of the socket), so the stall deadline is 5 minutes, not the 45 s idle timeout: 1 MiB per
 * 5 minutes is a floor of about 3.4 KiB/s. In-memory channels, virtual time; the client's side of the output is a
 * [ByteChannel] that takes no more once about 2 MiB wait in it.
 */
class H1PipelineWriteStallTest {
    private val idle = 45.seconds
    private val stall = 5.minutes

    private class Conn(
        val toServer: ByteChannel,
        val fromServer: ByteChannel,
        val job: Job,
    ) {
        /** Why the pipeline ended; null while it runs or when it ended normally. */
        var cause: Throwable? = null
    }

    private fun TestScope.pipeline(handler: suspend H1RequestScope.(Request) -> Unit): Conn {
        val toServer = ByteChannel()
        val fromServer = ByteChannel()
        val job = backgroundScope.startH1Pipeline(H1Connection(toServer, fromServer, null, null), idle, 30.seconds, handler = handler)
        runCurrent()
        return Conn(toServer, fromServer, job).also { c -> job.invokeOnCompletion { c.cause = it } }
    }

    private suspend fun Conn.send(text: String) {
        toServer.writeStringUtf8(text)
        toServer.flush()
    }

    /** A client that never reads a 16 MiB response is closed once the writer made no progress for 5 minutes. */
    @Test fun negative_clientThatStopsReadingIsClosed() =
        runTest {
            val handlerDone = Job()
            val c =
                pipeline { request ->
                    try {
                        respondLarge(request, 16 * MIB)
                    } finally {
                        handlerDone.complete()
                    }
                }
            c.send("GET /large HTTP/1.1\r\nHost: s\r\n\r\n")
            advanceTimeBy(stall - 1.milliseconds)
            assertTrue(c.job.isActive, "closed before the stall deadline")
            advanceTimeBy(2.milliseconds)
            assertTrue(c.job.isCompleted, "a client that does not read holds the connection after ${stall + 1.milliseconds}")
            assertTrue(handlerDone.isCompleted, "the handler is still blocked on the response")
            val cause = c.cause?.message.orEmpty()
            assertTrue(cause.contains("stopped reading"), "the cause names the stall, not the idle timeout: $cause")
        }

    /** The same over an upgraded connection (WebSocket), whose output goes through the same writer. */
    @Test fun negative_upgradedClientThatStopsReadingIsClosed() =
        runTest {
            val c =
                pipeline { request ->
                    request.release()
                    output.writeStringUtf8("HTTP/1.1 101 Switching Protocols\r\nUpgrade: test\r\nConnection: Upgrade\r\n\r\n")
                    output.flush()
                    upgraded!!.complete(true)
                    val chunk = ByteArray(64 * 1024)
                    while (true) {
                        output.writeFully(chunk)
                        output.flush()
                    }
                }
            c.send("GET /ws HTTP/1.1\r\nHost: s\r\nUpgrade: test\r\nConnection: Upgrade\r\n\r\n")
            advanceTimeBy(stall - 1.milliseconds)
            assertTrue(c.job.isActive, "closed before the stall deadline")
            advanceTimeBy(2.milliseconds)
            assertTrue(c.job.isCompleted, "an upgraded client that does not read holds the connection")
        }

    /**
     * The deadline is on progress, not on the whole response, and low enough for slow links: a client that reads 8 KiB a
     * second (EDGE, a throttled plan) downloads 6 MiB over 13 minutes without being cut. With the stall deadline at the
     * 45 s idle timeout it was cut after its first megabyte.
     */
    @Test fun slowReaderAt8KiBPerSecondKeepsItsResponse() =
        runTest {
            val size = 6 * MIB
            val total = head(size).length + size
            val c = pipeline { request -> respondLarge(request, size) }
            c.send("GET /large HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n")
            val buffer = ByteArray(8 * 1024)
            var received = 0L
            while (received < total) {
                advanceTimeBy(1.seconds)
                // a cut closes the client's side with the cause (or ends it early); the pipeline itself may end before
                // the client has read the last buffered megabyte
                assertNull(c.cause, "a client reading 8 KiB/s was cut after ${received / 1024} KiB")
                val n = c.fromServer.readAvailable(buffer, 0, buffer.size)
                assertTrue(n > 0, "the response ended early at $received of $total bytes")
                received += n
            }
            runCurrent()
            assertTrue(c.job.isCompleted)
            assertEquals(-1, c.fromServer.readAvailable(buffer, 0, buffer.size))
        }

    private companion object {
        const val MIB = 1024L * 1024

        fun head(length: Long) = "HTTP/1.1 200 OK\r\nContent-Length: $length\r\n\r\n"

        @OptIn(InternalAPI::class)
        suspend fun H1RequestScope.respondLarge(
            request: Request,
            size: Long,
        ) {
            request.release()
            output.writeStringUtf8(head(size))
            val chunk = ByteArray(64 * 1024)
            var left = size
            while (left > 0) {
                val n = minOf(left, chunk.size.toLong()).toInt()
                output.writeFully(chunk, 0, n)
                output.flush()
                left -= n
            }
        }
    }
}
