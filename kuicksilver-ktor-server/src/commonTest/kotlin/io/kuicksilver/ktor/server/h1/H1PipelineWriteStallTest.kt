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
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Send-side slowloris: a client that asks for a large response and never reads it. The response writer then waits for
 * the socket for ever and holds the connection and its handler; it must give up after the idle timeout without progress,
 * and only without progress: a client that reads slowly keeps its response. In-memory channels, virtual time; the
 * client's side of the output is a [ByteChannel] that takes no more once about 2 MiB wait in it.
 */
class H1PipelineWriteStallTest {
    private val idle = 45.seconds

    private class Conn(
        val toServer: ByteChannel,
        val fromServer: ByteChannel,
        val job: Job,
    )

    private fun TestScope.pipeline(handler: suspend H1RequestScope.(Request) -> Unit): Conn {
        val toServer = ByteChannel()
        val fromServer = ByteChannel()
        val job = backgroundScope.startH1Pipeline(H1Connection(toServer, fromServer, null, null), idle, 30.seconds, handler = handler)
        runCurrent()
        return Conn(toServer, fromServer, job)
    }

    private suspend fun Conn.send(text: String) {
        toServer.writeStringUtf8(text)
        toServer.flush()
    }

    /** A client that never reads a 16 MiB response is closed once the writer made no progress for the idle timeout. */
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
            advanceTimeBy(idle - 1.milliseconds)
            assertTrue(c.job.isActive, "closed before the idle timeout")
            advanceTimeBy(2.milliseconds)
            assertTrue(c.job.isCompleted, "a client that does not read holds the connection after ${idle + 1.milliseconds}")
            assertTrue(handlerDone.isCompleted, "the handler is still blocked on the response")
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
            advanceTimeBy(idle - 1.milliseconds)
            assertTrue(c.job.isActive, "closed before the idle timeout")
            advanceTimeBy(2.milliseconds)
            assertTrue(c.job.isCompleted, "an upgraded client that does not read holds the connection")
        }

    /**
     * The deadline is on progress, not on the whole response: a client that takes 1 MiB every 40 s (inside the 45 s)
     * keeps the connection for over 6 minutes and then gets the whole response. Progress is seen when the channel in front
     * of the socket takes the engine's buffered bytes, about 1 MiB at a time (Ktor's `ByteChannel`), so a client must read
     * about that much per idle timeout.
     */
    @Test fun readingClientKeepsItsResponse() =
        runTest {
            val size = 12 * MIB
            val c = pipeline { request -> respondLarge(request, size) }
            c.send("GET /large HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n")
            val buffer = ByteArray(64 * 1024)
            var received = 0L
            repeat(10) {
                advanceTimeBy(40.seconds)
                assertTrue(c.job.isActive, "a reading client was closed after ${received / 1024} KiB")
                var round = 0L
                while (round < MIB) {
                    val n = c.fromServer.readAvailable(buffer, 0, minOf(buffer.size.toLong(), MIB - round).toInt())
                    assertTrue(n > 0)
                    round += n
                }
                received += round
            }
            while (true) {
                runCurrent()
                val n = c.fromServer.readAvailable(buffer, 0, buffer.size)
                if (n < 0) break
                received += n
            }
            assertTrue(c.job.isCompleted)
            assertEquals(head(size).length + size, received)
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
