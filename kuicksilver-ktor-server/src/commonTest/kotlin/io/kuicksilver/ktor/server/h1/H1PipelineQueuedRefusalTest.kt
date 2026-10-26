// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.server.h1

import io.ktor.http.cio.Request
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A refused request (400, 431) behind pipelined requests whose responses fill the writer's queue. The refusal was queued
 * with `trySend` and dropped when the queue was full, so the client saw the earlier responses and then the close, with no
 * answer to the request it sent: RFC 9112 section 6.3 items 4 and 5 and section 3.2 require a 400, and RFC 6585 section 5
 * gives 431 for a head that is too large. In-memory channels, virtual time.
 */
class H1PipelineQueuedRefusalTest {
    private class Conn(
        val toServer: ByteChannel,
        val fromServer: ByteChannel,
        val job: Job,
    )

    /** A pipeline whose handler answers every request with 200 once [gate] is open. */
    private fun TestScope.pipeline(gate: Job): Conn {
        val toServer = ByteChannel()
        val fromServer = ByteChannel()
        val handler: suspend H1RequestScope.(Request) -> Unit = { request ->
            request.release()
            gate.join()
            output.writeStringUtf8(OK)
            output.flush()
        }
        val job = backgroundScope.startH1Pipeline(H1Connection(toServer, fromServer, null, null), 45.seconds, 30.seconds, handler = handler)
        return Conn(toServer, fromServer, job)
    }

    /** Four requests held by their handler fill the writer (one) and its queue (three), then [refused] is sent. */
    private fun TestScope.statusesAfterFullQueue(refused: String): List<String> {
        val gate = Job()
        val c = pipeline(gate)
        backgroundScope.launch {
            c.toServer.writeStringUtf8("GET / HTTP/1.1\r\nHost: s\r\n\r\n".repeat(4) + refused)
            c.toServer.flush()
        }
        runCurrent() // all five heads read, the fifth refused, while the first four wait for the gate
        gate.complete()
        var seen = ""
        backgroundScope.launch { seen = c.fromServer.readToEnd() }
        advanceTimeBy(5.seconds) // past the linger after a refused head, well inside the idle and head deadlines
        runCurrent()
        assertTrue(c.job.isCompleted, "the connection is still open")
        return Regex("HTTP/1.1 (\\d{3}) ").findAll(seen).map { it.groupValues[1] }.toList()
    }

    @Test fun negative_aMalformedRequestBehindAFullQueueGets400() =
        runTest {
            val statuses = statusesAfterFullQueue("POST / HTTP/1.1\r\nHost: s\r\nContent-Length: abc\r\n\r\n")
            assertEquals(listOf("200", "200", "200", "200", "400"), statuses)
        }

    @Test fun negative_anOversizedHeadBehindAFullQueueGets431() =
        runTest {
            val statuses = statusesAfterFullQueue("GET / HTTP/1.1\r\nHost: s\r\n" + "X-Pad: ${"p".repeat(7_000)}\r\n".repeat(10) + "\r\n")
            assertEquals(listOf("200", "200", "200", "200", "431"), statuses)
        }

    private companion object {
        const val OK = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

        /** Everything the server sent until it closed. */
        suspend fun ByteReadChannel.readToEnd(): String {
            val out = StringBuilder()
            val buf = ByteArray(4096)
            while (true) {
                val n = readAvailable(buf, 0, buf.size)
                if (n < 0) return out.toString()
                out.append(buf.decodeToString(0, n))
            }
        }
    }
}
