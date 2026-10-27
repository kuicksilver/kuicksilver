// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.server.h1

import io.ktor.http.cio.Request
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.discard
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runTest
import kotlinx.io.readString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The size limit of a request head (request line and header section): Ktor's parser bounds each line at 8 KiB but not
 * their number, so without a limit one connection could push any amount of header data into the heap.
 */
class H1PipelineHeadLimitTest {
    private class Conn(
        val toServer: ByteChannel,
        val fromServer: ByteChannel,
        val job: Job,
    )

    private fun TestScope.pipeline(handler: suspend H1RequestScope.(Request) -> Unit = { respondOk(it) }): Conn {
        val toServer = ByteChannel()
        val fromServer = ByteChannel()
        val job = backgroundScope.startH1Pipeline(H1Connection(toServer, fromServer, null, null), 45.seconds, 30.seconds, handler = handler)
        return Conn(toServer, fromServer, job)
    }

    /** Sends [text] and then ends the client's side; returns what the server sent until it closed. */
    private suspend fun TestScope.exchange(
        c: Conn,
        text: String,
    ): String {
        backgroundScope.launch {
            c.toServer.writeStringUtf8(text)
            c.toServer.flushAndClose()
        }
        advanceTimeBy(1.seconds) // well inside the 30 s header deadline; backgroundScope work does not count for advanceUntilIdle
        assertTrue(c.job.isCompleted, "the connection is still open")
        return c.fromServer.readBuffer().readString()
    }

    /** A head one byte over the limit gets 431 and the connection closes (RFC 6585 section 5). */
    @Test fun negative_headOverTheLimitGets431() =
        runTest {
            val c = pipeline()
            val response = exchange(c, headOfSize(MAX_REQUEST_HEAD_BYTES + 1) + "GET /next HTTP/1.1\r\nHost: s\r\n\r\n")
            assertTrue(response.startsWith("HTTP/1.1 431 Request Header Fields Too Large\r\n"), response.take(200))
            assertTrue(response.contains("\r\nConnection: close\r\n"), response)
            assertEquals(1, Regex("HTTP/1.1 ").findAll(response).count(), "the request after the refused head was served: $response")
        }

    /** Megabytes of header fields are refused after the limit, not buffered. */
    @Test fun negative_hugeHeaderSectionGets431() =
        runTest {
            val c = pipeline()
            val response = exchange(c, headOfSize(4 * 1024 * 1024))
            assertTrue(response.startsWith("HTTP/1.1 431 "), response.take(200))
        }

    /**
     * A request-target longer than the server parses (a request line over Ktor's 8 KiB line limit): the server MUST
     * respond with 414 (RFC 9112 section 3). Before, it answered 400.
     */
    @Test fun negative_longRequestTargetGets414() =
        runTest {
            val c = pipeline()
            val response = exchange(c, "GET /" + "a".repeat(9_000) + " HTTP/1.1\r\nHost: s\r\n\r\nGET /next HTTP/1.1\r\nHost: s\r\n\r\n")
            assertTrue(response.startsWith("HTTP/1.1 414 URI Too Long\r\n"), response.take(200))
            assertTrue(response.contains("\r\nConnection: close\r\n"), response)
            assertEquals(1, Regex("HTTP/1.1 ").findAll(response).count(), "the request after the refused head was served: $response")
        }

    /** A request line of exactly 8 KiB (Ktor's line limit) is served; one byte more is 414. */
    @Test fun requestLineAtTheLineLimitIsServed() =
        runTest {
            val line = "GET /" + "a".repeat(8_192 - "GET / HTTP/1.1".length) + " HTTP/1.1"
            assertEquals(8_192, line.length)
            assertEquals(OK, exchange(pipeline(), "$line\r\nHost: s\r\nConnection: close\r\n\r\n"))
            val response = exchange(pipeline(), "${line.replace("/a", "/aa")}\r\nHost: s\r\n\r\n")
            assertTrue(response.startsWith("HTTP/1.1 414 "), response.take(200))
        }

    /**
     * A method longer than any the server implements (a token over the whole 8 KiB line limit): 501 (RFC 9112 section 3:
     * the server SHOULD respond with 501). A line over the limit that starts with no token at all stays 400.
     */
    @Test fun negative_longMethodGets501() =
        runTest {
            val response = exchange(pipeline(), "G".repeat(9_000) + " / HTTP/1.1\r\nHost: s\r\n\r\n")
            assertTrue(response.startsWith("HTTP/1.1 501 Not Implemented\r\n"), response.take(200))
            val garbage = exchange(pipeline(), "\"" + "G".repeat(9_000) + " / HTTP/1.1\r\nHost: s\r\n\r\n")
            assertTrue(garbage.startsWith("HTTP/1.1 400 "), garbage.take(200))
        }

    /** A field line over the 8 KiB line limit is no request-target: it stays 400. */
    @Test fun negative_longFieldLineGets400() =
        runTest {
            val c = pipeline()
            val response = exchange(c, "GET / HTTP/1.1\r\nHost: s\r\nX-Long: " + "a".repeat(9_000) + "\r\n\r\n")
            assertTrue(response.startsWith("HTTP/1.1 400 "), response.take(200))
        }

    /** A head of exactly the limit is served. */
    @Test fun headAtTheLimitIsServed() =
        runTest {
            val c = pipeline()
            assertEquals(OK, exchange(c, headOfSize(MAX_REQUEST_HEAD_BYTES, close = true)))
        }

    /** The limit is per head: a large body before the next head does not count against it. */
    @Test fun bodyDoesNotCountAgainstTheNextHead() =
        runTest {
            val c =
                pipeline { request ->
                    input.discard()
                    respondOk(request)
                }
            val body = "b".repeat(3 * MAX_REQUEST_HEAD_BYTES)
            val response =
                exchange(
                    c,
                    "POST / HTTP/1.1\r\nHost: s\r\nContent-Length: ${body.length}\r\n\r\n$body" +
                        headOfSize(MAX_REQUEST_HEAD_BYTES, close = true),
                )
            assertEquals(OK + OK, response)
        }

    private companion object {
        const val OK = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

        @OptIn(InternalAPI::class)
        suspend fun H1RequestScope.respondOk(request: Request) {
            request.release()
            output.writeStringUtf8(OK)
            output.flush()
        }

        /** A GET head of exactly [size] bytes (request line, fields, the empty line), padded with lines under 8 KiB. */
        fun headOfSize(
            size: Int,
            close: Boolean = false,
        ): String {
            val start = "GET / HTTP/1.1\r\nHost: s\r\n" + (if (close) "Connection: close\r\n" else "")
            val padding = size - start.length - 2
            val lines = (padding + 7_999) / 8_000
            val sb = StringBuilder(start)
            for (j in 0 until lines) {
                val length = padding / lines + (if (j < padding % lines) 1 else 0)
                val name = "X-P" + j.toString().padStart(4, '0') + ": " // 9 characters, then the value and CRLF
                sb.append(name).append("p".repeat(length - name.length - 2)).append("\r\n")
            }
            sb.append("\r\n")
            check(sb.length == size) { "head of ${sb.length} bytes, $size wanted" }
            return sb.toString()
        }
    }
}
