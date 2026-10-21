// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.url
import io.ktor.http.cio.ParserException
import io.ktor.utils.io.readLineStrict
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Limits on what a server can make the HTTP/1.1 client hold for one response head: Ktor's `parseResponse` bounds each line
 * at 8 KiB but not their number, and interim 1xx heads were skipped without end.
 */
class H1ResponseHeadTest {
    private val get = HttpRequestBuilder().apply { url("http://127.0.0.1:8080/") }.build()

    /** Reads the request head, then writes [response] (as long as the client reads it). */
    private fun TestScope.server(
        wire: Wire,
        response: suspend (suspend (String) -> Unit) -> Unit,
    ) = backgroundScope.launch {
        while (wire.toServer.readLineStrict()?.isNotEmpty() == true) continue
        runCatching {
            response { text ->
                wire.fromServer.writeStringUtf8(text)
                wire.fromServer.flush()
            }
        }
    }

    /**
     * A response head of 4 MiB in 4 KiB fields fails the request with a ParserException naming the limit, and the
     * connection is closed. Before, all of it was buffered (twice its size as a CharArrayBuilder) and the call
     * succeeded.
     */
    @Test fun negative_hugeResponseHeadFails() =
        runTest(timeout = 20.seconds) {
            val wire = Wire()
            server(wire) { send ->
                send("HTTP/1.1 200 OK\r\n")
                repeat(1024) { send("X-Pad: " + "p".repeat(4000) + "\r\n") }
                send("Content-Length: 0\r\n\r\n")
            }
            val e = assertFailsWith<ParserException> { exchange(wire, get) }
            assertTrue(e.message!!.contains("65536"), e.message)
            assertTrue(wire.toServer.isClosedForWrite, "the connection was not closed")
        }

    /** A head just under the limit is read. */
    @Test fun headUnderTheLimitIsRead() =
        runTest(timeout = 20.seconds) {
            val wire = Wire()
            server(wire) { send ->
                send("HTTP/1.1 200 OK\r\n")
                repeat(14) { send("X-Pad: " + "p".repeat(4000) + "\r\n") }
                send("Content-Length: 0\r\nConnection: close\r\n\r\n")
            }
            assertEquals(200, exchange(wire, get).statusCode.value)
        }

    /**
     * A server that streams interim 103 heads holds the request only for a few of them: after 5 (Go's net/http stops at
     * the same count) the request fails. Before, they were skipped without end, bounded only by a request timeout.
     */
    @Test fun negative_endlessInterimResponsesFail() =
        runTest(timeout = 20.seconds) {
            val wire = Wire()
            server(wire) { send ->
                repeat(50) { send("HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n") }
                send("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            }
            val e = assertFailsWith<ParserException> { exchange(wire, get) }
            assertTrue(e.message!!.contains("interim"), e.message)
        }

    /** A 100 Continue and a few 103 Early Hints before the final response are skipped (RFC 9110 section 15.2). */
    @Test fun fewInterimResponsesAreSkipped() =
        runTest(timeout = 20.seconds) {
            val wire = Wire()
            server(wire) { send ->
                send("HTTP/1.1 100 Continue\r\n\r\n")
                repeat(4) { send("HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n") }
                send("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            }
            assertEquals(204, exchange(wire, get).statusCode.value)
        }
}
