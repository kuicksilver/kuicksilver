// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.url
import io.ktor.http.Url
import io.ktor.http.cio.ParserException
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ClosedReadChannelException
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

    /**
     * A response head cut before its empty line is incomplete (RFC 9112 section 8: the client MUST record it as such): the
     * request fails with a ClosedReadChannelException, which keeps the stale-connection retry of an idempotent request.
     * Before, the fields read so far were dropped and the call succeeded with a 200 without fields and an empty body.
     */
    @Test fun negative_headCutBeforeTheEmptyLineFails() =
        runTest(timeout = 20.seconds) {
            val wire = Wire()
            server(wire) { send ->
                send("HTTP/1.1 200 OK\r\nContent-Length: 100\r\nLocation: /x\r\n")
                wire.fromServer.flushAndClose()
            }
            assertFailsWith<ClosedReadChannelException> { exchange(wire, get) }
        }

    /** The proxy's CONNECT response cut before its empty line fails the tunnel the same way (RFC 9112 section 8). */
    @Test fun negative_connectHeadCutBeforeTheEmptyLineFails() =
        runTest(timeout = 20.seconds) {
            val input = ByteChannel()
            input.writeStringUtf8("HTTP/1.1 200 Connection established\r\nX-A: 1\r\n")
            input.flushAndClose()
            assertFailsWith<ClosedReadChannelException> { startTunnel(Url("https://origin.test/"), null, null, ByteChannel(), input) }
        }

    /**
     * NUL in a field value is invalid and dangerous (RFC 9110 section 5.5: reject or replace it); the client rejects it and
     * every other control character but HTAB (0x01-0x08, 0x0A-0x1F, 0x7F), in field lines and the reason phrase alike.
     * Before, `a<NUL>b` reached the application.
     */
    @Test fun negative_nulInFieldValueFails() =
        runTest(timeout = 20.seconds) {
            for (head in listOf("X-A: a\u0000b", "X-A: a\u0001b", "X-A: a\u007fb", "X-A: a\u001bb")) {
                val wire = Wire()
                server(wire) { send -> send("HTTP/1.1 200 OK\r\n$head\r\nContent-Length: 0\r\n\r\n") }
                assertFailsWith<ParserException>(head) { exchange(wire, get) }
            }
            val wire = Wire()
            server(wire) { send -> send("HTTP/1.1 200 O\u0000K\r\nContent-Length: 0\r\n\r\n") }
            assertFailsWith<ParserException> { exchange(wire, get) }
        }

    /** HTAB and obs-text (bytes above 0x7F) are field-value characters (RFC 9110 section 5.5) and pass. */
    @Test fun htabAndObsTextInFieldValuePass() =
        runTest(timeout = 20.seconds) {
            val wire = Wire()
            server(wire) { send -> send("HTTP/1.1 200 OK\r\nX-A: a\tb\u00e9\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") }
            val value = exchange(wire, get).headers["X-A"]
            assertEquals("a\tb", value?.substring(0, 3))
        }

    /**
     * A user agent MUST replace each obs-fold in a response with SP (RFC 9112 section 5.2): a field line that starts with
     * SP or HTAB continues the previous one. Before, Ktor's parser failed the response.
     */
    @Test fun obsFoldInResponseIsUnfolded() =
        runTest(timeout = 20.seconds) {
            val wire = Wire()
            server(wire) { send ->
                send("HTTP/1.1 200 OK\r\nX-A: a\r\n b\r\nX-B: one  \r\n\t two\r\n   three\r\n")
                send("Content-Length: 0\r\nConnection: close\r\n\r\n")
            }
            val headers = exchange(wire, get).headers
            assertEquals("a b", headers["X-A"])
            assertEquals("one two three", headers["X-B"])
        }

    /**
     * A line that starts with whitespace right after the status line continues no field: the response is rejected (RFC
     * 9112 section 2.2: reject it, or consume such lines without processing them).
     */
    @Test fun negative_foldRightAfterTheStatusLineFails() =
        runTest(timeout = 20.seconds) {
            val wire = Wire()
            server(wire) { send -> send("HTTP/1.1 200 OK\r\n X-A: a\r\nContent-Length: 0\r\n\r\n") }
            assertFailsWith<ParserException> { exchange(wire, get) }
        }
}
