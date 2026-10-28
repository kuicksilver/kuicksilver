// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.url
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.Url
import io.ktor.http.cio.ParserException
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ClosedReadChannelException
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.readLineStrict
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.io.readString
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
     * A server that streams interim 103 heads without end fails the request once they add up to more than
     * [MAX_INTERIM_HEAD_BYTES]: a bound by bytes, not by count, so any number of 1xx heads that a final response follows
     * is parsed (RFC 9110 section 15.2 MUST). Before, they were skipped without end, and then a sixth one failed.
     */
    @Test fun negative_endlessInterimResponsesFail() =
        runTest(timeout = 20.seconds) {
            val wire = Wire()
            server(wire) { send ->
                while (true) send("HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n")
            }
            val e = assertFailsWith<ParserException> { exchange(wire, get) }
            assertTrue(e.message!!.contains("interim") && e.message!!.contains("$MAX_INTERIM_HEAD_BYTES"), e.message)
            assertTrue(wire.toServer.isClosedForWrite, "the connection was not closed")
        }

    /**
     * A 100 Continue and many 103 Early Hints before the final response are skipped, however many there are (RFC 9110
     * section 15.2: a client MUST be able to parse one or more 1xx responses); before, a sixth one failed the request.
     */
    @Test fun manyInterimResponsesAreSkipped() =
        runTest(timeout = 20.seconds) {
            val wire = Wire()
            server(wire) { send ->
                send("HTTP/1.1 100 Continue\r\n\r\n")
                repeat(200) { send("HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n") }
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

    /**
     * The status code is exactly three digits (RFC 9112 section 4: `status-code = 3DIGIT`): a shorter or longer code
     * fails the response. Before, `HTTP/1.1 20` or `HTTP/1.1 2000` without a reason phrase were taken as statuses 20 and
     * 2000.
     */
    @Test fun negative_statusCodeNotThreeDigitsFails() =
        runTest(timeout = 20.seconds) {
            for (line in listOf("HTTP/1.1 20", "HTTP/1.1 2000", "HTTP/1.1 20 OK", "HTTP/1.1 2x0 X")) {
                val wire = Wire()
                server(wire) { send -> send("$line\r\nContent-Length: 0\r\n\r\n") }
                assertFailsWith<ParserException>(line) { exchange(wire, get) }
            }
        }

    /**
     * Three digits outside 100..599 are an invalid status code, and "A client that receives a response with an invalid
     * status code SHOULD process the response as if it had a 5xx (Server Error) status code" (RFC 9110 section 15): the
     * response is a 500 whose description keeps the code and reason the server sent, its body is read by its framing,
     * and a 0xx is not taken for an interim response. Before 0.2.1's checks such codes were passed on as they were;
     * then they failed the response.
     */
    @Test fun invalidStatusCodeIsProcessedAs5xx() =
        runTest(timeout = 20.seconds) {
            for ((line, description) in listOf(
                "HTTP/1.1 600 Six" to "600 Six",
                "HTTP/1.1 999 Nine" to "999 Nine",
                "HTTP/1.1 099 X" to "099 X",
                "HTTP/1.1 000" to "000",
                "HTTP/1.1 042 " to "042",
            )) {
                val wire = Wire()
                server(wire) { send -> send("$line\r\nContent-Length: 3\r\n\r\nabc") }
                exchange(wire, get) { response ->
                    assertEquals(500, response.statusCode.value, line)
                    assertEquals(description, response.statusCode.description, line)
                    assertEquals("abc", (response.body as ByteReadChannel).readBuffer().readString(), line)
                }
            }
        }

    /**
     * OWS is only SP and HTAB (RFC 9110 section 5.6.3) and obs-text is field content a recipient SHOULD treat as opaque
     * data (section 5.5), but Ktor's parser skips any Unicode whitespace before a value. A value that starts with
     * U+00A0 (or another Unicode space, sent as obs-text) is kept as sent, as the server does for requests: the
     * application sees it, and a Content-Length or Transfer-Encoding with it is invalid (RFC 9112 section 6.3 items 4 and
     * 5: the framing is unknown, the response is discarded and the connection closed). Before, `Transfer-Encoding:
     * <U+00A0>chunked` framed the body as chunked while a recipient that reads OWS as SP and HTAB only sees no coding it
     * knows, and `Content-Length: <U+00A0>5` framed 5 bytes.
     */
    @Test fun negative_unicodeSpaceBeforeAFramingValueIsInvalid() =
        runTest(timeout = 20.seconds) {
            for (field in listOf("Transfer-Encoding: \u00a0chunked", "Content-Length: \u00a05", "Content-Length: \u20035")) {
                val wire = Wire()
                server(wire) { send -> send("HTTP/1.1 200 OK\r\n$field\r\n\r\n5\r\nhello\r\n0\r\n\r\n") }
                assertFailsWith<ParserException>(field) { exchange(wire, get) }
            }
        }

    /** Any other value that starts with a Unicode space reaches the application as sent. */
    @Test fun unicodeSpaceBeforeAFieldValueIsKept() =
        runTest(timeout = 20.seconds) {
            val wire = Wire()
            server(wire) { send -> send("HTTP/1.1 200 OK\r\nX-A: b\r\nX-A: \u00a0a \r\nX-B: \u3000c\r\nContent-Length: 0\r\n\r\n") }
            val response = exchange(wire, get)
            assertEquals(listOf("b", "\u00a0a"), response.headers.getAll("X-A"))
            assertEquals("\u3000c", response.headers["x-b"])
        }

    /**
     * The head is read a line at a time from what is buffered: a head that arrives one byte per write, and one that
     * arrives with its body in a single write, are read the same, and the body bytes after the head stay for the body.
     */
    @Test fun headIsReadWhateverItsChunks() =
        runTest(timeout = 20.seconds) {
            val wire = "HTTP/1.1 200 OK\r\nX-A: a\r\n b\r\nContent-Length: 5\r\n\r\nhello"
            for (split in listOf(true, false)) {
                val w = Wire()
                server(w) { send -> if (split) wire.forEach { send(it.toString()) } else send(wire) }
                exchange(w, get) { response ->
                    assertEquals("a b", response.headers["X-A"], "split=$split")
                    assertEquals("hello", (response.body as ByteReadChannel).readBuffer().readString(), "split=$split")
                }
            }
        }

    /**
     * "Any Content-Length field value greater than or equal to zero is valid ... a recipient MUST anticipate potentially
     * large decimal numerals and prevent parsing errors due to integer conversion overflows" (RFC 9110 section 8.6):
     * leading zeros count for nothing, so `0000000000000000000005` is 5 and equals `5` in a list. A length of 10^18 or
     * more is valid but more than this client reads: the response fails with a ParserException that says so, not as an
     * invalid length. Before, any value of more than 18 characters was invalid.
     */
    @Test fun longContentLengthValuesAreRead() =
        runTest(timeout = 20.seconds) {
            for (cl in listOf("0000000000000000000005", "05, 5", "5, 000000000000000000000005")) {
                val wire = Wire()
                server(wire) { send -> send("HTTP/1.1 200 OK\r\nContent-Length: $cl\r\n\r\nhello") }
                exchange(wire, get) { response ->
                    assertEquals("hello", (response.body as ByteReadChannel).readBuffer().readString(), cl)
                }
            }
            for (cl in listOf("1000000000000000000", "99999999999999999999")) {
                val wire = Wire()
                server(wire) { send -> send("HTTP/1.1 200 OK\r\nContent-Length: $cl\r\n\r\nhello") }
                val e = assertFailsWith<ParserException>(cl) { exchange(wire, get) }
                assertTrue(e.message!!.contains("larger than this client reads"), "$cl: ${e.message}")
            }
        }

    /** A status line without a reason phrase is accepted, with or without the SP before it (as Go and OkHttp). */
    @Test fun statusLineWithoutReasonPhraseIsAccepted() =
        runTest(timeout = 20.seconds) {
            for (line in listOf("HTTP/1.1 204", "HTTP/1.1 204 ")) {
                val wire = Wire()
                server(wire) { send -> send("$line\r\nConnection: close\r\n\r\n") }
                assertEquals(204, exchange(wire, get).statusCode.value, line)
            }
        }

    /**
     * A higher minor version is processed as HTTP/1.1, the highest this client conforms to (RFC 9110 section 6.2 SHOULD);
     * before, `HTTP/1.2` failed the response. Another major version fails it.
     */
    @Test fun higherMinorVersionIsProcessedAsHttp11() =
        runTest(timeout = 20.seconds) {
            val wire = Wire()
            server(wire) { send -> send("HTTP/1.2 200 OK\r\nContent-Length: 0\r\n\r\n") }
            val response = exchange(wire, get)
            assertEquals(200, response.statusCode.value)
            assertEquals(HttpProtocolVersion.HTTP_1_1, response.version)
            for (line in listOf("HTTP/2.0 200 OK", "HTTP/0.9 200 OK", "http/1.1 200 OK")) {
                val other = Wire()
                server(other) { send -> send("$line\r\nContent-Length: 0\r\n\r\n") }
                assertFailsWith<ParserException>(line) { exchange(other, get) }
            }
        }

    /**
     * Interim responses to the CONNECT are bounded as those to a request ([MAX_INTERIM_HEAD_BYTES] in all): many of them
     * are skipped, a proxy that streams them without end fails the tunnel; a 101 is no answer to a CONNECT and fails it
     * as a refusal.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun negative_endlessInterimResponsesToTheConnectFail() =
        runTest(timeout = 20.seconds) {
            val many = ByteChannel()
            repeat(200) { many.writeStringUtf8("HTTP/1.1 103 Early Hints\r\n\r\n") }
            many.writeStringUtf8("HTTP/1.1 200 Connection established\r\n\r\n")
            many.flush()
            startTunnel(Url("https://origin.test/"), null, null, ByteChannel(), many)
            val input = ByteChannel()
            backgroundScope.launch {
                runCatching {
                    while (true) {
                        input.writeStringUtf8("HTTP/1.1 103 Early Hints\r\n\r\n")
                        input.flush()
                    }
                }
            }
            val e = assertFailsWith<ParserException> { startTunnel(Url("https://origin.test/"), null, null, ByteChannel(), input) }
            assertTrue(e.message!!.contains("interim") && e.message!!.contains("$MAX_INTERIM_HEAD_BYTES"), e.message)
            input.cancel(null)
            val upgrade = ByteChannel()
            upgrade.writeStringUtf8("HTTP/1.1 101 Switching Protocols\r\n\r\n")
            upgrade.flush()
            val refused =
                assertFailsWith<io.kuicksilver.ktor.client.ProxyException> {
                    startTunnel(Url("https://origin.test/"), null, null, ByteChannel(), upgrade)
                }
            assertEquals(101, refused.replyCode)
        }
}
