// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.http.HttpHeaders
import io.ktor.server.application.Application
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.receiveText
import io.ktor.server.request.uri
import io.ktor.server.response.header
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.withTimeout
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * How the server checks an HTTP/1.1 request (RFC 9112 section 3.2), finds its end and whether the connection carries another
 * (sections 6, 7).
 */
@OptIn(ExperimentalAtomicApi::class)
class ServerH1FramingTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** How often the handler of `/after-close` ran. */
    private val afterClose = AtomicInt(0)

    private val routes: Application.() -> Unit = {
        routing {
            post("/echo") { call.respondText("body=" + call.receiveText()) }
            get("/admin") { call.respondText("admin secret") }
            get("/") { call.respondText("root") }
            get("/echo-host") {
                val local = call.request.local
                call.respondText("${local.serverHost}|${local.serverPort}|${call.request.uri}|${call.request.queryParameters["q"]}")
            }
            get("/close") {
                call.response.header(HttpHeaders.Connection, "close")
                call.respondText("bye")
            }
            get("/after-close") {
                afterClose.incrementAndFetch()
                call.respondText("after")
            }
            get("/stream") {
                call.respondBytesWriter {
                    writeStringUtf8("hello ")
                    flush()
                    writeStringUtf8("world")
                }
            }
        }
    }

    /**
     * Content-Length and Transfer-Encoding together: the server MUST close the connection after responding (RFC 9112
     * section 6.1); here it rejects the request with 400. Before, it framed the body by the chunked coding and kept reading
     * the connection, so the bytes a Content-Length-framing front proxy took as body became a second, smuggled request.
     */
    @Test fun negative_contentLengthWithTransferEncodingIsRejectedAndClosed() =
        serverTest {
            plainServer { port ->
                val resp =
                    withTimeout(10.seconds) {
                        rawHttp(
                            port,
                            "POST /echo HTTP/1.1\r\nHost: s\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n" +
                                "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n",
                            tls = null,
                        )
                    }
                // the server's highest conforming version, not HTTP/1.0 (RFC 9110 section 6.2)
                assertTrue(resp.startsWith("HTTP/1.1 400 "), resp)
                assertFalse(resp.contains("admin secret"), "the smuggled request was served: $resp")
            }
        }

    /** Conflicting Content-Length values: 400 and close (RFC 9112 section 6.3 item 5). */
    @Test fun negative_invalidContentLengthIsRejected() =
        serverTest {
            plainServer { port ->
                for (cl in listOf("Content-Length: +4", "Content-Length: 4\r\nContent-Length: 5", "Content-Length: 4, 5")) {
                    val resp = withTimeout(10.seconds) { rawHttp(port, "POST /echo HTTP/1.1\r\nHost: s\r\n$cl\r\n\r\nabcd", tls = null) }
                    assertTrue(resp.contains(" 400 "), "$cl: $resp")
                }
            }
        }

    /**
     * A request without Content-Length or Transfer-Encoding has no body (RFC 9112 section 6.3 item 7), also with
     * `Connection: close`. Before, the server read the connection to its end as the body, and `receiveText()` waited for
     * a half-close the client never sends.
     */
    @Test fun postWithoutFramingHasAnEmptyBody() =
        serverTest {
            plainServer { port ->
                val resp =
                    withTimeout(10.seconds) {
                        rawHttp(port, "POST /echo HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n", tls = null)
                    }
                assertTrue(resp.startsWith("HTTP/1.1 200"), resp)
                assertTrue(resp.endsWith("body="), resp)
            }
        }

    /**
     * A chunked request body with a trailer section (RFC 9112 section 7.1.2): the body arrives, the trailer fields are
     * discarded, and the next request on the connection is read in step. Before, the body failed with "Expected CR".
     */
    @Test fun chunkedRequestWithTrailersIsAccepted() =
        serverTest {
            plainServer { port ->
                val resp =
                    withTimeout(10.seconds) {
                        rawHttp(
                            port,
                            "POST /echo HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: chunked\r\n\r\n" +
                                "5\r\nhello\r\n0\r\nX-Checksum: 1\r\nServer-Timing: x\r\n\r\n" +
                                "GET / HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n",
                            tls = null,
                        )
                    }
                assertTrue(resp.contains("body=hello"), resp)
                assertTrue(resp.endsWith("root"), resp)
            }
        }

    /**
     * RFC 9112 section 2.2: a bare CR MUST be treated as invalid. The chunk-size parser skipped a CR anywhere in the line:
     * `1\r0` was read as 0x10 (a recipient that ends the line at the CR reads 1) and `\r\r\n` as the last chunk, so the
     * server answered `body=0123456789abcdef`. Unit cases of the line grammar: `h1.ChunkedBodyTest`.
     */
    @Test fun negative_bareCrInChunkSizeIsRejected() =
        serverTest {
            plainServer { port ->
                for (sizeLine in listOf("1\r0\r\n", "\r\r\n")) {
                    val resp =
                        withTimeout(10.seconds) {
                            rawHttp(
                                port,
                                "POST /echo HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" +
                                    sizeLine + "0123456789abcdef\r\n0\r\n\r\n",
                                tls = null,
                            )
                        }
                    assertTrue(resp.contains(" 400 "), "${sizeLine.replace("\r", "\\r")}: $resp")
                }
            }
        }

    /**
     * RFC 9112 section 3.2: a server MUST respond with 400 to an HTTP/1.1 request without Host and to any request with more
     * than one Host field line. Both were served with 200, the first value winning, while a front proxy that keys on the
     * last one routes and caches by another host.
     */
    @Test fun negative_missingOrRepeatedHostIsRejected() =
        serverTest {
            plainServer { port ->
                for (head in listOf(
                    "GET / HTTP/1.1\r\n",
                    "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n",
                    "GET / HTTP/1.0\r\nHost: a\r\nHost: a\r\n",
                )) {
                    val resp = withTimeout(10.seconds) { rawHttp(port, "${head}Connection: close\r\n\r\n", tls = null) }
                    assertTrue(resp.contains(" 400 "), "[$head]: $resp")
                    assertFalse(resp.contains("root"), "[$head]: $resp")
                }
            }
        }

    /**
     * A response of unknown length to an HTTP/1.0 request: a server MUST NOT send Transfer-Encoding unless the request
     * indicates HTTP/1.1 or later (RFC 9112 section 6.1), so the body is delimited by the close of the connection
     * (section 6.3 item 8), which the response announces with `Connection: close` (section 9.6), also when the client
     * asked for keep-alive. Before, Ktor's `Transfer-Encoding: chunked` went out and the body was chunk-encoded, which
     * an HTTP/1.0 client reads as part of the body; with keep-alive the connection then stayed open.
     */
    @Test fun negative_http10StreamingResponseIsCloseDelimitedWithoutTransferEncoding() =
        serverTest {
            plainServer { port ->
                for (connection in listOf("", "Connection: keep-alive\r\n")) {
                    val resp = withTimeout(10.seconds) { rawHttp(port, "GET /stream HTTP/1.0\r\n$connection\r\n", tls = null) }
                    val head = resp.substringBefore("\r\n\r\n")
                    assertTrue(head.startsWith("HTTP/1.1 200 "), "[$connection]: $resp")
                    assertFalse(head.contains("Transfer-Encoding", ignoreCase = true), "[$connection]: $resp")
                    assertTrue(head.contains("\r\nConnection: close", ignoreCase = true), "[$connection]: $resp")
                    assertEquals("hello world", resp.substringAfter("\r\n\r\n"), "[$connection]: $resp")
                }
            }
        }

    /** A response of known length to an HTTP/1.0 keep-alive request keeps its Content-Length and the connection. */
    @Test fun http10KeepAliveResponseOfKnownLengthKeepsTheConnection() =
        serverTest {
            plainServer { port ->
                val resp =
                    withTimeout(10.seconds) {
                        rawHttp(port, "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\nGET / HTTP/1.0\r\n\r\n", tls = null)
                    }
                assertEquals(2, Regex("HTTP/1.1 200 ").findAll(resp).count(), resp)
                assertTrue(resp.contains("\r\nContent-Length: 4\r\n"), resp)
                assertFalse(resp.contains("Transfer-Encoding", ignoreCase = true), resp)
                assertTrue(resp.endsWith("root"), resp)
            }
        }

    /** An HTTP/1.0 request needs no Host (section 3.2 requires it of HTTP/1.1 only). */
    @Test fun http10RequestWithoutHostIsServed() =
        serverTest {
            plainServer { port ->
                val resp = withTimeout(10.seconds) { rawHttp(port, "GET / HTTP/1.0\r\n\r\n", tls = null) }
                assertTrue(resp.contains(" 200 ") && resp.endsWith("root"), resp)
            }
        }

    /**
     * A malformed header line gets a 400 with a fixed body. Before, the body was Ktor's ParserException message, which
     * embeds the whole header section read so far: cookies, credentials and any field a front proxy added were echoed to
     * the client (the class of Apache's CVE-2012-0053).
     */
    @Test fun negative_badRequestDoesNotEchoTheHeaderSection() =
        serverTest {
            plainServer { port ->
                val resp =
                    withTimeout(10.seconds) {
                        rawHttp(port, "GET / HTTP/1.1\r\nHost: s\r\nCookie: session=SECRET\r\nbad line\r\n\r\n", tls = null)
                    }
                assertTrue(resp.contains(" 400 "), resp)
                assertFalse(resp.contains("SECRET"), resp)
                assertFalse(resp.contains("Cookie"), resp)
            }
        }

    /**
     * RFC 9112 section 3.2.2: a server MUST accept the absolute-form, and when the target is in absolute-form it MUST
     * ignore the received Host field and use the host of the request-target (also section 3.3: the target URI is the
     * request-target). Before, the raw target went to routing (404) and the host came from Host.
     */
    @Test fun absoluteFormIsRoutedByItsPathAndAuthority() =
        serverTest {
            plainServer { port ->
                for ((target, expected) in listOf(
                    "http://a.example/echo-host?q=1" to "a.example|80|/echo-host?q=1|1",
                    "HTTP://A.example:8080/echo-host" to "A.example|8080|/echo-host|null",
                    "http://a.example?q=2" to null, // empty path: "/" (RFC 9110 section 4.2.3)
                )) {
                    val resp =
                        withTimeout(10.seconds) {
                            rawHttp(port, "GET $target HTTP/1.1\r\nHost: b.example\r\nConnection: close\r\n\r\n", tls = null)
                        }
                    assertTrue(resp.startsWith("HTTP/1.1 200 "), "[$target]: $resp")
                    assertTrue(resp.endsWith(expected ?: "root"), "[$target]: $resp")
                }
            }
        }

    /**
     * An "http" URI with an empty host: a recipient MUST reject it as invalid (RFC 9110 section 4.2.1). Userinfo in an
     * absolute-form target: a recipient SHOULD treat it as an error, it is likely used to obscure the authority (section
     * 4.2.4). Both 400; a Host field is still required (RFC 9112 section 3.2).
     */
    @Test fun negative_absoluteFormWithEmptyHostOrUserinfoIsRejected() =
        serverTest {
            plainServer { port ->
                for (head in listOf(
                    "GET http:///echo-host HTTP/1.1\r\nHost: b.example\r\n",
                    "GET http://u:p@a.example/echo-host HTTP/1.1\r\nHost: b.example\r\n",
                    "GET http://a.example/echo-host HTTP/1.1\r\n",
                )) {
                    val resp = withTimeout(10.seconds) { rawHttp(port, "${head}Connection: close\r\n\r\n", tls = null) }
                    assertTrue(resp.startsWith("HTTP/1.1 400 "), "[$head]: $resp")
                    assertFalse(resp.contains("example|"), "[$head]: $resp")
                }
            }
        }

    /**
     * RFC 9112 section 9.6: a server that sends a "close" connection option MUST initiate closure of the connection after
     * that response and MUST NOT process any further requests received on it. Before, a handler's `Connection: close`
     * was written, and the pipelined `/after-close` was still executed and answered on the same connection.
     */
    @Test fun negative_responseConnectionCloseEndsThePipeline() =
        serverTest {
            plainServer { port ->
                val resp =
                    withTimeout(10.seconds) {
                        rawHttp(
                            port,
                            "GET /close HTTP/1.1\r\nHost: s\r\n\r\nGET /after-close HTTP/1.1\r\nHost: s\r\n\r\n",
                            tls = null,
                        )
                    }
                assertTrue(resp.startsWith("HTTP/1.1 200 "), resp)
                assertTrue(resp.endsWith("bye"), resp)
                assertEquals(1, Regex("HTTP/1.1 ").findAll(resp).count(), resp)
                assertEquals(0, afterClose.load(), resp)
            }
        }

    /** A transfer coding other than a final `chunked`: 400 and close (RFC 9112 section 6.3 item 4). */
    @Test fun negative_unknownTransferCodingIsRejected() =
        serverTest {
            plainServer { port ->
                val resp =
                    withTimeout(10.seconds) {
                        rawHttp(port, "POST /echo HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: gzip\r\n\r\nabcd", tls = null)
                    }
                assertTrue(resp.contains(" 400 "), resp)
            }
        }

    /**
     * Whitespace other than SP and HTAB around a framing field value (VT, FF, U+00A0 sent as `C2 A0`) makes the value
     * invalid: OWS is `*( SP / HTAB )` (RFC 9110 section 5.6.3), Content-Length is `1*DIGIT` (RFC 9110 section 8.6) and a
     * transfer coding is a token (RFC 9112 section 6.1). 400 and close (RFC 9112 section 6.3 items 4 and 5), and the
     * pipelined request behind it is not served. Before, Kotlin's `trim()` stripped them and the body was framed by
     * the value, while a front proxy that ignores the invalid field (length 0) forwards the body as the next request
     * (CL.0 / TE obfuscation smuggling).
     */
    @Test fun negative_nonOwsWhitespaceInFramingFieldsIsRejected() =
        serverTest {
            plainServer { port ->
                val smuggled = "GET /admin HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n"
                val cases =
                    listOf(
                        "Content-Length: 5\u000b\r\n\r\nhello",
                        "Content-Length: 5\u000c\r\n\r\nhello",
                        "Content-Length: 5 \r\n\r\nhello",
                        "Content-Length: 5, 5\u000b\r\n\r\nhello",
                        "Content-Length: 5\u00a0\r\n\r\nhello",
                        "Content-Length: \u00a05\r\n\r\nhello",
                        "Transfer-Encoding: chunked\u00a0\r\n\r\n0\r\n\r\n",
                        "Transfer-Encoding: chunked \r\n\r\n0\r\n\r\n",
                        "Transfer-Encoding: chunked\u000b\r\n\r\n0\r\n\r\n",
                        "Transfer-Encoding: chunked\u000c\r\n\r\n0\r\n\r\n",
                        "Transfer-Encoding: chun ked\r\n\r\n0\r\n\r\n",
                        "Transfer-Encoding: \"chunked\"\r\n\r\n0\r\n\r\n",
                        "Transfer-Encoding: chunked;\r\n\r\n0\r\n\r\n",
                    )
                for (case in cases) {
                    val resp =
                        withTimeout(10.seconds) {
                            rawHttp(port, "POST /echo HTTP/1.1\r\nHost: s\r\n$case$smuggled", tls = null)
                        }
                    val shown =
                        case.substringBefore("\r\n\r\n").map {
                            if (it.code < 0x20 ||
                                it.code > 0x7e
                            ) {
                                "\\u" + it.code.toString(16).padStart(4, '0')
                            } else {
                                "$it"
                            }
                        }
                    assertTrue(resp.startsWith("HTTP/1.1 400 "), "${shown.joinToString("")}: $resp")
                    assertFalse(resp.contains("admin secret"), "${shown.joinToString("")}: the pipelined request was served: $resp")
                }
            }
        }

    /** SP and HTAB are OWS (RFC 9110 section 5.6.3) and coding names are case-insensitive (RFC 9112 section 7). */
    @Test fun owsAndCaseInFramingFieldsAreAccepted() =
        serverTest {
            plainServer { port ->
                for (case in listOf(
                    "Content-Length: \t5 \t\r\n\r\nhello",
                    "Transfer-Encoding: \t, ChUnKeD \t\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                )) {
                    val resp =
                        withTimeout(10.seconds) {
                            rawHttp(port, "POST /echo HTTP/1.1\r\nHost: s\r\nConnection: close\r\n$case", tls = null)
                        }
                    assertTrue(resp.startsWith("HTTP/1.1 200 "), "$case: $resp")
                    assertTrue(resp.endsWith("body=hello"), "$case: $resp")
                }
            }
        }

    /**
     * A transfer coding the server does not implement before a final `chunked` (`identity` is no transfer coding since
     * RFC 7230): 501 (RFC 9112 section 6.1), and the connection closes, as the body is not read.
     */
    @Test fun negative_unimplementedTransferCodingGets501() =
        serverTest {
            plainServer { port ->
                for (te in listOf("gzip, chunked", "gzip;level=\"1,2\" , chunked", "identity, chunked")) {
                    val resp =
                        withTimeout(10.seconds) {
                            rawHttp(
                                port,
                                "POST /echo HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: $te\r\n\r\n0\r\n\r\n" +
                                    "GET /admin HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n",
                                tls = null,
                            )
                        }
                    assertTrue(resp.startsWith("HTTP/1.1 501 "), "$te: $resp")
                    assertFalse(resp.contains("admin secret"), "$te: $resp")
                }
            }
        }

    /** `chunked` applied twice (RFC 9112 section 6.1: a sender MUST NOT) or not final (section 6.3 item 4): 400. */
    @Test fun negative_chunkedTwiceOrNotFinalIsRejected() =
        serverTest {
            plainServer { port ->
                for (te in listOf("chunked, chunked", "chunked\r\nTransfer-Encoding: chunked", "chunked, gzip", "chunked;x=1")) {
                    val resp =
                        withTimeout(10.seconds) {
                            rawHttp(port, "POST /echo HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: $te\r\n\r\n0\r\n\r\n", tls = null)
                        }
                    assertTrue(resp.startsWith("HTTP/1.1 400 "), "$te: $resp")
                }
            }
        }

    private suspend fun plainServer(block: suspend (Int) -> Unit) {
        val server =
            embeddedServer(Kuicksilver, configure = {
                connector {
                    host = "127.0.0.1"
                    port = 0
                }
            }, module = routes)
        server.startSuspend(false)
        try {
            block(
                server.engine
                    .resolvedConnectors()
                    .first()
                    .port,
            )
        } finally {
            server.stop(100, 500)
        }
    }
}
