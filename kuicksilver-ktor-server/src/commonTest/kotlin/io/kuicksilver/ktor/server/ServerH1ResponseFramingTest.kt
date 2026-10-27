// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.head
import io.ktor.server.routing.routing
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** How the server frames the responses the application gives it (RFC 9110 sections 6 and 8.6, RFC 9112 sections 4 and 6). */
class ServerH1ResponseFramingTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val routes: Application.() -> Unit = {
        routing {
            get("/") { call.respondText("root") }
            get("/204") { call.respond(HttpStatusCode.NoContent) }
            get("/204-stream") { call.respondBytesWriter(status = HttpStatusCode.NoContent) {} }
            get("/304") {
                call.response.header(HttpHeaders.ETag, "\"v1\"")
                call.respond(HttpStatusCode.NotModified)
            }
            get("/304-stream") { call.respondBytesWriter(status = HttpStatusCode.NotModified) {} }
            head("/head-text") { call.respondText("x") }
            head("/head-stream") { call.respondBytesWriter { writeStringUtf8("abc") } }
            get("/204-text") { call.respondText("x", status = HttpStatusCode.NoContent) }
            get("/304-text") { call.respondText("xy", status = HttpStatusCode.NotModified) }
            get("/own-date") {
                call.response.header(HttpHeaders.Date, "Sun, 06 Nov 1994 08:49:37 GMT")
                call.respondText("dated")
            }
            get("/reason-crlf") { call.respond(HttpStatusCode(200, "OK\r\nX-Injected: 1")) }
            get("/reason-nul") { call.respond(HttpStatusCode(299, "a\u0000b")) }
            get("/reason-ok") { call.respond(HttpStatusCode(299, "Tr\u00e8s\tbien !")) }
            get("/304-stream-text") { call.respondBytesWriter(status = HttpStatusCode.NotModified) { writeStringUtf8("abc") } }
        }
    }

    /**
     * RFC 9110 section 8.6: a server MUST NOT send Content-Length in a 1xx or 204 response, nor (RFC 9112 section 6.1)
     * Transfer-Encoding; for a 304 Transfer-Encoding is not sent either, and Content-Length only when it equals the
     * length the 200 would have, which `Content-Length: 0` from Ktor's empty content does not say. Before, `respond(NoContent)`
     * went out with `Content-Length: 0`, and a streamed 204 or 304 with `Transfer-Encoding: chunked`. The next response
     * on the connection follows right after the head.
     */
    @Test fun negative_noFramingFieldsOn204And304() =
        serverTest {
            plainServer { port ->
                for (path in listOf("/204", "/204-stream", "/304", "/304-stream")) {
                    val resp =
                        withTimeout(10.seconds) {
                            rawHttp(
                                port,
                                "GET $path HTTP/1.1\r\nHost: s\r\n\r\nGET / HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n",
                                tls = null,
                            )
                        }
                    val head = resp.substringBefore("\r\n\r\n")
                    assertTrue(head.startsWith("HTTP/1.1 ${path.substring(1, 4)} "), "$path: $resp")
                    assertFalse(head.contains("Content-Length", ignoreCase = true), "$path: $resp")
                    assertFalse(head.contains("Transfer-Encoding", ignoreCase = true), "$path: $resp")
                    assertTrue(resp.substringAfter("\r\n\r\n").startsWith("HTTP/1.1 200 "), "$path: $resp")
                    assertTrue(resp.endsWith("root"), "$path: $resp")
                    if (path == "/304") assertTrue(head.contains("\r\nETag: \"v1\""), resp)
                }
            }
        }

    /**
     * RFC 9110 section 9.3.2: the server MUST NOT send content in the response to HEAD; a 1xx, 204 or 304 response has
     * none either (sections 15.2, 15.3.5, 15.4.5; RFC 9112 section 6.3 item 1). What the application writes for one is
     * dropped, the fields stay (a HEAD response keeps the Content-Length or Transfer-Encoding a GET would have). Before,
     * `head("/") { call.respondText("x") }` without AutoHeadResponse sent `x`, which a keep-alive client reads as the
     * start of the next response.
     */
    @Test fun negative_noContentForHeadAnd204And304() =
        serverTest {
            plainServer { port ->
                for ((request, field) in listOf(
                    "HEAD /head-text" to "Content-Length: 1",
                    "HEAD /head-stream" to "Transfer-Encoding: chunked",
                    "GET /204-text" to null,
                    "GET /304-text" to "Content-Length: 2",
                    "GET /304-stream-text" to null,
                )) {
                    val resp =
                        withTimeout(10.seconds) {
                            rawHttp(
                                port,
                                "$request HTTP/1.1\r\nHost: s\r\n\r\nGET / HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n",
                                tls = null,
                            )
                        }
                    val head = resp.substringBefore("\r\n\r\n")
                    if (field != null) assertTrue(head.contains("\r\n$field\r\n"), "$request: $resp")
                    assertTrue(resp.substringAfter("\r\n\r\n").startsWith("HTTP/1.1 200 "), "$request: $resp")
                    assertEquals(2, Regex("HTTP/1.1 ").findAll(resp).count(), "$request: $resp")
                    assertTrue(resp.endsWith("root"), "$request: $resp")
                }
            }
        }

    /**
     * RFC 9110 section 6.6.1: an origin server with a clock MUST generate a Date field in its 2xx, 3xx and 4xx responses
     * (and MAY in 5xx), in IMF-fixdate. Before, only the DefaultHeaders plugin added it, and the engine's own refusals
     * (400, 414, 431, 501, 505) had none. A Date the application set is kept, not doubled.
     */
    @Test fun responsesCarryDate() =
        serverTest {
            plainServer { port ->
                val imfFixdate =
                    Regex(
                        "\r\nDate: (Mon|Tue|Wed|Thu|Fri|Sat|Sun), \\d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \\d{4} \\d{2}:\\d{2}:\\d{2} GMT\r\n",
                    )
                for ((request, status) in listOf(
                    "GET / HTTP/1.1\r\nHost: s\r\n" to "200",
                    "GET /missing HTTP/1.1\r\nHost: s\r\n" to "404",
                    "GET /204 HTTP/1.1\r\nHost: s\r\n" to "204",
                    "GET / HTTP/1.1\r\nHost: s\r\nbad line\r\n" to "400",
                    "GET / HTTP/1.1\r\n" to "400",
                    "GET / HTTP/2.0\r\nHost: s\r\n" to "505",
                    "GET /${"a".repeat(9_000)} HTTP/1.1\r\nHost: s\r\n" to "414",
                    "POST / HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: gzip, chunked\r\n" to "501",
                    "GET / HTTP/1.1\r\nHost: s\r\n" + "X-P: ${"p".repeat(8_000)}\r\n".repeat(9) to "431",
                )) {
                    val resp = withTimeout(10.seconds) { rawHttp(port, "${request}Connection: close\r\n\r\n", tls = null) }
                    val head = resp.substringBefore("\r\n\r\n") + "\r\n"
                    assertTrue(head.startsWith("HTTP/1.1 $status "), "${request.take(40)}: $resp")
                    assertEquals(1, imfFixdate.findAll(head).count(), "${request.take(40)}: $resp")
                }
                val own =
                    withTimeout(10.seconds) { rawHttp(port, "GET /own-date HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n", tls = null) }
                assertEquals(1, Regex("\r\nDate: ").findAll(own).count(), own)
                assertTrue(own.contains("\r\nDate: Sun, 06 Nov 1994 08:49:37 GMT\r\n"), own)
            }
        }

    /**
     * reason-phrase = *( HTAB / SP / VCHAR / obs-text ) (RFC 9112 section 4). An application's status description with
     * another character (CR, LF, NUL) is replaced by the registered reason of its code, or none: a CR LF there split the
     * response (`X-Injected` became a field). A valid one, obs-text included (UTF-8), goes out as it is.
     */
    @Test fun negative_invalidReasonPhraseIsReplaced() =
        serverTest {
            plainServer { port ->
                for ((path, line) in listOf(
                    "/reason-crlf" to "HTTP/1.1 200 OK",
                    "/reason-nul" to "HTTP/1.1 299 ",
                    "/reason-ok" to "HTTP/1.1 299 Tr\u00e8s\tbien !",
                )) {
                    val resp =
                        withTimeout(10.seconds) { rawHttp(port, "GET $path HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n", tls = null) }
                    assertEquals(line, resp.substringBefore("\r\n"), "$path: $resp")
                    assertFalse(resp.contains("X-Injected"), "$path: $resp")
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
