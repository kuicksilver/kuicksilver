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
import io.ktor.server.routing.routing
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
