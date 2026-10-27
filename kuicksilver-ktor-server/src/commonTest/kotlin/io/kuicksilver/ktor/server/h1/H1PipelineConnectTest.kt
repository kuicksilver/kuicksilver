// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.ktor.server.rawHttp
import io.kuicksilver.ktor.server.serverTest
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
 * RFC 9931 section 8 (updating RFC 9112): a server MUST close the connection when it rejects a CONNECT request, without
 * processing any further request on it, whether or not the request said `close`. A client that sends bytes for the
 * tunnel right behind its CONNECT (optimistically) would otherwise have them executed as its next request.
 */
@OptIn(ExperimentalAtomicApi::class)
class H1PipelineConnectTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val uploads = AtomicInt(0)

    /**
     * CONNECT answered 407, 504, 500 (a throwing handler) or Ktor's 404 (no route), with a POST behind it in the same
     * write: exactly one response, which says `Connection: close`, then EOF; the POST handler never runs. Before, the
     * connection stayed open and the POST was served as the client's next request (request smuggling, RFC 9931 section
     * 4.1).
     */
    @Test fun negative_refusedConnectEndsTheConnection() =
        serverTest {
            val server =
                embeddedServer(Kuicksilver, configure = {
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                }) {
                    intercept(ApplicationCallPipeline.Plugins) {
                        if (call.request.local.method.value == "CONNECT") {
                            when (call.request.local.uri) {
                                "a.example:443" -> {
                                    call.response.header(HttpHeaders.ProxyAuthenticate, "Basic")
                                    call.respond(HttpStatusCode.ProxyAuthenticationRequired)
                                    finish()
                                }

                                "b.example:443" -> {
                                    call.respond(HttpStatusCode.GatewayTimeout)
                                    finish()
                                }

                                "c.example:443" -> {
                                    error("the tunnel failed")
                                }
                            }
                        }
                    }
                    routing {
                        post("/upload") {
                            uploads.incrementAndFetch()
                            call.respondText("uploaded")
                        }
                    }
                }
            server.startSuspend(false)
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                for ((target, status) in listOf(
                    "a.example:443" to "407",
                    "b.example:443" to "504",
                    "c.example:443" to "500",
                    "no-such-destination.example:443" to "404",
                )) {
                    val resp =
                        withTimeout(10.seconds) {
                            rawHttp(
                                port,
                                "CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n" +
                                    "POST /upload HTTP/1.1\r\nHost: s\r\nContent-Length: 5\r\n\r\nhello",
                                tls = null,
                            )
                        }
                    val head = resp.substringBefore("\r\n\r\n") + "\r\n"
                    assertTrue(head.startsWith("HTTP/1.1 $status "), "$target: $resp")
                    assertTrue(head.contains("\r\nConnection: close\r\n"), "$target: $resp")
                    assertEquals(1, Regex("HTTP/1.1 ").findAll(resp).count(), "$target: $resp")
                    assertFalse(resp.contains("uploaded"), "$target: $resp")
                }
                assertEquals(0, uploads.load())
            } finally {
                server.stop(100, 500)
            }
        }
}
