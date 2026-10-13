// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.Application
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3Request
import io.kuicksilver.native.KslLoader
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * `Early-Data: 1` from a gateway that forwarded a request it received in early data (RFC 8470 section 5.1): the request
 * may be a replay, whatever the TLS state of this hop. `receivedEarly` says so, and a request the early-data policy does
 * not declare replayable is answered with 425 Too Early (waiting for this hop's handshake cannot make it safe).
 */
class ServerEarlyDataHeaderTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private var unsafeCalls = 0

    private val routes: Application.() -> Unit = {
        routing {
            get("/e") { call.respondText("early=${call.request.receivedEarly}") }
            post("/p") {
                unsafeCalls++
                call.respondText("processed")
            }
        }
    }

    @Test fun gatewayMarkedGetIsReceivedEarlyOverH1() =
        serverTest {
            val (server, port) = tlsServer(module = routes)
            try {
                val plain = rawHttp(port, "GET /e HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n")
                assertTrue(plain.endsWith("early=false"), plain)
                val marked = rawHttp(port, "GET /e HTTP/1.1\r\nHost: s\r\nEarly-Data: 1\r\nConnection: close\r\n\r\n")
                assertTrue(marked.endsWith("early=true"), marked)
                // "Multiple or invalid instances of the header field MUST be treated as equivalent to a single instance with a value of 1"
                val invalid = rawHttp(port, "GET /e HTTP/1.1\r\nHost: s\r\nEarly-Data: 0\r\nConnection: close\r\n\r\n")
                assertTrue(invalid.endsWith("early=true"), invalid)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun negative_gatewayMarkedPostIsTooEarlyOverH1() =
        serverTest {
            val (server, port) = tlsServer(module = routes)
            try {
                val resp =
                    rawHttp(port, "POST /p HTTP/1.1\r\nHost: s\r\nEarly-Data: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                assertTrue(resp.startsWith("HTTP/1.1 425"), resp)
                assertEquals(0, unsafeCalls, "the application processed a request that may be a replay")
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun negative_gatewayMarkedRequestsOverH3() =
        h3ServerTest {
            val (server, port) = tlsServer(module = routes)
            try {
                val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
                try {
                    val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                    try {
                        val early = Http3Headers(listOf("early-data" to "1"))
                        val get = c.request(Http3Request("GET", authority = "server.test", path = "/e", headers = early))
                        assertEquals("early=true", get.body.readFullBody().decodeToString())
                        val post = c.request(Http3Request("POST", authority = "server.test", path = "/p", headers = early))
                        assertEquals(425, post.status)
                        post.body.readFullBody()
                        assertEquals(0, unsafeCalls, "the application processed a request that may be a replay")
                    } finally {
                        c.close()
                    }
                } finally {
                    ep.close()
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
