// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.plugins.HttpRedirect
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.application.install
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.kuicksilver.ktor.server.priorityUpdates
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import io.ktor.server.websocket.WebSockets as ServerWebSockets
import io.ktor.server.websocket.webSocket as serverWebSocket
import io.kuicksilver.ktor.server.priority as serverPriority

/** RFC 9218 priorities from the Ktor client: `priority(...)` on a request, `updatePriority` on its response. */
class ClientPriorityTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private suspend fun fieldServer(http3: Boolean = true) =
        testServer(configure = { this.http3 = http3 }) {
            routing { get("/f") { call.respondText("${call.request.headers.getAll("priority")}") } }
        }

    @Test fun priorityAttributeSentOverH3() =
        h3Test {
            val (server, port) = fieldServer()
            try {
                testClient(Http3DiscoveryMode.H3Only).use { c ->
                    val r = c.get("https://127.0.0.1:$port/f") { priority(1, incremental = true) }
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertEquals("[u=1, i]", r.bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun priorityDefaultSendsNoField() =
        h3Test {
            val (server, port) = fieldServer()
            try {
                testClient(Http3DiscoveryMode.H3Only).use { c ->
                    assertEquals("null", c.get("https://127.0.0.1:$port/f") { priority() }.bodyAsText())
                    assertEquals("null", c.get("https://127.0.0.1:$port/f").bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** The attribute replaces a raw `Priority` header: one signal, the one the stream is scheduled with. */
    @Test fun attributeWinsOverRawHeader() =
        h3Test {
            val (server, port) = fieldServer()
            try {
                testClient(Http3DiscoveryMode.H3Only).use { c ->
                    val r =
                        c.get("https://127.0.0.1:$port/f") {
                            header("Priority", "u=5")
                            priority(1)
                            assertEquals(StreamPriority(1), priority)
                        }
                    assertEquals("[u=1]", r.bodyAsText())
                }
                testClient().use { c ->
                    val r =
                        c.get("https://127.0.0.1:$port/f") {
                            header("Priority", "u=5")
                            priority()
                        }
                    assertEquals("null", r.bodyAsText()) // the default signal is no field, over h1 as well
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun priorityOnH1SendsFieldOnly() =
        clientTest {
            val (server, port) = fieldServer(http3 = false)
            try {
                testClient().use { c ->
                    val r =
                        c.get("https://127.0.0.1:$port/f") {
                            assertNull(priority)
                            priority(1, incremental = true)
                        }
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                    assertEquals("[u=1, i]", r.bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun updatePriorityReachesServer() =
        h3Test {
            val (server, port) =
                testServer {
                    routing {
                        get("/u") {
                            call.respondBytesWriter {
                                flush() // the headers go out, so the client holds a response to update
                                withTimeout(5.seconds) { call.request.priorityUpdates.first { it == StreamPriority(6) } }
                                writeStringUtf8("updated")
                            }
                        }
                        get("/f") { call.respondText("ok") }
                    }
                }
            try {
                testClient(Http3DiscoveryMode.H3Only).use { c ->
                    val done =
                        c.prepareGet("https://127.0.0.1:$port/u") { priority(1) }.execute { r ->
                            assertTrue(r.updatePriority(6, incremental = false))
                            assertEquals("updated", r.bodyAsText())
                            r
                        }
                    assertFalse(done.updatePriority(5, incremental = false), "the exchange is over")
                }
                testClient().use { c ->
                    c.prepareGet("https://127.0.0.1:$port/f").execute { r ->
                        assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                        assertFalse(r.updatePriority(6, incremental = false), "no PRIORITY_UPDATE over HTTP/1.1")
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** The HTTP/1.1 hop of a redirect never updates the HTTP/3 stream of the hop before it. */
    @Test fun updatePriorityAfterRedirectToH1IsFalse() =
        h3Test {
            val (plain, plainPort) = testServer(plain = true) { routing { get("/f") { call.respondText("ok") } } }
            val (server, port) =
                testServer {
                    routing { get("/r") { call.respondRedirect("http://127.0.0.1:$plainPort/f") } }
                }
            try {
                testClient(Http3DiscoveryMode.Preferred, block = { install(HttpRedirect) { allowHttpsDowngrade = true } }).use { c ->
                    c.prepareGet("https://127.0.0.1:$port/r") { priority(1) }.execute { r ->
                        assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                        assertEquals("ok", r.bodyAsText())
                        assertFalse(r.updatePriority(6, incremental = false), "no PRIORITY_UPDATE on the redirect's HTTP/3 stream")
                    }
                }
            } finally {
                server.stop(100, 500)
                plain.stop(100, 500)
            }
        }

    @Test fun negative_priorityUrgencyOutOfRange() =
        clientTest {
            testClient().use { c ->
                val (server, port) = fieldServer(http3 = false)
                try {
                    assertFailsWith<IllegalArgumentException> { c.get("https://127.0.0.1:$port/f") { priority(8) } }
                    assertFailsWith<IllegalArgumentException> { c.get("https://127.0.0.1:$port/f") { priority(-1) } }
                } finally {
                    server.stop(100, 500)
                }
            }
        }

    @Test fun webSocketCarriesPriority() =
        h3Test {
            val (server, port) =
                testServer {
                    install(ServerWebSockets)
                    routing { serverWebSocket("/ws") { send(Frame.Text("${call.request.serverPriority}")) } }
                }
            try {
                testClient(Http3DiscoveryMode.H3Only, block = { install(WebSockets) }).use { c ->
                    c.webSocket("wss://127.0.0.1:$port/ws", request = { priority(2) }) {
                        val f = withTimeout(5.seconds) { incoming.receive() } as Frame.Text
                        assertEquals("${StreamPriority(2)}", f.readText())
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
