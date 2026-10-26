// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.http3Request
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlinx.io.readString
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** RFC 9218 priorities through Ktor: `call.request.priority`, `priorityUpdates`, `call.response.priority(...)`. */
class ServerPriorityTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private suspend fun <T> h3(
        port: Int,
        block: suspend (Http3Connection) -> T,
    ): T {
        val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
        try {
            val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
            try {
                return block(c)
            } finally {
                c.close()
            }
        } finally {
            ep.close()
        }
    }

    private fun get(
        path: String,
        vararg fields: Pair<String, String>,
    ) = http3Request("GET", "server.test", path) { headers = Http3Headers(fields.toList()) }

    private suspend fun Http3Connection.text(
        path: String,
        vararg fields: Pair<String, String>,
    ): String = withTimeout(5.seconds) { request(get(path, *fields)).body.readBuffer().readString() }

    @Test fun requestPriorityFromField() =
        h3ServerTest {
            val (server, port) = tlsServer { routing { get("/p") { call.respondText("${call.request.priority}") } } }
            try {
                h3(port) { c -> assertEquals("${StreamPriority(1, true)}", c.text("/p", "priority" to "u=1, i")) }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /** A PRIORITY_UPDATE after the response started reaches the handler through [priorityUpdates]. */
    @Test fun requestPriorityFollowsUpdate() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/u") {
                            call.respondBytesWriter {
                                flush() // the headers go out, so the client holds a response to update
                                val p = withTimeout(5.seconds) { call.request.priorityUpdates.first { it.urgency == 6 } }
                                writeStringUtf8("${p.urgency}")
                            }
                        }
                    }
                }
            try {
                h3(port) { c ->
                    val resp = withTimeout(5.seconds) { c.request(get("/u")) }
                    resp.updatePriority(StreamPriority(6))
                    assertEquals("6", withTimeout(5.seconds) { resp.body.readBuffer().readString() })
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /**
     * `call.response.priority(urgency = 0)` sends only `u=0` (RFC 9218 section 8): the client sees that field, and the
     * handler's view of the client's signal is untouched. The merge into the server's own scheduling is kuicksilver-http3's
     * (PriorityTest.responseFieldMergesIntoServerScheduling).
     */
    @Test fun responsePriorityAppliedLocally() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/r") {
                            call.response.priority(urgency = 0)
                            call.respondText("${call.request.priority}")
                        }
                        get("/i") {
                            call.response.priority(incremental = false)
                            call.respondText("ok")
                        }
                    }
                }
            try {
                h3(port) { c ->
                    val resp = withTimeout(5.seconds) { c.request(get("/r", "priority" to "u=5, i")) }
                    assertEquals(listOf("u=0"), resp.headers.getAll("priority"))
                    assertEquals("${StreamPriority(5, true)}", withTimeout(5.seconds) { resp.body.readBuffer().readString() })
                    val inc = withTimeout(5.seconds) { c.request(get("/i")) }
                    assertEquals(listOf("i=?0"), inc.headers.getAll("priority"))
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun requestPriorityOverH1() =
        serverTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/p") {
                            call.response.priority(urgency = 1, incremental = true)
                            call.respondText("${call.request.priority}|${call.request.priorityUpdates.value}")
                        }
                    }
                }
            try {
                val resp = rawHttp(port, "GET /p HTTP/1.1\r\nHost: s\r\nPriority: u=2\r\nConnection: close\r\n\r\n")
                assertTrue(resp.endsWith("${StreamPriority(2)}|${StreamPriority(2)}"), resp)
                assertTrue(resp.lowercase().contains("\r\npriority: u=1, i\r\n"), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    /** A garbled field reads as the defaults (RFC 9218 section 4) and the request is served all the same. */
    @Test fun negative_priorityFieldGarbageIsDefault() =
        h3ServerTest {
            val (server, port) = tlsServer { routing { get("/p") { call.respondText("${call.request.priority}") } } }
            try {
                h3(port) { c -> assertEquals("${StreamPriority.Default}", c.text("/p", "priority" to "u=99, i=7, ;;")) }
                val h1 = rawHttp(port, "GET /p HTTP/1.1\r\nHost: s\r\nPriority: u=99, i=7, ;;\r\nConnection: close\r\n\r\n")
                assertTrue(h1.startsWith("HTTP/1.1 200") && h1.endsWith("${StreamPriority.Default}"), h1)
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun negative_responsePriorityArguments() =
        serverTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/bad") {
                            val range = assertFailsWith<IllegalArgumentException> { call.response.priority(urgency = 8) }
                            val none = assertFailsWith<IllegalArgumentException> { call.response.priority() }
                            call.response.priority(urgency = 1)
                            val twice = assertFailsWith<IllegalStateException> { call.response.priority(urgency = 2) }
                            call.respondText(listOf(range, none, twice).joinToString("|") { it::class.simpleName.orEmpty() })
                        }
                    }
                }
            try {
                val resp = rawHttp(port, "GET /bad HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n")
                assertTrue(resp.endsWith("IllegalArgumentException|IllegalArgumentException|IllegalStateException"), resp)
            } finally {
                server.stop(100, 500)
            }
        }
}
