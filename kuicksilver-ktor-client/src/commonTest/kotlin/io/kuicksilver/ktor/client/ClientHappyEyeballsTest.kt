// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class, io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.server.application.install
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.kuicksilver.ktor.network.TcpAddress
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource
import io.ktor.server.websocket.WebSockets as ServerWebSockets
import io.ktor.server.websocket.webSocket as serverWebSocket

/** Happy Eyeballs (RFC 8305) through the engine: the per-family resolution and the address race of TCP and QUIC. */
class ClientHappyEyeballsTest {
    private val loopback6 = TcpAddress(ByteArray(16).also { it[15] = 1 }, 0)
    private val loopback4 = TcpAddress(byteArrayOf(127, 0, 0, 1), 0)

    /**
     * HTTP/3 races the addresses as TCP does: the first address (IPv6 first, RFC 6724) never answers QUIC, the second one
     * starts one connection attempt delay later and wins. Before, HTTP/3 connected to the first address only, and with
     * `H3Only` (no TCP to fall back to) the request failed at the connect timeout.
     */
    @Test fun h3RacesTheAddressesOfAName() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("v=${call.request.local.version}") } } }
            val selector = SelectorManager(Dispatchers.IO)
            // the first address swallows QUIC where the host has IPv6 loopback; elsewhere a connect to it fails at once
            val silent = runCatching { aSocket(selector).udp().bind(InetSocketAddress("::1", port)) }.getOrNull()
            try {
                testClient(Http3DiscoveryMode.H3Only, engine = {
                    connectTimeout = 20.seconds
                    familyResolverForTest = { _, v6 -> listOf(if (v6) loopback6 else loopback4) }
                }).use { c ->
                    val start = TimeSource.Monotonic.markNow()
                    val r = c.get("https://server.test:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertEquals("v=HTTP/3", r.bodyAsText())
                    assertTrue(start.elapsedNow() < 10.seconds, "${start.elapsedNow()}")
                }
            } finally {
                silent?.close()
                selector.close()
                server.stop(100, 500)
            }
        }

    /**
     * RFC 8305 section 3: an A answer does not wait for a AAAA answer that never comes beyond the Resolution Delay, and the
     * IPv4 connection is made while the AAAA query is still out.
     */
    @Test fun negative_aStalledAaaaQueryDoesNotHoldTheConnection() =
        clientTest {
            val (server, port) = testServer(plain = true) { routing { get("/") { call.respondText("ok") } } }
            val never = CompletableDeferred<Unit>()
            val asked = MutableStateFlow(emptySet<Boolean>())
            try {
                testClient(engine = {
                    connectTimeout = 20.seconds
                    familyResolverForTest = { _, v6 ->
                        asked.update { it + v6 }
                        if (v6) never.await()
                        listOf(loopback4)
                    }
                }).use { c ->
                    val start = TimeSource.Monotonic.markNow()
                    assertEquals("ok", c.get("http://origin.test:$port/").bodyAsText())
                    assertTrue(start.elapsedNow() < 10.seconds, "${start.elapsedNow()}")
                }
                assertEquals(setOf(true, false), asked.value)
            } finally {
                never.complete(Unit)
                server.stop(100, 500)
            }
        }

    private suspend fun echoServer() =
        testServer {
            install(ServerWebSockets)
            routing {
                serverWebSocket("/ws") {
                    for (f in incoming) if (f is Frame.Text) send(Frame.Text("echo:" + f.readText()))
                }
            }
        }

    /** A WebSocket's CONNECTING lock (RFC 6455 section 4.1) is keyed by the families that answered: [discovery]'s. */
    private suspend fun webSocketWithAStalledAaaa(discovery: Http3DiscoveryMode) {
        val (server, port) = echoServer()
        val never = CompletableDeferred<Unit>()
        try {
            testClient(discovery, engine = {
                connectTimeout = 20.seconds
                familyResolverForTest = { _, v6 ->
                    if (v6) never.await()
                    listOf(loopback4)
                }
            }, block = { install(WebSockets) }).use { c ->
                val start = TimeSource.Monotonic.markNow()
                c.webSocket("wss://server.test:$port/ws") {
                    send(Frame.Text("hi"))
                    assertEquals("echo:hi", (incoming.receive() as Frame.Text).readText())
                }
                assertTrue(start.elapsedNow() < 10.seconds, "${start.elapsedNow()}")
            }
        } finally {
            never.complete(Unit)
            server.stop(100, 500)
        }
    }

    /** Over HTTP/1.1: the keys came from both families, so a stalled AAAA cost the connect timeout (a failure). */
    @Test fun negative_aWebSocketOverH1DoesNotWaitForAStalledAaaa() = clientTest { webSocketWithAStalledAaaa(Http3DiscoveryMode.H1Only) }

    /** Over HTTP/3: the keys came from both families outside any timeout, so a stalled AAAA held the WebSocket for good. */
    @Test fun negative_aWebSocketOverH3DoesNotWaitForAStalledAaaa() = h3Test { webSocketWithAStalledAaaa(Http3DiscoveryMode.H3Only) }
}
