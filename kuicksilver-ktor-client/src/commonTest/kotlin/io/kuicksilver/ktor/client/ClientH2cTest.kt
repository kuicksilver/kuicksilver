// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.engine.ProxyBuilder
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.Url
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.application.install
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteReadChannel
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.runtime.H2ServerConnection
import io.kuicksilver.ktor.server.H2cMode
import io.kuicksilver.ktor.server.KuicksilverServerEventListener
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import io.ktor.server.websocket.WebSockets as ServerWebSockets
import io.ktor.server.websocket.webSocket as serverWebSocket

/**
 * h2c in the client engine (RFC 9113 section 3.3; ADR-0018): an `http://` origin listed in `http2 { priorKnowledge }`
 * goes over HTTP/2 on cleartext TCP, the preface at once; every other `http://` request stays HTTP/1.1, an `https://`
 * one negotiates by ALPN, and nothing falls back from a listed origin to HTTP/1.1. The server is the Kuicksilver engine on
 * a plain connector with h2c, or a plain HTTP/1.1 or TLS one for the negative cases.
 */
class ClientH2cTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** HTTP/2 connections the server opened (its event listener's count of `connectionOpened` with HTTP/2). */
    private val h2Opened = MutableStateFlow(0)
    private val calls = MutableStateFlow(0)

    private suspend fun h2cServer(mode: H2cMode = H2cMode.Only) =
        testServer(plain = true, configure = {
            connectors.clear()
            plainConnector {
                host = "127.0.0.1"
                port = 0
                h2c = mode
            }
            http3 = false
            eventListener =
                object : KuicksilverServerEventListener() {
                    override fun connectionOpened(
                        protocol: HttpProtocolVersion,
                        remote: io.ktor.network.sockets.InetSocketAddress?,
                    ) {
                        if (protocol == HttpProtocolVersion.HTTP_2_0) h2Opened.update { it + 1 }
                    }
                }
        }) {
            install(ServerWebSockets)
            routing {
                get("/") {
                    calls.update { it + 1 }
                    call.respondText("${call.request.httpVersion} ${call.request.local.scheme}")
                }
                serverWebSocket("/ws") {
                    val f = incoming.receive() as Frame.Text
                    send(Frame.Text("echo:" + f.readText() + " " + call.request.httpVersion))
                }
            }
        }

    private fun h2cClient(
        port: Int,
        block: io.ktor.client.HttpClientConfig<KuicksilverEngineConfig>.() -> Unit = {},
        engine: KuicksilverEngineConfig.() -> Unit = {},
    ) = testClient(engine = {
        http2 { priorKnowledge = setOf(HostPort("127.0.0.1", port)) }
        engine()
    }, block = block)

    @Test fun aListedHttpOriginGoesOverH2c() =
        clientTest {
            val (server, port) = h2cServer()
            try {
                h2cClient(port).use { c ->
                    val r = c.get("http://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                    assertEquals("HTTP/2 http", r.bodyAsText())
                    assertEquals(HttpProtocolVersion.HTTP_2_0, r.kuicksilverDiagnostics!!.protocol)
                    // RFC 9113 section 9.1: one connection, multiplexed
                    val all = coroutineScope { (1..20).map { async { c.get("http://127.0.0.1:$port/").bodyAsText() } }.awaitAll() }
                    assertEquals(List(20) { "HTTP/2 http" }, all)
                    assertEquals(1, h2Opened.value)
                    assertEquals(1, (c.engine as KuicksilverEngine).h1.h2.connectionCount)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** The same server takes HTTP/1.1 on the port ([H2cMode.WithHttp11]): an origin not listed stays HTTP/1.1. */
    @Test fun negative_anUnlistedHttpOriginStaysHttp11() =
        clientTest {
            val (server, port) = h2cServer(H2cMode.WithHttp11)
            try {
                testClient().use { c ->
                    val r = c.get("http://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                    assertEquals("HTTP/1.1 http", r.bodyAsText())
                }
                // listed for another port: still HTTP/1.1 here
                h2cClient(port + 1).use { c -> assertEquals(HttpProtocolVersion.HTTP_1_1, c.get("http://127.0.0.1:$port/").version) }
                // http2 { enabled = false } turns h2c off with the rest of HTTP/2
                h2cClient(port, engine = { http2 { enabled = false } }).use { c ->
                    assertEquals(HttpProtocolVersion.HTTP_1_1, c.get("http://127.0.0.1:$port/").version)
                }
                assertEquals(0, h2Opened.value)
            } finally {
                server.stop(100, 500)
            }
        }

    /** Section 3.3: over TLS, HTTP/2 only by ALPN. A listed host:port reached by `https://` negotiates (here: `http/1.1`). */
    @Test fun negative_httpsNeverUsesPriorKnowledge() =
        clientTest {
            val (server, port) = testServer(configure = { http3 = false }) { routing { get("/") { call.respondText("tls") } } }
            try {
                h2cClient(port).use { c ->
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                    assertEquals("tls", r.bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * No fallback from prior knowledge: a listed origin whose server speaks HTTP/1.1 only fails the call (its 505 to the
     * preface is no SETTINGS frame), and the request never reaches it as HTTP/1.1.
     */
    @Test fun negative_h2cToAnHttp11OnlyServerFails() =
        clientTest {
            val (server, port) = h2cServer(H2cMode.Off)
            try {
                h2cClient(port).use { c ->
                    assertFailsWith<Exception> { withTimeout(20.seconds) { c.get("http://127.0.0.1:$port/").bodyAsText() } }
                }
                assertEquals(0, calls.value)
            } finally {
                server.stop(100, 500)
            }
        }

    /** h2c to a TLS port: the preface is no ClientHello, the server's TLS handshake fails, and so does the call. */
    @Test fun negative_h2cToATlsPortFails() =
        clientTest {
            val (server, port) = testServer(configure = { http3 = false }) { routing { get("/") { calls.update { it + 1 } } } }
            try {
                h2cClient(port).use { c ->
                    assertFailsWith<Exception> { withTimeout(20.seconds) { c.get("http://127.0.0.1:$port/").bodyAsText() } }
                }
                assertEquals(0, calls.value)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * Threat model 3.18: an ALTSVC frame (RFC 7838 section 4) on an h2c connection is not heard: nothing authenticates a
     * cleartext server, and an `http` origin never learns an alternative (its `Alt-Svc` fields are not learned either).
     */
    @Test fun negative_altSvcFrameOverH2cIsNotLearned() =
        clientTest {
            val selector = SelectorManager(Dispatchers.IO)
            val (listener, port) = tcpOn(selector, 0)
            try {
                coroutineScope {
                    val serving =
                        launch {
                            listener.accept().use { s ->
                                coroutineScope {
                                    val output = s.openWriteChannel()
                                    val conn =
                                        H2ServerConnection.start(
                                            s.openReadChannel(),
                                            output,
                                            Http2Settings(),
                                            this,
                                            closeTransport = { s.close() },
                                        )
                                    for (r in conn.requests) {
                                        r.altSvc("h3=\":$port\"; ma=3600")
                                        r.respond(200, listOf("content-type" to "text/plain"))
                                        r.sendBody(ByteReadChannel("ok".encodeToByteArray()))
                                        r.release()
                                    }
                                }
                            }
                        }
                    h2cClient(port, engine = { http3 { discovery = Http3DiscoveryMode.Auto } }).use { c ->
                        val r = c.get("http://127.0.0.1:$port/")
                        assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                        assertEquals("ok", r.bodyAsText())
                        val engine = c.engine as KuicksilverEngine
                        assertEquals(0L, engine.altSvcFramesReceived)
                        assertTrue(engine.altSvcSnapshot(Url("http://127.0.0.1:$port/")).isEmpty())
                        assertTrue(engine.altSvcSnapshot(Url("https://127.0.0.1:$port/")).isEmpty())
                    }
                    serving.cancel()
                }
            } finally {
                listener.close()
                selector.close()
            }
        }

    /**
     * Through an HTTP proxy, h2c goes in a CONNECT tunnel (an absolute-form request is HTTP/1.1; OkHttp's
     * `Route.requiresTunnel` does the same for `H2_PRIOR_KNOWLEDGE`).
     */
    @Test fun h2cThroughAnHttpProxyUsesConnect() =
        clientTest {
            val (server, port) = h2cServer()
            try {
                ClientProxyTest().tunnelProxy(port) { proxyPort, head ->
                    h2cClient(port, engine = { proxy = ProxyBuilder.http(Url("http://127.0.0.1:$proxyPort")) }).use { c ->
                        val r = c.get("http://127.0.0.1:$port/")
                        assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                        assertEquals("HTTP/2 http", r.bodyAsText())
                    }
                    assertTrue(head().first().startsWith("CONNECT 127.0.0.1:$port "), "${head()}")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 8441 over h2c: a `ws://` WebSocket to a listed origin goes as an Extended CONNECT (`:scheme http`, section 5) on
     * the h2c connection that is open and allows it.
     */
    @Test fun webSocketOverH2c() =
        clientTest {
            val (server, port) = h2cServer()
            try {
                h2cClient(port, block = { install(WebSockets) }).use { c ->
                    assertEquals(HttpProtocolVersion.HTTP_2_0, c.get("http://127.0.0.1:$port/").version)
                    var version: HttpProtocolVersion? = null
                    var echo = ""
                    withTimeout(20.seconds) {
                        c.webSocket("ws://127.0.0.1:$port/ws") {
                            version = call.response.version
                            send(Frame.Text("hi"))
                            echo = (incoming.receive() as Frame.Text).readText()
                        }
                    }
                    assertEquals(HttpProtocolVersion.HTTP_2_0, version)
                    assertEquals("echo:hi HTTP/2", echo)
                    assertEquals(1, h2Opened.value)
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
