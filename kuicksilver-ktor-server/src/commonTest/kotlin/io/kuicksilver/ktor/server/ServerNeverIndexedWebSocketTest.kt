// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.ktor.client.neverIndex
import io.kuicksilver.ktor.client.neverIndexedHeaders
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds
import io.ktor.client.plugins.websocket.WebSockets as ClientWebSockets
import io.ktor.client.plugins.websocket.webSocket as clientWebSocket
import io.kuicksilver.ktor.client.Kuicksilver as KuicksilverClient

/**
 * RFC 7541 sections 6.2.3 and 7.1.3 (HTTP/2) and RFC 9204 sections 4.5.4 and 7.1.3 (HTTP/3) on a WebSocket's Extended
 * CONNECT (RFC 8441, RFC 9220), both engines: a field the client marks with `neverIndex` reaches the server's call as never
 * indexed, a plain one does not; a field the server marks on the handshake's answer reaches the client's response so.
 */
class ServerNeverIndexedWebSocketTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** What the server's WebSocket saw as never indexed, and what the client's handshake response reported. */
    private suspend fun exchange(
        port: Int,
        discovery: Http3DiscoveryMode,
        version: HttpProtocolVersion,
    ): Pair<String, List<Pair<String, String>>> {
        val client =
            HttpClient(KuicksilverClient) {
                install(ClientWebSockets)
                engine {
                    trust = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa)))
                    http3 { this.discovery = discovery }
                }
            }
        try {
            var seen = ""
            var received = emptyList<Pair<String, String>>()
            withTimeout(10.seconds) {
                // a WebSocket goes over HTTP/2 on a connection the client already has to the server (RFC 8441 section 3)
                if (version == HttpProtocolVersion.HTTP_2_0) assertEquals(version, client.get("https://127.0.0.1:$port/").version)
                client.clientWebSocket("wss://127.0.0.1:$port/ws", {
                    neverIndex("X-Secret")
                    header("x-secret", "s1")
                    header("x-plain", "p1")
                }) {
                    assertEquals(version, call.response.version)
                    received = call.response.neverIndexedHeaders
                    seen = (incoming.receive() as Frame.Text).readText()
                }
            }
            return seen to received
        } finally {
            client.close()
        }
    }

    private fun io.ktor.server.application.Application.marking() {
        install(WebSockets)
        routing {
            get("/") { call.respondText("ok") }
            route("/ws") {
                intercept(ApplicationCallPipeline.Plugins) {
                    call.response.neverIndex("X-Reply")
                    call.response.headers.append("x-reply", "r1")
                    call.response.headers.append("x-open", "o1")
                }
                webSocket {
                    send(Frame.Text(call.request.neverIndexedHeaders.joinToString(";") { "${it.first}=${it.second}" }))
                }
            }
        }
    }

    @Test fun clientMarkedFieldReachesTheServerNeverIndexedOverH2() =
        serverTest {
            val (server, port) = h2TlsServer { marking() }
            try {
                assertEquals("x-secret=s1", exchange(port, Http3DiscoveryMode.H1Only, HttpProtocolVersion.HTTP_2_0).first)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun serverMarkedFieldReachesTheClientNeverIndexedOverH2() =
        serverTest {
            val (server, port) = h2TlsServer { marking() }
            try {
                assertEquals(listOf("x-reply" to "r1"), exchange(port, Http3DiscoveryMode.H1Only, HttpProtocolVersion.HTTP_2_0).second)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun clientMarkedFieldReachesTheServerNeverIndexedOverH3() =
        h3ServerTest {
            val (server, port) = tlsServer { marking() }
            try {
                assertEquals("x-secret=s1", exchange(port, Http3DiscoveryMode.H3Only, HttpProtocolVersion.HTTP_3_0).first)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun serverMarkedFieldReachesTheClientNeverIndexedOverH3() =
        h3ServerTest {
            val (server, port) = tlsServer { marking() }
            try {
                assertEquals(listOf("x-reply" to "r1"), exchange(port, Http3DiscoveryMode.H3Only, HttpProtocolVersion.HTTP_3_0).second)
            } finally {
                server.stop(100, 500)
            }
        }
}
