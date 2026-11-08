// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.HttpClientEngineFactory
import io.ktor.client.engine.ProxyBuilder
import io.ktor.client.engine.http
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.api.createClientPlugin
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.get
import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.discard
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.ktor.server.peerCertificates
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.qlog.AsyncQlogSink
import io.kuicksilver.quic.qlog.DirectoryQlogSink
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.io.readString
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import io.ktor.server.websocket.WebSockets as ServerWebSockets
import io.ktor.server.websocket.webSocket as serverWebSocket
import io.kuicksilver.ktor.server.Kuicksilver as KuicksilverServer
import io.kuicksilver.ktor.server.webTransport as webTransportRoute

/** The client code blocks of docs/guide/ktor.md, kept compiling and running (block markers `guide:ktor:client*`). */
class GuideSamplesTest {
    @Test fun guideHasEveryMarker() {
        val guide =
            generateSequence(File("").absoluteFile) {
                it.parentFile
            }.map { File(it, "docs/guide/ktor.md") }.first { it.exists() }.readText()
        assertTrue("guide:ktor:client" in guide, "marker client")
        assertTrue("guide:ktor:minimal-client" in guide, "marker minimal-client")
        assertTrue("guide:ktor:pool" in guide, "marker pool")
        assertTrue("guide:ktor:webtransport-client" in guide, "marker webtransport-client")
        assertTrue("guide:ktor:priority-client" in guide, "marker priority-client")
        assertTrue("guide:ktor:proxy" in guide, "marker proxy")
        assertTrue("guide:ktor:websocket-deflate-client" in guide, "marker websocket-deflate-client")
        assertTrue("guide:ktor:client-diagnostics" in guide, "marker client-diagnostics")
        assertTrue("guide:ktor:http3-switch" in guide, "marker http3-switch")
        assertTrue("guide:ktor:http2-client" in guide, "marker http2-client")
        assertTrue("guide:ktor:mtls-client" in guide, "marker mtls-client")
        assertTrue("guide:ktor:protocol-log" in guide, "marker protocol-log")
    }

    @Test fun diagnosticsSample() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            val url = "https://127.0.0.1:$port/"
            try {
                HttpClient(Kuicksilver) { engine { trust = ClientFixtures.trust } }.use { client ->
                    // guide:ktor:client-diagnostics
                    val response = client.get(url)
                    val d = response.kuicksilverDiagnostics
                    if (d != null && d.protocol != HttpProtocolVersion.HTTP_3_0) {
                        println("HTTP/3 not used: ${d.fallback} (alternative ${d.alternative} via ${d.alternativeSource})")
                    }

                    assertEquals(FallbackReason.NoAlternative, d?.fallback)
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun http3SwitchSample() =
        clientTest {
            val remoteConfig = MutableStateFlow(true)
            // guide:ktor:http3-switch
            val quicAllowed: StateFlow<Boolean> = remoteConfig
            val client =
                HttpClient(Kuicksilver) {
                    engine { http3 { http3Allowed = { quicAllowed.value } } }
                }
            client.closeHttp3Connections()

            client.use { c ->
                remoteConfig.value = false
                val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
                try {
                    // the guide's client with the test trust: switched off, a Preferred request goes over HTTP/1.1
                    HttpClient(Kuicksilver) {
                        engine {
                            trust = ClientFixtures.trust
                            http3 {
                                discovery = Http3DiscoveryMode.Preferred
                                http3Allowed = { quicAllowed.value }
                            }
                        }
                    }.use { t -> assertEquals(HttpProtocolVersion.HTTP_1_1, t.get("https://127.0.0.1:$port/").version) }
                } finally {
                    server.stopSuspend(100, 1000)
                }
                assertTrue(c.engine is KuicksilverEngine)
            }
        }

    @Test fun webSocketDeflateSample() =
        clientTest {
            // guide:ktor:websocket-deflate-client
            val client =
                HttpClient(Kuicksilver) {
                    install(WebSockets) { extensions { install(PerMessageDeflate) } }
                }

            val (server, port) =
                testServer(plain = true) {
                    install(ServerWebSockets) { extensions { install(PerMessageDeflate) } }
                    routing { serverWebSocket("/ws") { send(Frame.Text(call.request.headers["Sec-WebSocket-Extensions"] ?: "none")) } }
                }
            try {
                client.use { c ->
                    c.webSocket("ws://127.0.0.1:$port/ws") {
                        assertEquals("permessage-deflate", (incoming.receive() as Frame.Text).readText())
                    }
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun observabilityAndZeroRttSamples() {
        // guide:ktor:client-observability
        val observed =
            HttpClient(Kuicksilver) {
                engine {
                    eventListener =
                        object : KuicksilverEventListener() {
                            override fun protocolSelected(
                                request: HttpRequestData,
                                protocol: HttpProtocolVersion,
                                reason: ProtocolReason,
                            ) {
                                println("${request.url}: $protocol ($reason)")
                            }
                        }
                    http3 { qlog = AsyncQlogSink(DirectoryQlogSink("qlog")) }
                }
            }
        observed.close()
        // guide:ktor:zero-rtt-client
        val client =
            HttpClient(Kuicksilver) {
                engine { http3 { earlyData = true } }
            }
        client.close()
    }

    @Test fun webTransportClientSample() =
        h3Test {
            val (server, port) =
                testServer(configure = { webTransport = true }) {
                    routing {
                        webTransportRoute("/echo", protocols = listOf("echo-v1")) { s ->
                            val st = s.acceptBidi()
                            st.input.copyTo(st.output)
                            st.output.flushAndClose()
                            s.closed.await()
                        }
                    }
                }
            try {
                testClient(Http3DiscoveryMode.Auto).use { client ->
                    val url = "https://127.0.0.1:$port/echo"
                    // guide:ktor:webtransport-client
                    val session = client.webTransport(url, protocols = listOf("echo-v1"))
                    val stream = session.openBidi()
                    stream.output.writeFully("ping".encodeToByteArray())
                    stream.output.flushAndClose()
                    println(stream.input.readBuffer().readString())
                    session.close(0, "done")
                    assertEquals("echo-v1", session.protocol)
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun priorityClientSample() =
        h3Test {
            val (server, port) =
                testServer {
                    routing {
                        get("/index.html") { call.respondText("${call.request.headers["priority"]}") }
                        get("/video.mp4") { call.respondText("video") }
                    }
                }
            try {
                testClient(Http3DiscoveryMode.H3Only).use { client ->
                    val origin = "https://127.0.0.1:$port"
                    // guide:ktor:priority-client
                    val page = client.get("$origin/index.html") { priority(urgency = 1) }
                    client.prepareGet("$origin/video.mp4") { priority(urgency = 5, incremental = true) }.execute { response ->
                        response.updatePriority(urgency = 2, incremental = true) // now in view: more urgent
                        response.bodyAsChannel().discard()
                    }
                    assertEquals("u=1", page.bodyAsText())
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun proxySample() =
        clientTest {
            // guide:ktor:proxy
            val password = System.getenv("PROXY_PASSWORD") ?: ""
            // one proxy for everything, with credentials for it
            val viaProxy =
                HttpClient(Kuicksilver) {
                    engine {
                        proxy = ProxyBuilder.http("http://proxy.corp.test:3128")
                        proxyCredentials = ProxyCredentials("user", password) // for `proxy` only
                    }
                }
            // a resolver of your own: its proxy carries its own credentials (ProxyResolvers.Environment takes them from https_proxy)
            val perHost =
                HttpClient(Kuicksilver) {
                    engine {
                        proxyResolver =
                            ProxyResolver { url ->
                                if (url.host.endsWith(".internal.test")) {
                                    null // direct
                                } else {
                                    ResolvedProxy.http("proxy.corp.test", 3128, ProxyCredentials("user", password))
                                }
                            }
                    }
                }
            viaProxy.close()
            perHost.use {
                val resolver = (it.engine as KuicksilverEngine).config.proxyResolver
                assertEquals(null, resolver.proxyFor(io.ktor.http.Url("https://a.internal.test/")))
                assertEquals("user", resolver.proxyFor(io.ktor.http.Url("https://example.test/"))?.credentials?.user)
            }
        }

    @Test
    fun poolSample() {
        // guide:ktor:pool
        val client =
            HttpClient(Kuicksilver) {
                engine {
                    maxConnectionsCount = 1000 // TCP connections (HTTP/1.1, HTTP/2) of the engine, idle ones included
                    maxConnectionsPerRoute = 100 // ... to one route (scheme, host, port, proxy)
                    maxIdleConnectionsPerRoute = 4 // idle keep-alive connections kept per route
                    idleTimeout = 5.minutes // idle HTTP/1.1, HTTP/2 and HTTP/3 connections are closed after this
                    maxConnectionLifetime = Duration.INFINITE // age after which a connection takes no new requests
                }
            }
        client.use {
            val config = it.engine.config as KuicksilverEngineConfig
            assertEquals(1000, config.maxConnectionsCount)
            assertEquals(5.minutes, config.idleTimeout)
        }
    }

    @Test
    fun http2Sample() {
        // guide:ktor:http2-client
        val client =
            HttpClient(Kuicksilver) {
                engine {
                    http2 {
                        enabled = true // the default: offer h2 on every TLS connection over TCP
                        pingInterval = 30.seconds // a keep-alive PING; Duration.INFINITE (the default): none
                        settings = Http2Settings(initialStreamWindow = 1 shl 20) // our windows and limits (threat model 3.23)
                    }
                }
            }
        client.use {
            val config = it.engine.config as KuicksilverEngineConfig
            assertTrue(config.http2.enabled)
            assertEquals(30.seconds, config.http2.pingInterval)
            assertEquals(1 shl 20, config.http2.settings.initialStreamWindow)
        }
    }

    @Test fun mtlsClientSample() =
        h3Test {
            val clientChainPem = TestCerts.toPem("CERTIFICATE", TestCerts.client)
            val clientKeyPem = TestCerts.toPem("PRIVATE KEY", TestCerts.clientKey)
            val serverCaPem = TestCerts.toPem("CERTIFICATE", TestCerts.testCa)
            val server =
                embeddedServer(KuicksilverServer, configure = {
                    tlsConnector(ClientFixtures.identity()) {
                        host = "127.0.0.1"
                        port = 0
                        clientAuth = ClientAuth.Required
                        trust = ClientFixtures.trust
                    }
                }) {
                    routing {
                        get(
                            "/",
                        ) { call.respondText("${call.request.httpVersion} ${call.request.peerCertificates.first().dnsNames}") }
                    }
                }
            server.startSuspend(false)
            val port =
                server.engine
                    .resolvedConnectors()
                    .first()
                    .port
            try {
                // guide:ktor:mtls-client
                val identity = TlsIdentity.fromPem(clientChainPem, clientKeyPem.toCharArray()) // every target; the key array is zeroed
                val client =
                    HttpClient(Kuicksilver) {
                        engine {
                            this.identity = identity // presented over HTTP/3, HTTP/2 and HTTP/1.1 alike
                            // or keep Platform for a public server certificate
                            trust = TrustConfig.AnchoredCa(Certificate.parsePem(serverCaPem))
                        }
                    }

                client.use { c -> assertEquals("HTTP/1.1 [client.test]", c.get("https://127.0.0.1:$port/").bodyAsText()) }
                HttpClient(Kuicksilver) {
                    engine {
                        this.identity = identity
                        trust = ClientFixtures.trust
                        http3 { discovery = Http3DiscoveryMode.H3Only }
                    }
                }.use { c -> assertEquals("HTTP/3 [client.test]", c.get("https://127.0.0.1:$port/").bodyAsText()) }
                // without a certificate: the server ends the QUIC handshake with certificate_required (0x0100 + 116)
                val without =
                    assertFails {
                        HttpClient(Kuicksilver) {
                            engine {
                                trust = ClientFixtures.trust
                                http3 { discovery = Http3DiscoveryMode.H3Only }
                            }
                        }.use { c -> c.get("https://127.0.0.1:$port/") }
                    }
                assertIs<QuicException.ConnectionLost.TransportClosed>(without, without.toString())
                assertEquals(0x0174L, without.code)
                assertIs<TlsException.AlertReceived>(without.cause, without.toString())
                // over TCP (H1Only), and in Preferred mode, where HTTP/3 fails first and the call goes on over TCP: there the TLS
                // handshake completes on the client's side and the alert ends the request, so the TCP failure is thrown alone
                val h3Failures = mutableListOf<Throwable?>()
                for (mode in listOf(Http3DiscoveryMode.H1Only, Http3DiscoveryMode.Preferred)) {
                    val e =
                        assertFails {
                            HttpClient(Kuicksilver) {
                                engine {
                                    trust = ClientFixtures.trust
                                    http3 { discovery = mode }
                                    eventListener =
                                        object : KuicksilverEventListener() {
                                            override fun raceEnded(
                                                request: HttpRequestData,
                                                winner: HttpProtocolVersion,
                                                headStart: kotlin.time.Duration,
                                                h3Failure: Throwable?,
                                            ) {
                                                h3Failures += h3Failure
                                            }

                                            override fun fallback(
                                                request: HttpRequestData,
                                                cause: Throwable,
                                            ) {
                                                h3Failures += cause
                                            }
                                        }
                                }
                            }.use { c -> c.get("https://127.0.0.1:$port/") }
                        }
                    assertEquals("TLS alert received from the peer: certificate_required (116)", e.message, "$mode: $e")
                    assertIs<TlsException.AlertReceived>(generateSequence(e) { it.cause }.last(), "$mode: $e")
                    assertEquals(emptyList(), e.suppressed.toList(), "$mode: $e")
                    if (mode == Http3DiscoveryMode.H1Only) {
                        assertEquals(emptyList(), h3Failures, "H1Only never tries HTTP/3")
                    } else {
                        // HTTP/3 was tried first and failed with the alert: CRYPTO_ERROR 0x0100 + 116
                        assertTrue(
                            h3Failures.any { it is QuicException.ConnectionLost.TransportClosed && it.code == 0x0174L },
                            "$h3Failures",
                        )
                    }
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun protocolLogSample() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            val lines = mutableListOf<String>()

            fun logLine(line: String) {
                lines += line
            }
            try {
                // guide:ktor:protocol-log
                val client =
                    HttpClient(Kuicksilver) {
                        engine {
                            trust = ClientFixtures.trust
                            // the engine's own line per call that HTTP/3 could have served, into your logging
                            logger =
                                object : KuicksilverLogger {
                                    override fun isEnabled(level: LogLevel) = level >= LogLevel.Info

                                    override fun log(
                                        level: LogLevel,
                                        message: String,
                                        cause: Throwable?,
                                    ) = logLine("$level $message")
                                }
                            // the HTTP/3 failure itself, when it happens; why the call did not use HTTP/3 is on the response
                            eventListener =
                                object : KuicksilverEventListener() {
                                    override fun fallback(
                                        request: HttpRequestData,
                                        cause: Throwable,
                                    ) = logLine("HTTP/3 failed for ${request.url.host}: $cause")
                                }
                        }
                        // one line per response: the protocol and why
                        install(
                            createClientPlugin("ProtocolLog") {
                                onResponse { response ->
                                    val d = response.kuicksilverDiagnostics ?: return@onResponse
                                    logLine(
                                        "${response.call.request.url} -> ${d.protocol} (${d.reason}, fallback=${d.fallback}, h3Failure=${d.h3Failure})",
                                    )
                                }
                            },
                        )
                    }

                client.use { it.get("https://127.0.0.1:$port/") }
                assertEquals(listOf("https://127.0.0.1:$port/ -> HTTP/1.1 (NoAlternative, fallback=NoAlternative, h3Failure=null)"), lines)
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    // The guide's minimal client uses the platform trust store; the test server's certificate comes from a test CA, so the
    // sample's `HttpClient(Kuicksilver)` resolves to this member, which adds that CA and nothing else.
    @Suppress("FunctionName")
    private fun HttpClient(engine: HttpClientEngineFactory<KuicksilverEngineConfig>): HttpClient =
        io.ktor.client.HttpClient(engine) { engine { trust = ClientFixtures.trust } }

    @Test fun minimalClientSample() =
        clientTest {
            val served = MutableStateFlow(0)
            val (server, port) =
                testServer {
                    routing {
                        get("/") {
                            served.value++
                            call.respondText("hello")
                        }
                    }
                }
            val url = "https://127.0.0.1:$port/"
            try {
                // guide:ktor:minimal-client
                val client = HttpClient(Kuicksilver)
                println(client.get(url).bodyAsText())
                client.close()
                assertEquals(1, served.value)
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun clientSample() {
        // guide:ktor:client
        val client =
            HttpClient(Kuicksilver) {
                engine {
                    trust =
                        TrustConfig.Pinned(
                            setOf(SpkiSha256.parse("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")),
                            base = TrustConfig.Platform,
                        )
                    http3 { discovery = Http3DiscoveryMode.Auto } // the default: HTTP/1.1 first, HTTP/3 after Alt-Svc
                }
                install(HttpTimeout) {
                    connectTimeoutMillis = 5_000
                    socketTimeoutMillis = 15_000
                }
            }
        client.use {
            val config = it.engine.config as KuicksilverEngineConfig
            assertTrue(config.trust is TrustConfig.Pinned)
            assertEquals(Http3DiscoveryMode.Auto, config.http3.discovery)
        }
    }
}
