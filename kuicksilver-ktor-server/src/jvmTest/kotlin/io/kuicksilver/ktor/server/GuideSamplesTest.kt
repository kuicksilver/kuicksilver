// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.http.HttpProtocolVersion
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.application.pluginOrNull
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.plugins.origin
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.utils.io.copyTo
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.http2Settings
import io.kuicksilver.http3.Http3EarlyDataPolicy
import io.kuicksilver.http3.UdpProxy
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.qlog.AsyncQlogSink
import io.kuicksilver.quic.qlog.DirectoryQlogSink
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.EchKey
import io.kuicksilver.tls.EchServerKeys
import io.kuicksilver.tls.ServerTlsOverride
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.io.IOException
import java.nio.file.Files
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * The server code blocks of docs/guide/ktor.md (block markers `guide:ktor:server*`) and docs/guide/deployment.md
 * (`guide:deployment:*`), kept compiling and running.
 */
class GuideSamplesTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val chainPem = TestCerts.toPem("CERTIFICATE", TestCerts.server)
    private val keyPem = TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey)
    private val clientCa = Certificate(TestCerts.testCa)

    @Test fun guideHasEveryMarker() {
        val guide =
            generateSequence(File("").absoluteFile) {
                it.parentFile
            }.map { File(it, "docs/guide/ktor.md") }.first { it.exists() }.readText()
        assertTrue("guide:ktor:server" in guide, "marker server")
        assertTrue("guide:ktor:minimal-server" in guide, "marker minimal-server")
        assertTrue("guide:ktor:webtransport-server" in guide, "marker webtransport-server")
        assertTrue("guide:ktor:connect-udp-server" in guide, "marker connect-udp-server")
        assertTrue("guide:ktor:priority-server" in guide, "marker priority-server")
        assertTrue("guide:ktor:certificate-rotation" in guide, "marker certificate-rotation")
        assertTrue("guide:ktor:client-ca-rotation" in guide, "marker client-ca-rotation")
        assertTrue("guide:ktor:websocket-deflate-server" in guide, "marker websocket-deflate-server")
        assertTrue("guide:ktor:http3-advertising" in guide, "marker http3-advertising")
        assertTrue("guide:ktor:http2-server" in guide, "marker http2-server")
        assertTrue("guide:ktor:h2c-server" in guide, "marker h2c-server")
        assertTrue("guide:ktor:mtls-server" in guide, "marker mtls-server")
        assertTrue("guide:ktor:drain-wait" in guide, "marker drain-wait")
        assertTrue("guide:ktor:reload-from-files" in guide, "marker reload-from-files")
        assertTrue("guide:ktor:zero-rtt-replayable" in guide, "marker zero-rtt-replayable")
        assertTrue("guide:ktor:sni-server" in guide, "marker sni-server")
    }

    private object Metrics {
        var recorded = 0

        fun record(
            protocol: HttpProtocolVersion,
            status: Int?,
        ) {
            recorded++
        }
    }

    @Test fun observabilityAndZeroRttSamples() {
        val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        val metrics = Metrics
        // the samples build the engines; starting them is what serverSample does
        // guide:ktor:server-observability
        val observed =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { this.identity = identity }
                    port = 0
                    host = "127.0.0.1" // a test reaches its servers over 127.0.0.1; the wildcard address shares the port there
                }
                observability {
                    logger = KuicksilverLogger.stderr(LogLevel.Info)
                    qlog = AsyncQlogSink(DirectoryQlogSink("/var/log/qlog"), sampleEvery = 100)
                }
                observability {
                    eventListener =
                        object : KuicksilverServerEventListener() {
                            override fun requestEnded(
                                protocol: HttpProtocolVersion,
                                call: ApplicationCall,
                                cause: Throwable?,
                            ) {
                                metrics.record(protocol, call.response.status()?.value)
                            }
                        }
                }
            }, module = Application::module)
        assertTrue(observed.engine.configuration.observability.qlog is AsyncQlogSink)
        // guide:ktor:zero-rtt-server
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { this.identity = identity }
                    port = 0
                    host = "127.0.0.1" // a test reaches its servers over 127.0.0.1; the wildcard address shares the port there
                }
                http3 {
                    earlyData {
                        enabled = true
                        policy = Http3EarlyDataPolicy.Reject425() // or keep the default: unsafe requests wait
                    }
                }
            }, module = Application::module)
        assertTrue(
            server.engine.configuration
                .resolveHttp3Settings()
                .earlyData is Http3EarlyDataPolicy.Reject425,
        )
    }

    @Test fun webSocketDeflateSample() {
        val server =
            embeddedServer(Kuicksilver, configure = {
                connector {
                    host = "127.0.0.1"
                    port = 0
                }
            }) {
                // guide:ktor:websocket-deflate-server
                install(WebSockets) {
                    extensions { install(PerMessageDeflate) { maxInflatedMessageSize = 1024 * 1024 } }
                }
            }
        server.start(wait = false)
        try {
            // ServerDeflateTest and ClientDeflateTest talk to such a server
            assertTrue(server.application.pluginOrNull(WebSockets) != null)
        } finally {
            server.stop(100, 1000)
        }
    }

    @Test fun webTransportSample() {
        val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        // guide:ktor:webtransport-server
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { this.identity = identity }
                    port = 0
                    host = "127.0.0.1" // a test reaches its servers over 127.0.0.1; the wildcard address shares the port there
                }
                http3 { webTransport { enabled = true } }
            }) {
                routing {
                    webTransport("/echo", protocols = listOf("echo-v1")) { session ->
                        val stream = session.acceptBidi()
                        stream.input.copyTo(stream.output)
                        stream.output.flushAndClose()
                    }
                }
            }
        assertTrue(server.engine.configuration.http3.webTransport.enabled) // ServerWebTransportTest runs such a route
    }

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun connectUdpSample() {
        val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        // guide:ktor:connect-udp-server
        val proxyServer =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { this.identity = identity }
                    port = 0
                    host = "127.0.0.1" // a test reaches its servers over 127.0.0.1; the wildcard address shares the port there
                }
                http3 { connectUdp = true }
            }) {
                routing {
                    connectUdp(UdpProxy())
                }
            }
        assertTrue(proxyServer.engine.configuration.http3.connectUdp) // ServerConnectUdpTest runs such a route
    }

    @Test fun certificateRotationSample() {
        val renewedChainPem =
            TestCerts.toPem("CERTIFICATE", TestCerts.serverViaIntermediate) + TestCerts.toPem("CERTIFICATE", TestCerts.intermediate)
        val keyChars = keyPem.toCharArray() // the guide's arrays come from a file read without a String (readPemKey does that)
        val renewedKeyChars = TestCerts.toPem("PRIVATE KEY", TestCerts.serverViaIntermediateKey).toCharArray()
        // guide:ktor:certificate-rotation
        val identity = TlsIdentity.reloadable(TlsIdentity.fromPem(chainPem, keyChars)) // the key array is zeroed after import
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { this.identity = identity }
                    port = 0
                    host = "127.0.0.1" // a test reaches its servers over 127.0.0.1; the wildcard address shares the port there
                }
            }, module = Application::module)
        // later, when the renewed files are in place: new TCP and QUIC handshakes present them, open connections keep theirs
        identity.reload(TlsIdentity.fromPem(renewedChainPem, renewedKeyChars))
        assertTrue(
            server.engine.configuration.connectors
                .single() is KuicksilverTlsConnector,
        ) // ServerIdentityReloadTest serves it
        assertEquals(Certificate(TestCerts.serverViaIntermediate), identity.current.chain[0])
        identity.close()
    }

    @Test fun clientCaRotationSample() {
        val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        val caBundlePem = TestCerts.toPem("CERTIFICATE", TestCerts.testCa)
        val renewedBundlePem = TestCerts.toPem("CERTIFICATE", TestCerts.otherCa)
        // guide:ktor:client-ca-rotation
        val clientCa = TrustConfig.reloadable(TrustConfig.AnchoredCa(Certificate.parsePem(caBundlePem)))
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { this.identity = identity }
                    port = 0
                    host = "127.0.0.1" // a test reaches its servers over 127.0.0.1; the wildcard address shares the port there
                    tls {
                        clientAuth = ClientAuth.Required
                        clientTrust = clientCa
                    }
                }
            }, module = Application::module)
        // later: new TCP and QUIC handshakes verify client certificates against the new bundle
        clientCa.reload(TrustConfig.AnchoredCa(Certificate.parsePem(renewedBundlePem)))
        val connector =
            server.engine.configuration.connectors
                .single() as KuicksilverTlsConnector
        assertTrue(connector.resolved(ResolvedServerTls.None).tls.trust === clientCa) // ServerClientCaReloadTest serves it
        assertEquals(Certificate(TestCerts.otherCa), clientCa.current.roots.single())
        identity.close()
    }

    @Test fun http3AdvertisingSample() {
        val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        // guide:ktor:http3-advertising
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { this.identity = identity }
                    port = 0
                    host = "127.0.0.1" // a test reaches its servers over 127.0.0.1; the wildcard address shares the port there
                }
            }, module = Application::module)
        // later, when the remote configuration says so: clients fall back to HTTP/1.1 over TLS
        server.engine.http3Advertising = Http3Advertising.Drain
        // and when the incident is over
        server.engine.http3Advertising = Http3Advertising.On

        assertEquals(Http3Advertising.On, server.engine.http3Advertising) // ServerHttp3AdvertisingTest runs each mode
        identity.close()
    }

    @Test fun http2ServerSample() {
        val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        // guide:ktor:http2-server
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { this.identity = identity }
                    port = 0
                    host = "127.0.0.1" // a test reaches its servers over 127.0.0.1; the wildcard address shares the port there
                }
                http2 {
                    enabled = true // offer h2 before http/1.1 in ALPN
                    settings { maxConcurrentStreams = 50 } // windows and flood limits are Http2Settings'
                }
            }, module = Application::module)

        val configuration = server.engine.configuration
        assertTrue(configuration.http2.enabled, "the TLS connector offers h2") // ServerHttp2*Test serve it
        assertEquals(50, configuration.resolveHttp2Settings().maxConcurrentStreams)
        identity.close()
    }

    @Test fun h2cServerSample() {
        // guide:ktor:h2c-server
        val server =
            embeddedServer(Kuicksilver, configure = {
                plainConnector {
                    port = 0
                    host = "127.0.0.1" // a test reaches its servers over 127.0.0.1; the wildcard address shares the port there
                    h2c = H2cMode.WithHttp11 // HTTP/1.1 and h2c (prior knowledge) on this cleartext port; H2cMode.Only: h2c alone
                }
            }, module = Application::module)

        val connector =
            server.engine.configuration.connectors
                .single() as KuicksilverPlainConnector
        assertEquals(H2cMode.WithHttp11, connector.h2c) // ServerH2cTest serves it
    }

    @Test fun deploymentGuideHasEveryMarker() {
        val guide =
            generateSequence(File("").absoluteFile) {
                it.parentFile
            }.map { File(it, "docs/guide/deployment.md") }.first { it.exists() }.readText()
        assertTrue("guide:deployment:public-alt-svc" in guide, "marker public-alt-svc")
        assertTrue("guide:deployment:quic-limits" in guide, "marker quic-limits")
        assertTrue("guide:deployment:health" in guide, "marker health")
    }

    @Test fun quicLimitsSample() {
        val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        // guide:deployment:quic-limits
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { this.identity = identity }
                    port = 0
                    host = "127.0.0.1" // a test reaches its servers over 127.0.0.1; the wildcard address shares the port there
                }
                // behind kube-proxy (externalTrafficPolicy: Cluster): clients share node addresses
                http3 { endpoint { maxConnectionsPerIp = 4_096 } }
            }) {
                routing { get("/") { call.respondText("ok") } }
            }
        server.start(wait = false)
        // for a metrics gauge: clients dropped by quicMaxConnections or quicMaxConnectionsPerIp since the start
        val refusedByLimits = server.engine.http3Stats.sumOf { it.connectionsRefusedLimits }

        try {
            assertEquals(0L, refusedByLimits)
            assertEquals(4_096, server.engine.configuration.http3.endpoint.maxConnectionsPerIp)
            assertEquals(1, server.engine.http3Stats.size, "one HTTP/3 listener")
        } finally {
            server.stop(100, 500)
            identity.close()
        }
    }

    @Test fun publicAltSvcSample() {
        val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        // guide:deployment:public-alt-svc
        val publicPort = 443 // the UDP port clients reach (the load balancer's or the NAT's), not the one bound here
        lateinit var engine: KuicksilverApplicationEngine
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { this.identity = identity }
                    port = 0
                    host = "127.0.0.1" // a test reaches its servers over 127.0.0.1; the wildcard address shares the port there
                }
            }) {
                intercept(ApplicationCallPipeline.Plugins) {
                    // an Alt-Svc the application sets is never replaced, so it follows engine.http3Advertising itself
                    val h3 = engine.http3Advertising == Http3Advertising.On
                    call.response.header("Alt-Svc", if (h3) "h3=\":$publicPort\"; ma=86400" else "clear")
                }
                routing { get("/") { call.respondText("ok") } }
            }
        engine = server.engine

        server.start(wait = false)
        try {
            runBlocking {
                withTimeout(30.seconds) {
                    val port =
                        server.engine
                            .resolvedConnectors()
                            .first()
                            .port
                    assertNoLoopbackSquatter(port)
                    val get = "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n"

                    fun altSvc(resp: String) = resp.lines().filter { it.startsWith("Alt-Svc", ignoreCase = true) }
                    val on = rawHttp(port, get)
                    assertEquals(listOf("Alt-Svc: h3=\":443\"; ma=86400"), altSvc(on), on) // the public port, once
                    server.engine.http3Advertising = Http3Advertising.Drain
                    val drained = rawHttp(port, get)
                    assertEquals(listOf("Alt-Svc: clear"), altSvc(drained), drained)
                }
            }
        } finally {
            server.stop(100, 500)
            identity.close()
        }
    }

    @Test fun proxyProtocolSample() =
        runBlocking {
            withTimeout(30.seconds) {
                val server =
                    embeddedServer(Kuicksilver, configure = {
                        // guide:ktor:proxy-protocol
                        plainConnector {
                            host = "127.0.0.1"
                            port = 0
                            proxyProtocol {
                                trust("10.0.0.0/8", "2001:db8:1::/48") // the load balancers' addresses
                                trust("127.0.0.1") // the test plays the load balancer
                            }
                        }
                    }) {
                        routing {
                            // guide:ktor:proxy-protocol-origin
                            get("/") {
                                val client = call.request.origin.remoteAddress // the client the header names
                                val proxy = call.request.local.remoteAddress // the TCP peer: the load balancer
                                val sni = call.request.proxyHeader?.authority // a TLV, when the proxy sends one
                                call.respondText("$client via $proxy for $sni")
                            }
                        }
                    }
                server.startSuspend(wait = false)
                try {
                    val port =
                        server.engine
                            .resolvedConnectors()
                            .first()
                            .port
                    val r =
                        rawHttp(
                            port,
                            "PROXY TCP6 2001:db8::7 2001:db8::1 40000 443\r\nGET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n",
                            tls = null,
                        )
                    assertTrue(r.startsWith("HTTP/1.1 200 ") && r.endsWith("2001:db8::7 via 127.0.0.1 for null"), r)
                } finally {
                    server.stopSuspend(100, 500)
                }
            }
        }

    @Test fun trustedGatewaySample() =
        runBlocking {
            withTimeout(30.seconds) {
                val internalIdentity = ServerFixtures.identity()
                val server =
                    embeddedServer(Kuicksilver, configure = {
                        // guide:ktor:trusted-gateway
                        tlsConnector {
                            tls { identity = internalIdentity }
                            host = "127.0.0.1" // a test reaches its servers over 127.0.0.1; the wildcard address shares the port there
                            port = 0
                            allowMisdirectedHosts = true // every client of this port is the gateway
                        }
                        http3 { enabled = false }
                    }) { routing { get("/") { call.respondText("ok") } } }
                server.startSuspend(wait = false)
                try {
                    val port =
                        server.engine
                            .resolvedConnectors()
                            .first()
                            .port
                    assertNoLoopbackSquatter(port)
                    // a name the certificate does not carry, forwarded by the gateway: served
                    val r = rawHttp(port, "GET / HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n")
                    assertTrue(r.startsWith("HTTP/1.1 200 "), r)
                } finally {
                    server.stopSuspend(100, 500)
                }
            }
        }

    /**
     * guide:ktor:sni-server, run with the test certificates: `api.example.com` gets the proxy.internal certificate over HTTP/3
     * (the client checks it under that name), and `admin.example.com` requires a client certificate.
     */
    @Test fun sniServerSample() =
        runBlocking {
            withTimeout(30.seconds) {
                val defaultIdentity = ServerFixtures.identity()
                val apiIdentity = TlsIdentity.fromDer(listOf(TestCerts.proxy), TestCerts.proxyKey.copyOf())
                val adminIdentity = ServerFixtures.identity()
                val adminCa = TrustConfig.AnchoredCa(listOf(clientCa))
                val server =
                    embeddedServer(Kuicksilver, configure = {
                        // guide:ktor:sni-server
                        tlsConnector {
                            tls { identity = defaultIdentity }
                            port = 0
                            host = "127.0.0.1" // a test reaches its servers over 127.0.0.1; the wildcard address shares the port there
                            tls {
                                sniSelector = { hello ->
                                    when (hello.serverName) {
                                        "api.example.com" -> {
                                            ServerTlsOverride(apiIdentity)
                                        }

                                        "admin.example.com" -> {
                                            ServerTlsOverride(
                                                adminIdentity,
                                                clientAuth = ClientAuth.Required,
                                                trust = adminCa,
                                            )
                                        }

                                        else -> {
                                            null
                                        } // a name not served here: the handshake ends with unrecognized_name
                                    }
                                }
                            }
                        }
                    }) { routing { get("/") { call.respondText("ok") } } }
                server.startSuspend(wait = false)
                try {
                    val port =
                        server.engine
                            .resolvedConnectors()
                            .first()
                            .port

                    fun client(
                        name: String,
                        checkedAs: String,
                        alpn: String,
                    ) = io.kuicksilver.tls.tlsConfig(io.kuicksilver.tls.TlsRole.Client) {
                        this.alpn = listOf(alpn)
                        serverName = name
                        trust = TrustConfig.ExpectedName(checkedAs, TrustConfig.AnchoredCa(listOf(clientCa)))
                    }
                    // TCP: the handshake for api.example.com presents the proxy.internal certificate (checked as that name)
                    val tcp =
                        rawHttp(
                            port,
                            "GET / HTTP/1.1\r\nHost: proxy.internal\r\nConnection: close\r\n\r\n",
                            client("api.example.com", "proxy.internal", "http/1.1"),
                        )
                    assertTrue(tcp.startsWith("HTTP/1.1 421 "), "a request for another name than the SNI one: $tcp")
                    if (quicServerSupported()) {
                        val ep =
                            io.kuicksilver.http3.Http3Endpoint
                                .bind(
                                    io.ktor.network.sockets
                                        .InetSocketAddress("127.0.0.1", 0),
                                )
                        try {
                            val target =
                                io.ktor.network.sockets
                                    .InetSocketAddress("127.0.0.1", port)
                            val h3 = ep.connect(target, client("api.example.com", "proxy.internal", "h3"))
                            assertEquals(Certificate(TestCerts.proxy), h3.quic.peerCertificates[0], "the same identity over HTTP/3")
                            h3.close()
                            assertFails("admin.example.com requires a client certificate over HTTP/3 too") {
                                ep
                                    .connect(
                                        target,
                                        client("admin.example.com", "server.test", "h3"),
                                    ).request(io.kuicksilver.http3.http3Request("GET", "admin.example.com", "/"))
                            }
                        } finally {
                            ep.close()
                        }
                    }
                } finally {
                    server.stopSuspend(100, 500)
                }
            }
        }

    @Test fun prioritySample() =
        runBlocking {
            withTimeout(30.seconds) {
                fun buildReport() = "report"
                val (server, port) =
                    tlsServer {
                        routing {
                            // guide:ktor:priority-server
                            get("/report") {
                                if (call.request.priority.urgency < 4) call.response.priority(urgency = 4) // bulk: never ahead of the pages
                                call.respondText(buildReport())
                            }
                        }
                    }
                try {
                    val resp = rawHttp(port, "GET /report HTTP/1.1\r\nHost: server.test\r\nPriority: u=1\r\nConnection: close\r\n\r\n")
                    assertTrue(resp.lowercase().contains("\r\npriority: u=4\r\n") && resp.endsWith("report"), resp)
                } finally {
                    server.stop(100, 500)
                }
            }
        }

    @Test fun minimalServerSample() {
        // guide:ktor:minimal-server
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray()) }
                    host = "127.0.0.1"
                    port = 0
                }
            }) {
                routing {
                    get("/") { call.respondText("hello") }
                }
            }
        server.start(wait = false)
        try {
            val response =
                runBlocking {
                    withTimeout(30.seconds) {
                        val port =
                            server.engine
                                .resolvedConnectors()
                                .first()
                                .port
                        rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                    }
                }
            assertTrue(response.startsWith("HTTP/1.1 200"), response)
            assertTrue(response.endsWith("hello"), response)
        } finally {
            server.stop(100, 500)
        }
    }

    @Test fun serverSample() {
        // guide:ktor:server
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray()) }
                    // the key array is zeroed after import
                    host = "127.0.0.1"
                    port = 0
                    tls {
                        clientAuth = ClientAuth.Optional // ask for a client certificate without requiring one
                        clientTrust = TrustConfig.AnchoredCa(listOf(clientCa))
                    }
                }
            }) {
                routing {
                    get("/") { call.respondText("hello, ${call.request.peerCertificates.size} certificates") }
                }
            }
        server.start(wait = false)
        try {
            val response =
                runBlocking {
                    withTimeout(30.seconds) {
                        val port =
                            server.engine
                                .resolvedConnectors()
                                .first()
                                .port
                        rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                    }
                }
            assertTrue(response.startsWith("HTTP/1.1 200"), response)
            assertTrue(response.endsWith("hello, 0 certificates"), response)
        } finally {
            server.stop(100, 500)
        }
    }

    @Test fun mtlsServerSample() {
        val clientCaPem = TestCerts.toPem("CERTIFICATE", TestCerts.testCa) // the guide reads it from a file
        // guide:ktor:mtls-server
        val clientCa = Certificate.parsePem(clientCaPem) // the CA that issues the client certificates
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray()) }
                    host = "127.0.0.1"
                    port = 0
                    tls {
                        clientAuth = ClientAuth.Required // no handshake without a client certificate that chains to clientCa
                        clientTrust = TrustConfig.AnchoredCa(clientCa)
                    }
                }
            }) {
                routing {
                    get("/whoami") { call.respondText("client ${call.request.peerCertificates.first().dnsNames}") }
                }
            }
        server.start(wait = false)
        try {
            runBlocking {
                withTimeout(30.seconds) {
                    val port =
                        server.engine
                            .resolvedConnectors()
                            .first()
                            .port
                    val get = "GET /whoami HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n"
                    val identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())
                    val withCertificate = rawHttp(port, get, ServerFixtures.clientTls(identity = identity))
                    assertTrue(withCertificate.startsWith("HTTP/1.1 200"), withCertificate)
                    assertTrue(withCertificate.endsWith("client [client.test]"), withCertificate)
                    // without one the server ends the handshake with certificate_required (RFC 9846 section 4.5.1.3)
                    val without = assertFails { rawHttp(port, get) }
                    assertTrue("certificate_required (116)" in without.message.orEmpty(), without.toString())
                }
            }
        } finally {
            server.stop(100, 500)
        }
    }

    @Test fun drainWaitSample() {
        val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { this.identity = identity }
                    port = 0
                    host = "127.0.0.1" // a test reaches its servers over 127.0.0.1; the wildcard address shares the port there
                }
            }, module = Application::module)
        server.start(wait = false)
        try {
            runBlocking {
                withTimeout(30.seconds) {
                    // guide:ktor:drain-wait
                    server.engine.http3Advertising = Http3Advertising.Drain
                    // wait until the HTTP/3 connections are gone, or for 10 minutes at most (Drain has no deadline of its own)
                    withTimeoutOrNull(10.minutes) {
                        while (server.engine.http3Stats.sumOf { it.connectionsActive } > 0) delay(1.seconds)
                    }
                    // now the maintenance; afterwards:
                    server.engine.http3Advertising = Http3Advertising.On
                }
            }
            assertEquals(1, server.engine.http3Stats.size, "one HTTP/3 listener")
            assertEquals(0L, server.engine.http3Stats.sumOf { it.connectionsActive })
        } finally {
            server.stop(100, 500)
            identity.close()
        }
    }

    @Test fun healthSample() {
        val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        // guide:deployment:health
        lateinit var engine: KuicksilverApplicationEngine
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { this.identity = identity }
                    port = 0
                    host = "127.0.0.1" // a test reaches its servers over 127.0.0.1; the wildcard address shares the port there
                }
            }) {
                routing {
                    // for the readiness and liveness probes: the kubelet probes over TCP (httpGet with scheme HTTPS)
                    get("/healthz") { call.respondText("ok") }
                    // for a metrics scraper: is QUIC arriving, and is it refused?
                    get("/metrics/quic") {
                        val s = engine.http3Stats
                        call.respondText(
                            "datagrams_received ${s.sumOf { it.datagramsReceived }}\n" +
                                "connections_active ${s.sumOf { it.connectionsActive }}\n" +
                                "refused_limits ${s.sumOf { it.connectionsRefusedLimits }}\n" +
                                "handshakes_failed_timeout ${s.sumOf { it.handshakesFailedTimeout }}\n" +
                                "http3_advertising ${engine.http3Advertising}\n",
                        )
                    }
                }
            }
        engine = server.engine

        server.start(wait = false)
        try {
            runBlocking {
                withTimeout(30.seconds) {
                    val port =
                        server.engine
                            .resolvedConnectors()
                            .first()
                            .port
                    assertNoLoopbackSquatter(port)
                    val health = rawHttp(port, "GET /healthz HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                    assertTrue(health.startsWith("HTTP/1.1 200") && health.endsWith("ok"), health)
                    val metrics = rawHttp(port, "GET /metrics/quic HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                    assertTrue(metrics.contains("\r\n\r\ndatagrams_received 0\n"), metrics)
                    assertTrue(metrics.endsWith("http3_advertising On\n"), metrics)
                }
            }
        } finally {
            server.stop(100, 500)
            identity.close()
        }
    }

    @Test fun zeroRttReplayableSample() {
        val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        // guide:ktor:zero-rtt-replayable
        val policy =
            Http3EarlyDataPolicy.WaitForHandshake(replayable = { request ->
                request.method == "GET" && request.path.orEmpty().startsWith("/static/") // only these may run before the handshake
            })
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { this.identity = identity }
                    port = 0
                    host = "127.0.0.1" // a test reaches its servers over 127.0.0.1; the wildcard address shares the port there
                }
                http3 {
                    earlyData {
                        enabled = true
                        this.policy = policy
                    }
                }
            }) {
                routing {
                    get("/feed") {
                        if (call.request.receivedEarly) { /* a replay is possible here: no side effects */ }
                        call.respondText("feed")
                    }
                }
            }

        assertTrue(
            server.engine.configuration
                .resolveHttp3Settings()
                .earlyData === policy,
        ) // ServerH3Test runs early requests
        identity.close()
    }

    @Test fun reloadFromFilesSample() {
        val dir = Files.createTempDirectory("kuicksilver-reload").toFile()
        val chainFile = File(dir, "fullchain.pem").apply { writeText(chainPem) }
        val keyFile = File(dir, "privkey.pem").apply { writeText(keyPem) }

        // guide:ktor:reload-from-files
        fun readKeyChars(file: File): CharArray {
            val bytes = file.readBytes()
            try {
                return CharArray(bytes.size) { bytes[it].toInt().toChar() }
            } finally {
                bytes.fill(0)
            }
        }

        // guide:ktor:reload-from-files
        fun reloadIfChanged(
            identity: TlsIdentity.Reloadable,
            chainFile: File,
            keyFile: File,
            served: Long,
        ): Long {
            val modified = chainFile.lastModified()
            if (modified == served) return served
            return try {
                val next = TlsIdentity.fromPem(chainFile.readText(), readKeyChars(keyFile)) // fails while the key does not match yet
                try {
                    identity.reload(next) // refuses an expired certificate, or one not valid yet
                } catch (e: TlsException) {
                    next.close() // a refused identity is still ours to close
                    throw e
                }
                modified
            } catch (e: TlsException) {
                served // the old identity keeps serving; tried again at the next check
            } catch (e: IOException) {
                served
            }
        }

        // guide:ktor:reload-from-files
        val identity = TlsIdentity.reloadable(TlsIdentity.fromPem(chainFile.readText(), readKeyChars(keyFile)))
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { this.identity = identity }
                    port = 0
                    host = "127.0.0.1" // a test reaches its servers over 127.0.0.1; the wildcard address shares the port there
                }
            }) {
                launch {
                    var served = chainFile.lastModified()
                    while (true) {
                        delay(1.hours)
                        served = reloadIfChanged(identity, chainFile, keyFile, served)
                    }
                }
                module()
            }

        server.start(wait = false) // the watch waits its hour; the stop cancels it with the application
        try {
            val first = chainFile.lastModified()
            assertEquals(first, reloadIfChanged(identity, chainFile, keyFile, first), "unchanged files: nothing to do")
            // the renewed certificate written before its key (certbot's order): refused, the old identity keeps serving
            chainFile.writeText(TestCerts.toPem("CERTIFICATE", TestCerts.serverViaIntermediate))
            chainFile.setLastModified(first + 10_000)
            assertEquals(first, reloadIfChanged(identity, chainFile, keyFile, first))
            assertEquals(Certificate(TestCerts.server), identity.current.chain[0])
            // then the key: the next check serves the pair
            keyFile.writeText(TestCerts.toPem("PRIVATE KEY", TestCerts.serverViaIntermediateKey))
            assertEquals(first + 10_000, reloadIfChanged(identity, chainFile, keyFile, first))
            assertEquals(Certificate(TestCerts.serverViaIntermediate), identity.current.chain[0])
        } finally {
            server.stop(100, 500)
            identity.close()
            dir.deleteRecursively()
        }
    }

    @OptIn(ExperimentalKuicksilverApi::class)
    @Test
    fun echServerSample() {
        val dir = Files.createTempDirectory("ech-guide").toFile()
        val identity = ServerFixtures.identity()
        try {
            val ech1 = File(dir, "ech-1.pem").apply { writeText(EchTestKeys.A) }
            val ech2 = File(dir, "ech-2.pem").apply { writeText(EchTestKeys.B) }
            // guide:ktor:ech-server
            val keys = EchServerKeys(listOf(EchKey(ech1.readBytes())))
            val server =
                embeddedServer(Kuicksilver, configure = {
                    tlsConnector {
                        // built, never started
                        tls { this.identity = identity }
                        port = 443
                        tls { echKeys = keys }
                    }
                }) { routing { get("/") { call.respondText("hidden") } } }
            // later: a new key; the old one still decrypts for clients that hold it, but is not sent in retry configurations
            keys.rotate(listOf(EchKey(ech2.readBytes()), EchKey(ech1.readBytes(), inRetryConfigs = false)))

            assertTrue(
                server.engine.configuration.connectors
                    .single() is KuicksilverTlsConnector,
            )
        } finally {
            dir.deleteRecursively()
        }
    }
}

/** The application module the samples name. */
private fun Application.module() {}
