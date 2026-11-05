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
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.utils.io.copyTo
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.Http3EarlyDataPolicy
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.qlog.AsyncQlogSink
import io.kuicksilver.quic.qlog.DirectoryQlogSink
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.io.File
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
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
        assertTrue("guide:ktor:webtransport-server" in guide, "marker webtransport-server")
        assertTrue("guide:ktor:priority-server" in guide, "marker priority-server")
        assertTrue("guide:ktor:certificate-rotation" in guide, "marker certificate-rotation")
        assertTrue("guide:ktor:websocket-deflate-server" in guide, "marker websocket-deflate-server")
        assertTrue("guide:ktor:http3-advertising" in guide, "marker http3-advertising")
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
                tlsConnector(identity) { port = 0 }
                logger = KuicksilverLogger.stderr(LogLevel.Info)
                qlog = AsyncQlogSink(DirectoryQlogSink("/var/log/qlog"), sampleEvery = 100)
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
            }, module = Application::module)
        assertTrue(observed.engine.configuration.qlog is AsyncQlogSink)
        // guide:ktor:zero-rtt-server
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector(identity) { port = 0 }
                quicEarlyData = true
                http3Settings = http3Settings { earlyData = Http3EarlyDataPolicy.Reject425() } // or keep the default: safe methods early
            }, module = Application::module)
        assertTrue(server.engine.configuration.http3Settings.earlyData is Http3EarlyDataPolicy.Reject425)
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
                tlsConnector(identity) { port = 0 }
                webTransport = true
            }) {
                routing {
                    webTransport("/echo", protocols = listOf("echo-v1")) { session ->
                        val stream = session.acceptBidi()
                        stream.input.copyTo(stream.output)
                        stream.output.flushAndClose()
                    }
                }
            }
        assertTrue(server.engine.configuration.webTransport) // ServerWebTransportTest runs such a route
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
                tlsConnector(identity) { port = 0 }
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

    @Test fun http3AdvertisingSample() {
        val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        // guide:ktor:http3-advertising
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector(identity) { port = 0 }
            }, module = Application::module)
        // later, when the remote configuration says so: clients fall back to HTTP/1.1 over TLS
        server.engine.http3Advertising = Http3Advertising.Drain
        // and when the incident is over
        server.engine.http3Advertising = Http3Advertising.On

        assertEquals(Http3Advertising.On, server.engine.http3Advertising) // ServerHttp3AdvertisingTest runs each mode
        identity.close()
    }

    @Test fun deploymentGuideHasEveryMarker() {
        val guide =
            generateSequence(File("").absoluteFile) {
                it.parentFile
            }.map { File(it, "docs/guide/deployment.md") }.first { it.exists() }.readText()
        assertTrue("guide:deployment:public-alt-svc" in guide, "marker public-alt-svc")
    }

    @Test fun publicAltSvcSample() {
        val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        // guide:deployment:public-alt-svc
        val publicPort = 443 // the UDP port clients reach (the load balancer's or the NAT's), not the one bound here
        lateinit var engine: KuicksilverApplicationEngine
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector(identity) { port = 0 }
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
                    val resp = rawHttp(port, "GET /report HTTP/1.1\r\nHost: s\r\nPriority: u=1\r\nConnection: close\r\n\r\n")
                    assertTrue(resp.lowercase().contains("\r\npriority: u=4\r\n") && resp.endsWith("report"), resp)
                } finally {
                    server.stop(100, 500)
                }
            }
        }

    @Test fun serverSample() {
        // guide:ktor:server
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector(TlsIdentity.fromPem(chainPem, keyPem.toCharArray())) {
                    // the key array is zeroed after import
                    host = "127.0.0.1"
                    port = 0
                    clientAuth = ClientAuth.Optional // ask for a client certificate without requiring one
                    trust = TrustConfig.AnchoredCa(listOf(clientCa))
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
}

/** The application module the samples name. */
private fun Application.module() {}
