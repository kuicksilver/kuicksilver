// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.http.HttpProtocolVersion
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.Http3EarlyDataPolicy
import io.kuicksilver.http3.http3Settings
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
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The server code blocks of docs/guide/ktor.md, kept compiling and running (block markers `guide:ktor:server*`). */
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
