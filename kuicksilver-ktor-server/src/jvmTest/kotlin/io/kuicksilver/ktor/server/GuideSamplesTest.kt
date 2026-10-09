// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
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
