// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.guide.both

// guide:ktor:both-engines-aliases
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.server.application.Application
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import io.kuicksilver.ktor.client.Kuicksilver as KuicksilverClient
import io.kuicksilver.ktor.server.Kuicksilver as KuicksilverServer

/** The application module the sample names. */
fun Application.module() {
    routing { get("/") { call.respondText("both") } }
}

/** docs/guide/ktor.md: one file with both engines, each `Kuicksilver` imported under its own name (`guide:ktor:both-engines`). */
class GuideBothEnginesTest {
    @Test fun bothEnginesSample() {
        val certs = io.kuicksilver.ktor.client.TestCerts
        val identity = TlsIdentity.fromDer(listOf(certs.server), certs.serverKey.copyOf())
        // guide:ktor:both-engines
        val server =
            embeddedServer(KuicksilverServer, configure = {
                tlsConnector(identity) { port = 0 }
            }, module = Application::module)
        val client =
            HttpClient(KuicksilverClient) {
                engine { trust = TrustConfig.AnchoredCa(listOf(Certificate(certs.testCa))) }
            }

        server.start(wait = false)
        try {
            runBlocking {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                assertEquals("both", client.get("https://127.0.0.1:$port/").bodyAsText())
            }
        } finally {
            client.close()
            server.stop(100, 500)
        }
    }
}
