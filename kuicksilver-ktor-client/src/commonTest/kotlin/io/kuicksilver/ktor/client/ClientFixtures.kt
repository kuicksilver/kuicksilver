// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.server.application.Application
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.kuicksilver.ktor.server.KuicksilverApplicationEngine
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.time.Duration.Companion.seconds
import io.kuicksilver.ktor.server.Kuicksilver as KuicksilverServer

internal object ClientFixtures {
    val testCa = Certificate(TestCerts.testCa)
    val trust: TrustConfig = TrustConfig.AnchoredCa(listOf(testCa))

    fun identity(): TlsIdentity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
}

internal typealias TestServer = EmbeddedServer<KuicksilverApplicationEngine, KuicksilverApplicationEngine.Configuration>

/** A Kuicksilver server engine on loopback: TLS (HTTP/1.1 + HTTP/3) unless [plain]; returns it and its port. */
internal suspend fun testServer(
    plain: Boolean = false,
    configure: KuicksilverApplicationEngine.Configuration.() -> Unit = {},
    module: Application.() -> Unit,
): Pair<TestServer, Int> {
    val server =
        embeddedServer(KuicksilverServer, configure = {
            if (plain) {
                connector {
                    host = "127.0.0.1"
                    port = 0
                }
            } else {
                tlsConnector(ClientFixtures.identity()) {
                    host = "127.0.0.1"
                    port = 0
                }
            }
            configure()
        }, module = module)
    server.startSuspend(false)
    return server to
        server.engine
            .resolvedConnectors()
            .first()
            .port
}

/** A client with the test trust; HTTP/1.1 only unless [discovery] says otherwise. */
internal fun testClient(
    discovery: Http3DiscoveryMode = Http3DiscoveryMode.H1Only,
    engine: KuicksilverEngineConfig.() -> Unit = {},
    block: HttpClientConfig<KuicksilverEngineConfig>.() -> Unit = {},
): HttpClient =
    HttpClient(Kuicksilver) {
        engine {
            trust = ClientFixtures.trust
            http3 { this.discovery = discovery }
            engine()
        }
        block()
    }

internal fun clientTest(block: suspend () -> Unit) = runBlocking { withTimeout(60.seconds) { block() } }
