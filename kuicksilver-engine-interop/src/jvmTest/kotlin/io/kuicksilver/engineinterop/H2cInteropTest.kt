// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.engineinterop

import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.application.Application
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.ktor.client.HostPort
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.ktor.server.H2cMode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URI
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import io.kuicksilver.ktor.client.Kuicksilver as KuicksilverClient
import io.kuicksilver.ktor.server.Kuicksilver as KuicksilverServer

/**
 * h2c (HTTP/2 over cleartext TCP with prior knowledge, RFC 9113 section 3.3) between our engines and the peers: OkHttp's
 * `H2_PRIOR_KNOWLEDGE` (directly and as Ktor's OkHttp engine) and the JDK's HttpClient against our server; our client
 * against a plain Netty server and Ktor's Netty engine with `enableH2c`.
 */
internal class H2cInteropTest {
    private val module: Application.() -> Unit = {
        routing { get("/") { call.respondText("${call.request.httpVersion} ${call.request.local.scheme}") } }
    }

    private fun ourServer(mode: H2cMode): Pair<EmbeddedServer<*, *>, Int> {
        val server =
            embeddedServer(KuicksilverServer, configure = {
                plainConnector {
                    host = "127.0.0.1"
                    port = 0
                    h2c = mode
                }
                http3 = false
                shutdownGracePeriod = 0
            }, module = module)
        server.start(wait = false)
        val port =
            kotlinx.coroutines.runBlocking {
                server.engine
                    .resolvedConnectors()
                    .first()
                    .port
            }
        return server to port
    }

    private fun ourClient(port: Int) =
        HttpClient(KuicksilverClient) {
            engine {
                http3 { discovery = Http3DiscoveryMode.H1Only }
                http2 { priorKnowledge = setOf(HostPort("127.0.0.1", port)) }
            }
        }

    @Test fun okHttpPriorKnowledgeToOurServer() =
        interopTest {
            for (mode in listOf(H2cMode.Only, H2cMode.WithHttp11)) {
                val (server, port) = ourServer(mode)
                try {
                    val ok =
                        okhttp3.OkHttpClient
                            .Builder()
                            .protocols(listOf(okhttp3.Protocol.H2_PRIOR_KNOWLEDGE))
                            .build()
                    try {
                        withContext(Dispatchers.IO) {
                            ok
                                .newCall(
                                    okhttp3.Request
                                        .Builder()
                                        .url("http://127.0.0.1:$port/")
                                        .build(),
                                ).execute()
                                .use { r ->
                                    assertEquals(okhttp3.Protocol.H2_PRIOR_KNOWLEDGE, r.protocol, "$mode")
                                    assertEquals("HTTP/2 http", r.body.string())
                                }
                        }
                    } finally {
                        ok.dispatcher.executorService.shutdown()
                        ok.connectionPool.evictAll()
                    }
                } finally {
                    server.stop(0, 2_000)
                }
            }
        }

    @Test fun ktorOkHttpEnginePriorKnowledgeToOurServer() =
        interopTest {
            val (server, port) = ourServer(H2cMode.Only)
            try {
                HttpClient(OkHttp) { engine { config { protocols(listOf(okhttp3.Protocol.H2_PRIOR_KNOWLEDGE)) } } }.use { c ->
                    val r = c.get("http://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                    assertEquals("HTTP/2 http", r.bodyAsText())
                }
            } finally {
                server.stop(0, 2_000)
            }
        }

    /**
     * The JDK's HttpClient has no prior knowledge: with `HTTP_2` on an `http://` URI it sends an HTTP/1.1 request with
     * `Upgrade: h2c` (RFC 7540 section 3.2, deprecated by RFC 9113 section 3.1). Our server does not take the upgrade and
     * answers HTTP/1.1 ([H2cMode.WithHttp11]); an h2c-only port has nothing to answer it with, so the request fails.
     */
    @Test fun jdkHttpClientUpgradeIsServedAsHttp11() =
        interopTest {
            val jdk =
                java.net.http.HttpClient
                    .newBuilder()
                    .version(java.net.http.HttpClient.Version.HTTP_2)
                    .connectTimeout(Duration.ofSeconds(10))
                    .build()
            val (both, bothPort) = ourServer(H2cMode.WithHttp11)
            try {
                val r =
                    withContext(Dispatchers.IO) {
                        jdk.send(
                            HttpRequest.newBuilder(URI("http://127.0.0.1:$bothPort/")).timeout(Duration.ofSeconds(20)).build(),
                            HttpResponse.BodyHandlers.ofString(),
                        )
                    }
                assertEquals(java.net.http.HttpClient.Version.HTTP_1_1, r.version())
                assertEquals("HTTP/1.1 http", r.body())
            } finally {
                both.stop(0, 2_000)
            }
            val (only, onlyPort) = ourServer(H2cMode.Only)
            try {
                assertFailsWith<java.io.IOException> {
                    withContext(Dispatchers.IO) {
                        jdk.send(
                            HttpRequest.newBuilder(URI("http://127.0.0.1:$onlyPort/")).timeout(Duration.ofSeconds(20)).build(),
                            HttpResponse.BodyHandlers.ofString(),
                        )
                    }
                }
            } finally {
                only.stop(0, 2_000)
            }
        }

    @Test fun ourClientToPlainNettyH2c() =
        interopTest {
            PlainNettyServer(h2 = true, h2c = true).use { s ->
                ourClient(s.port).use { c ->
                    val r = c.get(s.url("/next"))
                    assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                    assertEquals("/next", r.bodyAsText())
                    // a trailer section over h2c (RFC 9113 section 8.1), and the connection carries the next request
                    assertEquals("with trailers", c.get(s.url("/trailers")).bodyAsText())
                    assertEquals("/after", c.get(s.url("/after")).bodyAsText())
                    assertEquals(1, s.connections.get())
                }
            }
        }

    @Test fun ourClientToKtorNettyH2c() =
        interopTest {
            val server =
                embeddedServer(Netty, configure = {
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                    enableH2c = true
                    shutdownGracePeriod = 0
                }, module = module)
            server.start(wait = false)
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                ourClient(port).use { c ->
                    val r = c.get("http://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                    assertEquals("HTTP/2 http", r.bodyAsText())
                }
            } finally {
                server.stop(0, 2_000)
            }
        }
}
