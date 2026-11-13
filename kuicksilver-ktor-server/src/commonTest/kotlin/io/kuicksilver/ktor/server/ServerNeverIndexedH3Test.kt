// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
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
import io.kuicksilver.ktor.client.Kuicksilver as KuicksilverClient

/**
 * RFC 9204 sections 4.5.4 and 7.1.3 over HTTP/3, both engines: the client's marked field and its `authorization` reach the
 * server's call with QPACK's 'N' bit, a plain field does not; the server's marked response field reaches the client so.
 */
class ServerNeverIndexedH3Test {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun neverIndexedFieldsCrossBothEnginesOverH3() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/") {
                            call.response.neverIndex("X-Reply")
                            call.response.headers.append("x-reply", "r1")
                            call.response.headers.append("x-open", "o1")
                            call.respondText(call.request.neverIndexedHeaders.joinToString(";") { "${it.first}=${it.second}" })
                        }
                    }
                }
            val client =
                HttpClient(KuicksilverClient) {
                    expectSuccess = false
                    engine {
                        trust = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa)))
                        http3 { discovery = Http3DiscoveryMode.H3Only }
                    }
                }
            try {
                val r =
                    withTimeout(10.seconds) {
                        client.get("https://127.0.0.1:$port/") {
                            neverIndex("X-Secret")
                            header("x-secret", "s1")
                            header("x-plain", "p1")
                            header("authorization", "Bearer t")
                        }
                    }
                assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                assertEquals("x-secret=s1;authorization=Bearer t", r.bodyAsText())
                assertEquals(listOf("x-reply" to "r1"), r.neverIndexedHeaders)
            } finally {
                client.close()
                server.stop(100, 500)
            }
        }
}
