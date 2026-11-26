// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.ipLiteral
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** Closing the client closes every endpoint of its HTTP/3 pool: the wildcard one and the loopback ones of both families. */
class ClientH3EndpointCloseTest {
    @Test fun closeClosesEveryEndpoint() =
        h3Test {
            val (s4, p4) = testServer(host = "127.0.0.1") { routing { get("/") { call.respondText("ok") } } }
            val s6 = runCatching { testServer(host = "::1") { routing { get("/") { call.respondText("ok") } } } }.getOrNull()
            try {
                val chosen = LinkedHashMap<String, Http3Endpoint>()
                // closed also when a request or a check fails: the leak sentinel would otherwise wait for its endpoints and
                // report them beside the failure, in this test and in the class's check
                testClient(Http3Discovery.H3Only, engine = { connectTimeout = 300.milliseconds }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    engine.h3.endpointChosenForTest = { _, ep -> chosen[ep.localAddress.ipLiteral()] = ep }
                    assertEquals("ok", c.get("https://127.0.0.1:$p4/").bodyAsText())
                    s6?.let { (_, p6) -> assertEquals("ok", c.get("https://[::1]:$p6/").bodyAsText()) }
                    assertFails { c.get("https://192.0.2.1:443/") }
                    assertEquals(setOfNotNull("127.0.0.1", "0.0.0.0", s6?.let { "::1" }), chosen.keys)
                    c.close()
                    withTimeout(10.seconds) { engine.cleanup.join() }
                    val tls = engine.config.tlsConfigFor("server.test", listOf(Http3Endpoint.H3))
                    for ((local, ep) in chosen) {
                        assertFailsWith<QuicException.EndpointClosing>(local) {
                            withTimeout(5.seconds) { ep.connect(InetSocketAddress(if (local == "::1") "::1" else "127.0.0.1", 9), tls) }
                        }
                    }
                }
            } finally {
                s4.stop(100, 500)
                s6?.first?.stop(100, 500)
            }
        }
}
