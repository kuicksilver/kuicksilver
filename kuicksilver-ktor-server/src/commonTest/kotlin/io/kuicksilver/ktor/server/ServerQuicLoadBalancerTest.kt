// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.http3Request
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicLbConfig
import io.kuicksilver.tls.KslCrypto
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.seconds

/** `quicLoadBalancer` and `engine.updateLoadBalancer` (QUIC-LB, draft-ietf-quic-load-balancers-21) reach the HTTP/3 listeners. */
@OptIn(ExperimentalKuicksilverApi::class)
class ServerQuicLoadBalancerTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val sid = byteArrayOf(0x31, 0x44, 0x1a)

    @Test fun requestsServedAcrossAConfigurationChange() =
        h3ServerTest {
            val first = KslQuicCrypto.newLoadBalancerKey(KslCrypto.randomBytes(16))
            val second = KslQuicCrypto.newLoadBalancerKey(KslCrypto.randomBytes(16))
            val (server, port) =
                tlsServer(configure = { quicLoadBalancer = QuicLbConfig(1, sid, 4, first) }) {
                    routing { get("/") { call.respondText("ok") } }
                }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                assertEquals(200, withTimeout(10.seconds) { c.request(http3Request("GET", "server.test", "/")) }.status)
                server.engine.updateLoadBalancer(QuicLbConfig(2, sid, 4, second))
                assertEquals(200, withTimeout(10.seconds) { c.request(http3Request("GET", "server.test", "/")) }.status, "after the change")
                c.close()
            } finally {
                ep.close()
                server.stop(100, 500)
                first.close()
                second.close()
            }
        }

    @Test fun negative_updateWithoutQuicLoadBalancer() =
        h3ServerTest {
            val (server, _) = tlsServer { routing { get("/") { call.respondText("ok") } } }
            try {
                assertFailsWith<IllegalStateException> { server.engine.updateLoadBalancer(null) }
            } finally {
                server.stop(100, 500)
            }
        }
}
