// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.http3Request
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.quicConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The QUIC endpoint limits set from the engine configuration, and the endpoint statistics read through the engine. */
class ServerQuicLimitsTest {
    @kotlin.test.BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Starts a server whose HTTP/3 bind records the endpoint configuration it was given; returns the server and that configuration. */
    private suspend fun boundWith(configure: KuicksilverApplicationEngine.Configuration.() -> Unit): Pair<Server, QuicEndpointConfig> {
        var seen: QuicEndpointConfig? = null
        val (server, _) =
            tlsServer({
                configure()
                val bind = http3Bind
                http3Bind = { a, c, s ->
                    seen = c
                    bind(a, c, s)
                }
            }) {}
        return server to checkNotNull(seen) { "the HTTP/3 listener was not bound" }
    }

    @Test fun defaultsAreTheEndpointDefaults() =
        h3ServerTest {
            val c = KuicksilverApplicationEngine.Configuration()
            assertEquals(10_000, c.quicMaxConnections)
            assertEquals(256, c.quicMaxConnectionsPerIp)
            assertEquals(128, c.quicAcceptQueue)
            val (server, ep) = boundWith {}
            try {
                assertEquals(QuicEndpointConfig.Default.maxConnections, ep.maxConnections)
                assertEquals(QuicEndpointConfig.Default.maxConnectionsPerIp, ep.maxConnectionsPerIp)
                assertEquals(QuicEndpointConfig.Default.acceptQueue, ep.acceptQueue)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun limitsReachTheEndpoint() =
        h3ServerTest {
            val (server, ep) =
                boundWith {
                    quicMaxConnections = 50
                    quicMaxConnectionsPerIp = 2
                    quicAcceptQueue = 7
                }
            try {
                assertEquals(50, ep.maxConnections)
                assertEquals(2, ep.maxConnectionsPerIp)
                assertEquals(7, ep.acceptQueue)
            } finally {
                server.stop(100, 500)
            }
            val (off, ep2) = boundWith { quicMaxConnectionsPerIp = null }
            try {
                assertNull(ep2.maxConnectionsPerIp, "null turns the per-IP limit off")
            } finally {
                off.stop(100, 500)
            }
        }

    @Test fun negative_outOfRangeLimitsAreRefused() {
        val c = KuicksilverApplicationEngine.Configuration()
        assertFailsWith<IllegalArgumentException> { c.quicMaxConnections = 0 }
        assertFailsWith<IllegalArgumentException> { c.quicMaxConnectionsPerIp = 0 }
        assertFailsWith<IllegalArgumentException> { c.quicAcceptQueue = 0 }
        assertEquals(10_000, c.quicMaxConnections)
        assertEquals(256, c.quicMaxConnectionsPerIp)
        assertEquals(128, c.quicAcceptQueue)
    }

    /**
     * With `quicMaxConnectionsPerIp = 2` a third connection from the same address is dropped at its first Initial (the client
     * times out), and the engine's statistics count it as refused by the limits; the two before it are served.
     */
    @Test fun negative_perIpLimitOfTwoRefusesTheThirdConnection() =
        h3ServerTest {
            val (server, port) =
                tlsServer({ quicMaxConnectionsPerIp = 2 }) {
                    routing { get("/") { call.respondText("ok") } }
                }
            val client = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                val remote = InetSocketAddress("127.0.0.1", port)
                val tls = ServerFixtures.clientTls(alpn = listOf("h3"))
                val first = client.connect(remote, tls)
                val second = client.connect(remote, tls)
                for (c in listOf(first, second)) assertEquals(200, c.request(http3Request("GET", "server.test", "/")).status)
                val third = runCatching { client.connect(remote, tls, quicConfig { handshakeTimeout = 2.seconds }) }
                assertTrue(third.isFailure, "a third connection from one address was served with quicMaxConnectionsPerIp = 2")
                val stats = server.engine.http3Stats.single()
                assertTrue(stats.connectionsRefusedLimits >= 1, "the refusal is not counted: $stats")
                assertEquals(2L, stats.connectionsAccepted, "$stats")
                first.close()
                second.close()
            } finally {
                client.close()
                server.stop(100, 500)
            }
        }

    /** One statistics snapshot per HTTP/3 listener once the engine started; it counts the traffic served, and keeps it after the stop. */
    @Test fun statsReflectTraffic() =
        h3ServerTest {
            val server =
                kuicksilverServer(null, configure = {
                    tlsConnector(ServerFixtures.identity()) {
                        host = "127.0.0.1"
                        port = 0
                    }
                }) {
                    routing { get("/") { call.respondText("ok") } }
                }
            assertTrue(server.engine.http3Stats.isEmpty(), "statistics before the start")
            server.startSuspend(wait = false)
            val port =
                server.engine
                    .resolvedConnectors()
                    .first()
                    .port
            val client = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                val before = server.engine.http3Stats.single()
                assertEquals(0L, before.connectionsAccepted)
                val c = client.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                val body = c.request(http3Request("GET", "server.test", "/")).body
                assertEquals("ok", body.readFullBody().decodeToString())
                val after = server.engine.http3Stats.single()
                assertEquals(1L, after.connectionsAccepted, "$after")
                assertTrue(after.handshakesCompleted >= 1, "$after")
                assertTrue(after.datagramsReceived > before.datagramsReceived, "$after")
                assertTrue(after.datagramsSent > before.datagramsSent, "$after")
                c.close()
            } finally {
                client.close()
                server.stop(100, 500)
            }
            val final = server.engine.http3Stats.single()
            assertEquals(1L, final.connectionsAccepted, "the final counts after the stop: $final")
        }

    /** A server without HTTP/3 has no QUIC endpoint and so no statistics. */
    @Test fun noStatsWithoutHttp3() =
        serverTest {
            val (server, _) = tlsServer({ http3 = false }) {}
            try {
                assertTrue(server.engine.http3Stats.isEmpty())
            } finally {
                server.stop(100, 500)
            }
        }
}
