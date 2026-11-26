// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.engine.connector
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.http3Request
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.IO
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** How `http3 { quic { } }` makes the HTTP/3 listeners' QUIC settings. */
class ServerQuicConfigTest {
    @kotlin.test.BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * 0-RTT and client certificates do not go together (`QuicServerConfig` refuses `earlyData` with a `clientAuth` other than
     * None; docs/guide/engine-tls.md, "Mutual TLS"): `http3 { earlyData { enabled } }` on an engine whose TLS connector asks for client certificates
     * fails the start with that message, instead of serving HTTP/3 without 0-RTT or HTTP/1.1 alone.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun negative_quicEarlyDataWithClientCertificatesFailsTheStart() =
        h3ServerTest {
            for (auth in listOf(ClientAuth.Optional, ClientAuth.Required)) {
                val e =
                    assertFailsWith<IllegalArgumentException>("clientAuth $auth") {
                        tlsServer({ http3 { earlyData { enabled = true } } }, connector = {
                            tls {
                                clientAuth = auth
                                clientTrust = TrustConfig.AnchoredCa(listOf(ServerFixtures.testCa))
                            }
                        }) {}
                    }
                assertEquals("acceptEarlyData cannot be combined with client certificates", e.message, "clientAuth $auth")
            }
        }

    @Test fun theQuicBlockReachesTheListeners() {
        val c = KuicksilverApplicationEngine.Configuration().apply { http3 { quic { maxIdleTimeout = 7.seconds } } }
        assertEquals(7.seconds, c.resolveQuic().maxIdleTimeout)
    }

    /**
     * `http3 { endpoint { loops = 4 } }` serves HTTP/3 on every platform with a QUIC server: four loops on the port, with SO_REUSEPORT where
     * the kernel balances (Linux, Android), else on one socket routed in process (macOS, iOS, Windows). Before 0.3.0 the
     * engine logged why and served HTTP/1.1 alone, without `Alt-Svc`, outside Linux and Android.
     */
    @Test fun udpSocketCountFourServesHttp3OnEveryPlatform() =
        h3ServerTest {
            val log = CapturedLog()
            val (server, port) =
                tlsServer({ http3 { endpoint { loops = 4 } } }, log = log) {
                    routing { get("/") { call.respondText("${call.request.httpVersion} ok") } }
                }
            try {
                val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertTrue(resp.contains("Alt-Svc: h3=\":$port\""), "no HTTP/3 advertised with four UDP loops: $resp ${log.lines}")
                val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
                try {
                    val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                    try {
                        val r = c.request(http3Request("GET", "server.test", "/"))
                        assertEquals(200, r.status)
                        assertEquals("HTTP/3 ok", r.body.readFullBody().decodeToString())
                    } finally {
                        c.close()
                    }
                } finally {
                    ep.close()
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * HTTP/3 needs the client to be able to open three unidirectional streams (RFC 9114 section 6.2): a server whose QUIC
     * settings grant fewer does not start, unless it serves no HTTP/3.
     */
    @Test fun negative_fewerThanThreeUniStreamsAreRefused() =
        serverTest {
            val e =
                assertFailsWith<IllegalArgumentException> {
                    val (server, _) = tlsServer({ http3 { quic { expert { maxUniStreams = 2 } } } }) {}
                    server.stop(100, 500)
                }
            assertTrue("RFC 9114 section 6.2" in e.message.orEmpty(), e.message)
            // refused whether HTTP/3 is served or not: the block is checked at every start
            assertFailsWith<IllegalArgumentException> {
                val (server, _) =
                    tlsServer({
                        http3 {
                            enabled = false
                            quic { expert { maxUniStreams = 2 } }
                        }
                    }) {}
                server.stop(100, 500)
            }
        }

    /**
     * A start that fails at a later connector stops the ones before it: a plain connector on a fixed port, then a TLS one
     * whose TLS configuration is refused while it is set up. Before, the failure left the first connector accepting.
     */
    @Test fun negative_aFailedStartLeavesNoEarlierConnectorAccepting() =
        serverTest {
            val selector =
                io.ktor.network.selector
                    .SelectorManager(kotlinx.coroutines.Dispatchers.IO)
            try {
                val probe =
                    io.ktor.network.sockets
                        .aSocket(selector)
                        .tcp()
                        .bind("127.0.0.1", 0)
                val port = (probe.localAddress as io.ktor.network.sockets.InetSocketAddress).port
                probe.close()
                val server =
                    kuicksilverServer(null, configure = {
                        connector {
                            host = "127.0.0.1"
                            this.port = port
                        }
                        tlsConnector {
                            tls {
                                identity = ServerFixtures.identity()
                                // key shares are a client's: the TLS configuration of this connector is refused as it is set up
                                keyExchangeGroups =
                                    io.kuicksilver.tls.KeyExchangeGroups(
                                        listOf(io.kuicksilver.tls.KeyExchangeGroups.X25519),
                                        setOf(io.kuicksilver.tls.KeyExchangeGroups.X25519),
                                    )
                            }
                            host = "127.0.0.1"
                            this.port = 0
                        }
                    }) {}
                assertFailsWith<io.kuicksilver.tls.TlsException.Config> { server.startSuspend(false) }
                assertEquals(0, server.engine.tcpConnectionsForProbe.size, "a connector that failed to start is still counted by the probe")
                // without stop(): the first connector's port is free again, its listener closed by the failed start itself
                val again =
                    kotlinx.coroutines.withTimeoutOrNull(5.seconds) {
                        var bound: io.ktor.network.sockets.ServerSocket? = null
                        while (bound == null) {
                            bound =
                                runCatching {
                                    io.ktor.network.sockets
                                        .aSocket(selector)
                                        .tcp()
                                        .bind("127.0.0.1", port)
                                }.getOrNull()
                            if (bound == null) kotlinx.coroutines.yield()
                        }
                        bound
                    } ?: error("port $port of the first connector still taken 5 s after the failed start")
                again.close()
                runCatching { server.stop(100, 500) }
            } finally {
                selector.close()
            }
        }

    @Test fun nothingSetKeepsTheDefault() {
        val q = KuicksilverApplicationEngine.Configuration().resolveQuic()
        assertEquals(QuicConfig.Default.maxIdleTimeout, q.maxIdleTimeout)
        assertEquals(QuicConfig.Default.maxBidiStreams, q.maxBidiStreams)
        assertEquals(QuicConfig.Default.initialStreamWindow, q.initialStreamWindow)
        assertEquals(QuicConfig.Default.resetStreamAt, q.resetStreamAt)
    }
}
