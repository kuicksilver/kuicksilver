// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.call
import io.ktor.server.request.host
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.http3Request
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.ServerTlsOverride
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * A TLS connector with an `sniSelector` serves HTTP/3 as well (RFC 6066 section 3 over QUIC): its TCP side advertises
 * `Alt-Svc`, and the QUIC side presents, per name, the identity the same selector chose, so the alternative service a client
 * is sent to is valid for the origin it came from (RFC 7838 section 2.1).
 */
class ServerSniHttp3Test {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun proxyIdentity() = TlsIdentity.fromDer(listOf(TestCerts.proxy), TestCerts.proxyKey.copyOf())

    private fun client(
        name: String,
        alpn: String,
    ) = tlsConfig(TlsRole.Client) {
        this.alpn = listOf(alpn)
        serverName = name
        trust = TrustConfig.AnchoredCa(listOf(ServerFixtures.testCa))
    }

    /**
     * server.test with the connector's identity; proxy.internal with its own, its answer listing `h3` next to TCP's
     * protocols; a.wild.test with the connector's identity, restricted to HTTP/1.1 (no `h3` in its answer).
     */
    private suspend fun names(): Pair<Server, Int> {
        val proxy = proxyIdentity()
        val server = ServerFixtures.identity()
        return tlsServer(
            configure = { http3 { enabled = true } },
            connector = {
                tls {
                    sniSelector = { hello ->
                        when (hello.serverName) {
                            "proxy.internal" -> ServerTlsOverride(proxy, alpn = listOf("h3", "http/1.1"))
                            "server.test" -> ServerTlsOverride(server)
                            "a.wild.test" -> ServerTlsOverride(server, alpn = listOf("http/1.1"))
                            else -> null
                        }
                    }
                }
            },
        ) { routing { get("/") { call.respondText("hello ${call.request.host()}") } } }
    }

    @Test fun eachNameGetsItsIdentityOverHttp3AndAltSvcLeadsThere() =
        h3ServerTest {
            val (server, port) = names()
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                for (name in listOf("server.test", "proxy.internal")) {
                    val tcp = rawHttp(port, "GET / HTTP/1.1\r\nHost: $name\r\nConnection: close\r\n\r\n", client(name, "http/1.1"))
                    assertTrue(tcp.contains("h3=\":$port\""), "$name: Alt-Svc for the same port: $tcp")
                    assertTrue(tcp.endsWith("hello $name"), tcp)
                    val c = ep.connect(InetSocketAddress("127.0.0.1", port), client(name, "h3"))
                    try {
                        val leaf = if (name == "proxy.internal") TestCerts.proxy else TestCerts.server
                        assertEquals(Certificate(leaf), c.quic.peerCertificates[0], name)
                        assertEquals("h3", c.quic.negotiatedAlpn)
                        val r = c.request(http3Request("GET", name, "/"))
                        assertEquals(200, r.status)
                    } finally {
                        c.close()
                    }
                }
            } finally {
                ep.close()
                server.stopSuspend(0, 1000)
            }
        }

    /**
     * A name whose answer lists ALPN without `h3` is not served over HTTP/3: its QUIC handshake ends with
     * no_application_protocol (RFC 7301 section 3.2, CRYPTO_ERROR 0x178), and its TCP responses advertise no alternative
     * (RFC 7838 section 2.1: an alternative must serve the origin), while the other names keep theirs.
     */
    @Test fun negative_aNameRestrictedToTcpIsNeitherServedNorAdvertisedOverHttp3() =
        h3ServerTest {
            val (server, port) = names()
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                val tcp =
                    rawHttp(port, "GET / HTTP/1.1\r\nHost: a.wild.test\r\nConnection: close\r\n\r\n", client("a.wild.test", "http/1.1"))
                assertTrue(tcp.startsWith("HTTP/1.1 200 ") && tcp.endsWith("hello a.wild.test"), tcp)
                assertFalse(tcp.contains("Alt-Svc", ignoreCase = true), "no Alt-Svc for a name without h3: $tcp")
                val e =
                    runCatching {
                        ep
                            .connect(
                                InetSocketAddress("127.0.0.1", port),
                                client("a.wild.test", "h3"),
                            ).request(http3Request("GET", "a.wild.test", "/"))
                    }.exceptionOrNull()
                val closed =
                    generateSequence(e) {
                        it.cause
                    }.filterIsInstance<io.kuicksilver.quic.QuicException.ConnectionLost.TransportClosed>().firstOrNull()
                assertEquals(0x100L + 120, closed?.code, "CRYPTO_ERROR no_application_protocol: $e")
                val other =
                    rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n", client("server.test", "http/1.1"))
                assertTrue(other.contains("h3=\":$port\""), "control: server.test still advertised: $other")
            } finally {
                ep.close()
                server.stopSuspend(0, 1000)
            }
        }

    /**
     * 0-RTT under SNI: a connection the server hands out at 0-RTT acceptance (the engine builds its 421 check right then,
     * possibly before the handshake completes) holds the name its identity was chosen for, so the check of its requests sent
     * in 0-RTT reads it (RFC 9110 section 7.4): one for its own name is served, one for another name the certificate covers
     * gets 421. Whether the server runs a request before the client's Finished arrives is loopback timing here;
     * `QuicSniApiTest.zeroRttAcceptedUnderTheChosenIdentity` holds the Finished back to pin that order.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun zeroRttRequestsAreCheckedAgainstTheNameTheirIdentityWasChosenFor() =
        h3ServerTest {
            val identity = ServerFixtures.identity()
            val (server, port) =
                tlsServer(
                    configure = {
                        http3 {
                            enabled = true
                            earlyData { enabled = true }
                        }
                    },
                    connector = {
                        tls {
                            sniSelector =
                                { hello -> if (hello.serverName == "server.test") ServerTlsOverride(identity) else null }
                        }
                    },
                ) { routing { get("/") { call.respondText("early=${call.request.receivedEarly}") } } }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            val target = InetSocketAddress("127.0.0.1", port)
            try {
                val first = ep.connect(target, client("server.test", "h3"))
                assertEquals(200, first.request(http3Request("GET", "server.test", "/")).status)
                first.close()
                // the ticket arrives after the handshake: a connection without one runs a full handshake, so try again
                var accepted = false
                for (attempt in 0 until 20) {
                    val c = ep.connectEarly(target, client("server.test", "h3"))
                    try {
                        fun early(host: String) = http3Request("GET", host, "/") { allowEarlyData = true }
                        val own = c.request(early("server.test"))
                        val other = c.request(early("a.wild.test"))
                        val ownBody = own.body.readFullBody().decodeToString()
                        c.quic.awaitHandshake()
                        if (c.quic.earlyDataAccepted != true) continue
                        accepted = true
                        assertEquals(200, own.status, "its own name is served on a 0-RTT connection")
                        assertTrue(ownBody.startsWith("early="), ownBody)
                        assertEquals(421, other.status, "another name the certificate names: 421, also early")
                        break
                    } finally {
                        c.close()
                    }
                }
                assertTrue(accepted, "no 0-RTT connection in 20 attempts")
            } finally {
                ep.close()
                server.stopSuspend(0, 1000)
            }
        }

    /** A name the selector does not serve: the QUIC handshake fails (unrecognized_name), as the TCP one does. */
    @Test fun negative_unknownNameRefusedOverHttp3() =
        h3ServerTest {
            val (server, port) = names()
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                val e =
                    runCatching {
                        ep
                            .connect(
                                InetSocketAddress("127.0.0.1", port),
                                client("other.test", "h3"),
                            ).request(http3Request("GET", "other.test", "/"))
                    }.exceptionOrNull()
                val closed =
                    generateSequence(e) {
                        it.cause
                    }.filterIsInstance<io.kuicksilver.quic.QuicException.ConnectionLost.TransportClosed>().firstOrNull()
                assertEquals(0x100L + 112, closed?.code, "CRYPTO_ERROR unrecognized_name: $e")
            } finally {
                ep.close()
                server.stopSuspend(0, 1000)
            }
        }
}
