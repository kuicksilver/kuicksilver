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

    /** server.test with the connector's identity, proxy.internal with its own, whose override lists TCP's ALPN only. */
    private suspend fun twoNames(): Pair<Server, Int> {
        val proxy = proxyIdentity()
        val server = ServerFixtures.identity()
        return tlsServer(
            configure = { http3 = true },
            connector = {
                sniSelector = { hello ->
                    when (hello.serverName) {
                        "proxy.internal" -> ServerTlsOverride(proxy, alpn = listOf("http/1.1"))
                        "server.test" -> ServerTlsOverride(server)
                        else -> null
                    }
                }
            },
        ) { routing { get("/") { call.respondText("hello ${call.request.host()}") } } }
    }

    @Test fun eachNameGetsItsIdentityOverHttp3AndAltSvcLeadsThere() =
        h3ServerTest {
            val (server, port) = twoNames()
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
                        assertEquals("h3", c.quic.negotiatedAlpn, "the override's TCP ALPN list does not apply to HTTP/3")
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

    /** A name the selector does not serve: the QUIC handshake fails (unrecognized_name), as the TCP one does. */
    @Test fun negative_unknownNameRefusedOverHttp3() =
        h3ServerTest {
            val (server, port) = twoNames()
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
