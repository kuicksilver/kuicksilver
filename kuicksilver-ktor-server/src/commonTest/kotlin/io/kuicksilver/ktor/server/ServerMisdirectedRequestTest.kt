// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.engine.connector
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.runtime.H2ClientConnection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.http3Request
import io.kuicksilver.ktor.network.connectTcp
import io.kuicksilver.ktor.network.tls
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.ServerTlsOverride
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.coroutineScope
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration

/**
 * RFC 9110 section 7.4: "a request for an "https" resource MUST be rejected unless it has been received over a connection
 * that has been secured via a certificate valid for that target URI's origin". The server's certificate names `server.test`,
 * `*.wild.test`, 127.0.0.1 and ::1. A browser that reuses a connection for another host of the same address (RFC 9113
 * section 9.1.1, RFC 9114 section 3.3) sends requests for a host this certificate does not name: each gets 421 and never
 * reaches the application, and on HTTP/2 and HTTP/3 the connection serves the next request.
 */
@OptIn(ExperimentalAtomicApi::class)
class ServerMisdirectedRequestTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A server whose application counts the calls it saw and answers 200 "ok" to any GET /. */
    private suspend fun countingServer(
        connector: KuicksilverTlsConnector.Builder.() -> Unit = {},
        http2: Boolean = false,
        http3: Boolean = false,
    ): Triple<Server, Int, AtomicInt> {
        val seen = AtomicInt(0)
        val (server, port) =
            tlsServer(
                configure = {
                    this.http2 = http2
                    this.http3 = http3
                },
                connector = connector,
            ) {
                intercept(ApplicationCallPipeline.Setup) { seen.incrementAndFetch() }
                routing { get("/") { call.respondText("ok") } }
            }
        return Triple(server, port, seen)
    }

    private fun status(response: String): String = response.substringAfter("HTTP/1.1 ").substringBefore(' ')

    /** Every response status of [raw], in order. */
    private fun statuses(raw: String): List<String> = Regex("HTTP/1\\.1 (\\d{3}) ").findAll(raw).map { it.groupValues[1] }.toList()

    @Test fun negative_h1HostTheCertificateDoesNotNameGets421() =
        serverTest {
            val (server, port, seen) = countingServer()
            try {
                // SNI server.test, then a request for another host on the same connection; then one it names
                val raw =
                    rawHttp(
                        port,
                        "GET / HTTP/1.1\r\nHost: other.test\r\n\r\n" +
                            "GET / HTTP/1.1\r\nHost: server.test:$port\r\nConnection: close\r\n\r\n",
                    )
                assertEquals(listOf("421", "200"), statuses(raw), raw)
                assertEquals(1, seen.load(), "the misdirected request never reached the application")
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    @Test fun h1HostsTheCertificateNames() =
        serverTest {
            val (server, port, seen) = countingServer()
            try {
                val named =
                    listOf("server.test", "SERVER.Test.", "server.test:1", "a.wild.test", "x-1.WILD.test:$port", "127.0.0.1:$port", "[::1]")
                for (host in named) {
                    val r = rawHttp(port, "GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n")
                    assertEquals("200", status(r), "Host: $host\n$r")
                }
                // absolute-form: its authority is the target's (RFC 9112 section 3.2.2), whatever Host says
                val abs = rawHttp(port, "GET https://server.test/ HTTP/1.1\r\nHost: other.test\r\nConnection: close\r\n\r\n")
                assertEquals("200", status(abs), abs)
                assertEquals(named.size + 1, seen.load())
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    @Test fun negative_h1HostsTheCertificateDoesNotName() =
        serverTest {
            val (server, port, seen) = countingServer()
            try {
                val unnamed =
                    listOf(
                        "other.test",
                        "wild.test", // the wildcard needs a label in its place
                        "a.b.wild.test", // and stands for one label only
                        "server.test.evil.test",
                        "127.0.0.2:$port",
                        "[::2]",
                        "xn--bcher-kva.test",
                    )
                for (host in unnamed) {
                    val r = rawHttp(port, "GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n")
                    assertEquals("421", status(r), "Host: $host\n$r")
                }
                val abs = rawHttp(port, "GET https://other.test/ HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertEquals("421", status(abs), abs)
                assertEquals(0, seen.load(), "no misdirected request reached the application")
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /** The exception RFC 9110 section 7.4 makes: "Unless the connection is from a trusted gateway". */
    @Test fun trustedGatewayConnectorServesAnyHost() =
        serverTest {
            val (server, port, seen) = countingServer(connector = { trustedGateway = true })
            try {
                val r = rawHttp(port, "GET / HTTP/1.1\r\nHost: other.test\r\nConnection: close\r\n\r\n")
                assertEquals("200", status(r), r)
                assertEquals(1, seen.load())
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /**
     * The certificate checked is the one this connection presented: an `sniSelector` that answers `proxy.internal` with a
     * certificate naming only that host makes `server.test`, which the default identity names, misdirected on that connection.
     */
    @Test fun negative_h1CertificateChosenBySniIsTheOneChecked() =
        serverTest {
            val proxy = TlsIdentity.fromDer(listOf(TestCerts.proxy), TestCerts.proxyKey.copyOf())
            val (server, port, seen) =
                countingServer(connector = {
                    sniSelector = { ServerTlsOverride(if (it.serverName == "proxy.internal") proxy else ServerFixtures.identity()) }
                })
            try {
                val viaProxyName =
                    tlsConfig(TlsRole.Client) {
                        alpn = listOf("http/1.1")
                        serverName = "proxy.internal"
                        trust = TrustConfig.AnchoredCa(listOf(ServerFixtures.testCa))
                    }
                for (host in listOf("server.test", "a.wild.test", "127.0.0.1")) {
                    val r = rawHttp(port, "GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n", viaProxyName)
                    assertEquals("421", status(r), "Host: $host over the proxy.internal identity\n$r")
                }
                val own = rawHttp(port, "GET / HTTP/1.1\r\nHost: proxy.internal\r\nConnection: close\r\n\r\n", viaProxyName)
                assertEquals("200", status(own), own)
                // the default identity (SNI server.test) still serves server.test, and not proxy.internal
                assertEquals("200", status(rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")))
                assertEquals("421", status(rawHttp(port, "GET / HTTP/1.1\r\nHost: proxy.internal\r\nConnection: close\r\n\r\n")))
                assertEquals(2, seen.load())
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /** A server with one plain connector ([connector]) whose application counts its calls. */
    private suspend fun plainCountingServer(
        connector: KuicksilverApplicationEngine.Configuration.() -> Unit = {
            connector {
                host = "127.0.0.1"
                port = 0
            }
        },
    ): Triple<Server, Int, AtomicInt> {
        val seen = AtomicInt(0)
        val server =
            kuicksilverServer(null, configure = { connector() }) {
                intercept(ApplicationCallPipeline.Setup) { seen.incrementAndFetch() }
                routing { get("/") { call.respondText("ok") } }
            }
        server.startSuspend(wait = false)
        val port =
            server.engine
                .resolvedConnectors()
                .first()
                .port
        return Triple(server, port, seen)
    }

    /**
     * A plain connection is secured by no certificate: an absolute-form `https` target over it is a request for an "https"
     * resource that "MUST be rejected" (RFC 9110 section 7.4); origin-form requests (what a gateway in front sends) and
     * `http` targets are served for any host.
     */
    @Test fun negative_plainConnectorRejectsAbsoluteFormHttps() =
        serverTest {
            val (server, port, seen) = plainCountingServer()
            try {
                for (target in listOf("https://server.test/", "HTTPS://other.test:8443/")) {
                    val r = rawHttp(port, "GET $target HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n", tls = null)
                    assertEquals("421", status(r), "$target\n$r")
                }
                assertEquals(0, seen.load(), "no https request reached the application")
                for (head in listOf("GET / HTTP/1.1\r\nHost: other.test", "GET http://other.test/ HTTP/1.1\r\nHost: other.test")) {
                    val r = rawHttp(port, "$head\r\nConnection: close\r\n\r\n", tls = null)
                    assertEquals("200", status(r), "$head\n$r")
                }
                assertEquals(2, seen.load())
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /** `plainConnector { trustedGateway = true }`: the clients are trusted gateways, so absolute-form https targets are served. */
    @Test fun trustedGatewayPlainConnectorServesAbsoluteFormHttps() =
        serverTest {
            val (server, port, seen) =
                plainCountingServer {
                    plainConnector {
                        host = "127.0.0.1"
                        port = 0
                        trustedGateway = true
                    }
                }
            try {
                val r = rawHttp(port, "GET https://other.test/ HTTP/1.1\r\nHost: other.test\r\nConnection: close\r\n\r\n", tls = null)
                assertEquals("200", status(r), r)
                assertEquals(1, seen.load())
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /** RFC 9113 section 9.1.1: a coalesced HTTP/2 request for an unnamed host gets 421 on its stream; the connection goes on. */
    @Test fun negative_h2CoalescedRequestGets421AndConnectionStaysUsable() =
        serverTest {
            val (server, port, seen) = countingServer(http2 = true)
            val selector = SelectorManager(Dispatchers.IO)
            try {
                val tcp = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                val t = tcp.tls(ServerFixtures.clientTls(alpn = listOf("h2")))
                assertEquals("h2", t.negotiatedAlpn)
                coroutineScope {
                    val c =
                        H2ClientConnection.start(
                            t.openReadChannel(),
                            t.openWriteChannel(),
                            Http2Settings(),
                            this,
                            Duration.INFINITE,
                            { t.close() },
                        )

                    suspend fun get(authority: String): Int {
                        assertTrue(c.tryReserve())
                        val s = c.open("GET", "https", authority, "/", emptyList(), endStream = true)
                        try {
                            return s.response().status
                        } finally {
                            s.release()
                        }
                    }
                    assertEquals(421, get("other.test"))
                    assertEquals(421, get("a.b.wild.test:$port"))
                    assertEquals(200, get("server.test:$port"), "the connection still serves the hosts it is authoritative for")
                    assertEquals(200, get("a.wild.test"))
                    assertTrue(c.isUsable)
                    c.abort(kotlinx.io.IOException("done"))
                }
                assertEquals(2, seen.load(), "the misdirected requests never reached the application")
            } finally {
                selector.close()
                server.stopSuspend(0, 1000)
            }
        }

    /** RFC 9114 section 3.3: the same over HTTP/3. */
    @Test fun negative_h3CoalescedRequestGets421AndConnectionStaysUsable() =
        h3ServerTest {
            val (server, port, seen) = countingServer(http3 = true)
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                try {
                    assertEquals(421, c.request(http3Request("GET", "other.test", "/")).status)
                    assertEquals(421, c.request(http3Request("GET", "127.0.0.2:$port", "/")).status)
                    assertEquals(200, c.request(http3Request("GET", "server.test:$port", "/")).status)
                    assertEquals(200, c.request(http3Request("GET", "a.wild.test", "/")).status)
                } finally {
                    c.close()
                }
                assertEquals(2, seen.load(), "the misdirected requests never reached the application")
            } finally {
                ep.close()
                server.stopSuspend(0, 1000)
            }
        }
}
