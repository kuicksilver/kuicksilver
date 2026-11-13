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
import io.ktor.server.request.httpVersion
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
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration

/** The calls an application saw: authority, protocol and remote port of each, so a count that is off names the call. */
@OptIn(ExperimentalAtomicApi::class)
internal class Seen {
    private val calls = kotlin.concurrent.atomics.AtomicReference(emptyList<String>())

    fun record(call: io.ktor.server.application.ApplicationCall) {
        val r = call.request.local
        val line = "${r.serverHost}:${r.serverPort} ${call.request.httpVersion} ${r.scheme} from port ${r.remotePort}"
        while (true) {
            val now = calls.load()
            if (calls.compareAndSet(now, now + line)) break
        }
    }

    val count: Int get() = calls.load().size

    override fun toString(): String = calls.load().toString()
}

/** [expected] calls reached the application; the message lists them. */
internal fun assertCalls(
    expected: Int,
    seen: Seen,
    message: String = "calls the application saw",
) = assertEquals(expected, seen.count, "$message: $seen")

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
    ): Triple<Server, Int, Seen> {
        val seen = Seen()
        val (server, port) =
            tlsServer(
                configure = {
                    this.http2 = http2
                    this.http3 = http3
                },
                connector = connector,
            ) {
                intercept(ApplicationCallPipeline.Setup) { seen.record(context) }
                routing { get("/") { call.respondText("ok") } }
            }
        return Triple(server, port, seen)
    }

    /** The reasons the engine logs (debug level) with each 421, which docs/guide/troubleshooting.md quotes. */
    @Test fun negative_rejectionReasons() {
        val leaf = listOf(io.kuicksilver.tls.Certificate(TestCerts.server))
        assertEquals(null, misdirected(leaf, "https", "server.test", trustedGateway = false))
        assertEquals(
            "421 Misdirected Request for other.test: the certificate of this connection does not name it",
            misdirected(leaf, "https", "other.test", trustedGateway = false),
        )
        assertEquals(
            "421 Misdirected Request for other.test: an https request over a plain connection",
            misdirected(emptyList(), "https", "other.test", trustedGateway = false),
        )
        assertEquals(
            "421 Misdirected Request for b\u00fccher.test: not a valid host name or address",
            misdirected(leaf, "https", "b\u00fccher.test", trustedGateway = false),
        )
        assertEquals(
            "421 Misdirected Request for a.wild.test: the sniSelector chose this connection's TLS settings for another name",
            misdirected(leaf, "https", "a.wild.test", trustedGateway = false, sni = SniChoice("server.test")),
        )
        assertEquals(null, misdirected(leaf, "https", "other.test", trustedGateway = true))
        // over TLS every request with an authority is checked, whatever its scheme: the call reports the connection's https
        assertEquals(
            "421 Misdirected Request for other.test: the certificate of this connection does not name it",
            misdirected(leaf, "http", "other.test", trustedGateway = false),
        )
        assertEquals(null, misdirected(emptyList(), "http", "other.test", trustedGateway = false), "plain: http is served")
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
                assertCalls(1, seen, "the misdirected request never reached the application")
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
                assertCalls(named.size + 1, seen)
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
                        "127.000.000.001:$port", // a reg-name (RFC 3986 dec-octet has no leading zeros), not the address
                        "127.0.0.1.", // likewise: an IPv4address has no trailing dot
                    )
                for (host in unnamed) {
                    val r = rawHttp(port, "GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n")
                    assertEquals("421", status(r), "Host: $host\n$r")
                }
                val abs = rawHttp(port, "GET https://other.test/ HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertEquals("421", status(abs), abs)
                assertCalls(0, seen, "no misdirected request reached the application")
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
                assertCalls(1, seen)
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
                assertCalls(2, seen)
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
    ): Triple<Server, Int, Seen> {
        val seen = Seen()
        val server =
            kuicksilverServer(null, configure = { connector() }) {
                intercept(ApplicationCallPipeline.Setup) { seen.record(context) }
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
                assertCalls(0, seen, "no https request reached the application")
                for (head in listOf("GET / HTTP/1.1\r\nHost: other.test", "GET http://other.test/ HTTP/1.1\r\nHost: other.test")) {
                    val r = rawHttp(port, "$head\r\nConnection: close\r\n\r\n", tls = null)
                    assertEquals("200", status(r), "$head\n$r")
                }
                assertCalls(2, seen)
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
                assertCalls(1, seen)
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /**
     * The statuses of GET requests for [authorities], in order, on one HTTP/2 connection made with [tls]; the connection
     * must still be usable after them.
     */
    private suspend fun h2Statuses(
        port: Int,
        tls: io.kuicksilver.tls.TlsConfig,
        authorities: List<String>,
        scheme: String = "https",
    ): List<Int> {
        val selector = SelectorManager(Dispatchers.IO)
        try {
            val tcp = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
            val t = tcp.tls(tls)
            assertEquals("h2", t.negotiatedAlpn)
            return coroutineScope {
                val c =
                    H2ClientConnection.start(
                        t.openReadChannel(),
                        t.openWriteChannel(),
                        Http2Settings(),
                        this,
                        Duration.INFINITE,
                        { t.close() },
                    )
                val out =
                    authorities.map { authority ->
                        assertTrue(c.tryReserve())
                        val st = c.open("GET", scheme, authority, "/", emptyList(), endStream = true)
                        try {
                            st.response().status
                        } finally {
                            st.release()
                        }
                    }
                assertTrue(c.isUsable, "the connection still serves requests")
                c.abort(kotlinx.io.IOException("done"))
                out
            }
        } finally {
            selector.close()
        }
    }

    /** RFC 9113 section 9.1.1: a coalesced HTTP/2 request for an unnamed host gets 421 on its stream; the connection goes on. */
    @Test fun negative_h2CoalescedRequestGets421AndConnectionStaysUsable() =
        serverTest {
            val (server, port, seen) = countingServer(http2 = true)
            try {
                assertEquals(
                    listOf(421, 421, 200, 200),
                    h2Statuses(
                        port,
                        ServerFixtures.clientTls(alpn = listOf("h2")),
                        listOf("other.test", "a.b.wild.test:$port", "server.test:$port", "a.wild.test"),
                    ),
                )
                assertCalls(2, seen, "the misdirected requests never reached the application")
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /**
     * A connector whose `sniSelector` gives `a.wild.test` its own TLS policy (a client certificate required) and every other
     * name the default (none); the one certificate names both `server.test` and `a.wild.test`.
     */
    private suspend fun sniPolicyServer(
        http2: Boolean = false,
        trustedGateway: Boolean = false,
    ): Triple<Server, Int, Seen> {
        val identity = ServerFixtures.identity()
        val strict =
            ServerTlsOverride(
                identity,
                clientAuth = io.kuicksilver.tls.ClientAuth.Required,
                trust = TrustConfig.AnchoredCa(listOf(ServerFixtures.testCa)),
            )
        val open = ServerTlsOverride(identity)
        return countingServer(http2 = http2, connector = {
            sniSelector = { if (it.serverName == "a.wild.test") strict else open }
            this.trustedGateway = trustedGateway
        })
    }

    /** A client of [sniPolicyServer] for [serverName] (an IP literal sends no SNI), with the client certificate when [withCertificate]. */
    private fun via(
        serverName: String,
        withCertificate: Boolean = false,
        alpn: String = "http/1.1",
    ) = tlsConfig(TlsRole.Client) {
        this.alpn = listOf(alpn)
        this.serverName = serverName
        trust = TrustConfig.AnchoredCa(listOf(ServerFixtures.testCa))
        if (withCertificate) identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())
    }

    private suspend fun h1Status(
        port: Int,
        host: String,
        tls: io.kuicksilver.tls.TlsConfig,
    ): String = status(rawHttp(port, "GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n", tls))

    /**
     * RFC 9110 section 7.4 lets the server reject a request whose "connection context" is not appropriate for it, and
     * section 15.5.20 makes 421 the answer for a target URI that "does not match the connection context over which the
     * request was received". A connection made for `server.test`, without a client certificate, must not carry a request
     * for `a.wild.test`, whose TLS policy requires one, although the certificate names it.
     */
    @Test fun negative_h1RequestForStricterSniPolicyOnLaxConnectionGets421() =
        serverTest {
            val (server, port, seen) = sniPolicyServer()
            try {
                assertEquals("421", h1Status(port, "a.wild.test", via("server.test")))
                assertEquals("421", h1Status(port, "a.wild.test", via("127.0.0.1")), "a connection without SNI")
                assertCalls(0, seen)
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /** And the other way round: a request for `server.test` on `a.wild.test`'s connection gets 421 too. */
    @Test fun negative_h1RequestForAnotherSniPolicyOnStrictConnectionGets421() =
        serverTest {
            val (server, port, seen) = sniPolicyServer()
            try {
                assertEquals("421", h1Status(port, "server.test", via("a.wild.test", withCertificate = true)))
                assertEquals("421", h1Status(port, "127.0.0.1:$port", via("a.wild.test", withCertificate = true)))
                assertCalls(0, seen)
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /** Each connection serves the name its TLS settings were chosen for; one without SNI serves address literals. */
    @Test fun sniPolicyConnectionsServeTheirOwnName() =
        serverTest {
            val (server, port, seen) = sniPolicyServer()
            try {
                assertEquals("200", h1Status(port, "server.test:$port", via("server.test")))
                assertEquals("200", h1Status(port, "A.Wild.Test.", via("a.wild.test", withCertificate = true)))
                assertEquals("200", h1Status(port, "127.0.0.1:$port", via("127.0.0.1")))
                assertEquals("421", h1Status(port, "server.test", via("127.0.0.1")), "a name on a connection without SNI")
                assertEquals("421", h1Status(port, "127.0.0.1", via("server.test")), "an address on a connection with SNI")
                assertCalls(3, seen)
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /** The same over HTTP/2: the stream gets 421, the connection goes on. (HTTP/3 never runs on a connector with an `sniSelector`.) */
    @Test fun negative_h2RequestForAnotherSniPolicyGets421() =
        serverTest {
            val (server, port, seen) = sniPolicyServer(http2 = true)
            try {
                assertEquals(listOf(421, 200), h2Statuses(port, via("server.test", alpn = "h2"), listOf("a.wild.test", "server.test")))
                assertEquals(
                    listOf(421, 200),
                    h2Statuses(port, via("a.wild.test", withCertificate = true, alpn = "h2"), listOf("server.test", "a.wild.test:$port")),
                )
                assertCalls(2, seen)
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /** A trusted gateway's connections are not checked against SNI either. */
    @Test fun trustedGatewayConnectorServesAnyNameOverSniPolicy() =
        serverTest {
            val (server, port, seen) = sniPolicyServer(trustedGateway = true)
            try {
                assertEquals("200", h1Status(port, "a.wild.test", via("server.test")))
                assertCalls(1, seen)
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /**
     * A target URI with another scheme than https on a TLS connection: the application still sees an https call for that
     * host, so the host is checked as for https (over HTTP/1.1 an absolute-form `http://` target).
     */
    @Test fun negative_h1HttpTargetOnTlsConnectionIsChecked() =
        serverTest {
            val (server, port, seen) = countingServer()
            try {
                val r = rawHttp(port, "GET http://other.test/ HTTP/1.1\r\nHost: other.test\r\nConnection: close\r\n\r\n")
                assertEquals("421", status(r), r)
                assertCalls(0, seen)
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /** The same over HTTP/2 (`:scheme` http). */
    @Test fun negative_h2HttpSchemeOnTlsConnectionIsChecked() =
        serverTest {
            val (server, port, seen) = countingServer(http2 = true)
            try {
                assertEquals(
                    listOf(421, 200),
                    h2Statuses(port, ServerFixtures.clientTls(alpn = listOf("h2")), listOf("other.test", "server.test"), scheme = "http"),
                )
                assertCalls(1, seen)
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /** A request for an mTLS name with `http://` must not slip past the SNI policy either. */
    @Test fun negative_h1HttpTargetForStricterSniPolicyGets421() =
        serverTest {
            val (server, port, seen) = sniPolicyServer()
            try {
                val r =
                    rawHttp(port, "GET http://a.wild.test/ HTTP/1.1\r\nHost: a.wild.test\r\nConnection: close\r\n\r\n", via("server.test"))
                assertEquals("421", status(r), r)
                assertCalls(0, seen)
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /**
     * Over HTTP/1.1 the 421 is the engine's own, as over HTTP/2 and HTTP/3: the application's send pipeline (StatusPages,
     * logging, compression) never runs for it, and it carries Date (RFC 9110 section 6.6.1).
     */
    @Test fun negative_h1MisdirectedNeverRunsTheApplicationPipelines() =
        serverTest {
            val sent = Seen()
            val (server, port) =
                tlsServer {
                    sendPipeline.intercept(io.ktor.server.response.ApplicationSendPipeline.Before) { sent.record(context) }
                    routing { get("/") { call.respondText("ok") } }
                }
            try {
                val r =
                    rawHttp(
                        port,
                        "GET / HTTP/1.1\r\nHost: other.test\r\n\r\nGET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n",
                    )
                assertEquals(listOf("421", "200"), statuses(r), r)
                assertTrue(r.substringBefore("HTTP/1.1 200").contains("\r\nDate: "), r)
                assertCalls(1, sent, "send pipelines")
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /**
     * A misdirected request that expects 100-continue gets the 421 without a 100 (a final status the head determines, RFC
     * 9110 section 10.1.1), and since its content may still come, the connection closes after it and says so (RFC 9112
     * section 9.6).
     */
    @Test fun negative_h1MisdirectedWithExpectContinueSendsNo100AndCloses() =
        serverTest {
            val (server, port, seen) = countingServer()
            try {
                val r = rawHttp(port, "POST / HTTP/1.1\r\nHost: other.test\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n")
                assertTrue(r.startsWith("HTTP/1.1 421 "), r)
                assertTrue("100 Continue" !in r, r)
                assertTrue("\r\nConnection: close\r\n" in r, r)
                assertTrue("\r\nDate: " in r, r)
                assertCalls(0, seen)
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /** A misdirected request's content is read past, and the request pipelined after it is served on the same connection. */
    @Test fun negative_h1MisdirectedWithContentThenPipelinedRequest() =
        serverTest {
            val (server, port, seen) = countingServer()
            try {
                val r =
                    rawHttp(
                        port,
                        "POST / HTTP/1.1\r\nHost: other.test\r\nContent-Length: 5\r\n\r\nhello" +
                            "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n",
                    )
                assertEquals(listOf("421", "200"), statuses(r), r)
                assertTrue(r.endsWith("ok"), r)
                assertCalls(1, seen)
            } finally {
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
                    val misdirected = c.request(http3Request("GET", "other.test", "/"))
                    assertEquals(421, misdirected.status)
                    assertTrue(misdirected.headers["date"] != null, "RFC 9110 section 6.6.1: Date on a 4xx")
                    assertEquals(421, c.request(http3Request("GET", "other.test", "/") { scheme = "http" }).status, ":scheme http")
                    assertEquals(421, c.request(http3Request("GET", "127.0.0.2:$port", "/")).status)
                    assertEquals(200, c.request(http3Request("GET", "server.test:$port", "/")).status)
                    assertEquals(200, c.request(http3Request("GET", "a.wild.test", "/")).status)
                } finally {
                    c.close()
                }
                assertCalls(2, seen, "the misdirected requests never reached the application")
            } finally {
                ep.close()
                server.stopSuspend(0, 1000)
            }
        }
}
