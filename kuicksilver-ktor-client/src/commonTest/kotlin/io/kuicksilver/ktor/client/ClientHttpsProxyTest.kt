// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.network.sockets.ConnectTimeoutException
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.server.application.install
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.readText
import io.kuicksilver.ktor.network.bindTcp
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyReason
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.io.encoding.Base64
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import io.ktor.server.websocket.webSocket as serverWebSocket

/**
 * An `https://` proxy: TLS to the proxy itself (as curl's HTTPS proxy and Chrome's `HTTPS` PAC entries), the CONNECT
 * tunnel and the absolute form inside it (RFC 9110 section 9.3.6, RFC 9112 section 3.2.2), the proxy's certificate
 * checked against the proxy's name (RFC 9525, SNI per RFC 6066 section 3), the origin's TLS inside the tunnel unchanged.
 * The proxy is the project's own TLS server on 127.0.0.1 ([tlsProxy]); `proxy.internal` and `server.test` reach it
 * through the engine's `dns`. Threat model 3.28.
 */
class ClientHttpsProxyTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val loopback = IpAddress.parse("127.0.0.1")

    /** A resolver that answers 127.0.0.1 for [names] and records every name it is asked for. */
    private class Recording(
        private val names: Set<String>,
    ) : Dns {
        private val lock = Mutex()
        private val asked = ArrayList<String>()

        override suspend fun lookup(host: String): List<IpAddress> {
            lock.withLock { asked += host }
            return if (host in names) listOf(IpAddress.parse("127.0.0.1")) else emptyList()
        }

        suspend fun asked(): List<String> = lock.withLock { asked.toList() }
    }

    private fun KuicksilverEngineConfig.through(proxy: ResolvedProxy) {
        if (dns === Dns.System) dns = Recording(setOf("proxy.internal", "server.test"))
        proxyResolver = ProxyResolver { proxy }
        connectTimeout = 10.seconds
    }

    private suspend fun origin(
        altSvc: Boolean = false,
        http2: Boolean = false,
        block: suspend (port: Int) -> Unit,
    ) {
        val (server, port) =
            testServer(configure = { this.http2 = http2 }) {
                routing {
                    get("/") {
                        if (altSvc) call.response.header("Alt-Svc", "h3=\":443\"; ma=3600")
                        call.respondText(
                            "through|${call.request.headers[HttpHeaders.ProxyAuthorization]}",
                        )
                    }
                }
            }
        try {
            block(port)
        } finally {
            server.stop(100, 500)
        }
    }

    /**
     * TLS to the proxy, then the CONNECT inside it, then the origin's own TLS inside the tunnel (TLS in TLS): the proxy's
     * handshake carries SNI `proxy.internal` and offers ALPN `http/1.1` only, the CONNECT names the origin, the engine's
     * `dns` is asked for the proxy's name and never for the origin's, and the origin's certificate is still checked
     * against `server.test`.
     */
    @Test fun httpsOriginGoesThroughTlsToTheProxy() =
        clientTest {
            origin { originPort ->
                tlsProxy(originPort) { proxyPort, seen ->
                    val dns = Recording(setOf("proxy.internal"))
                    testClient(engine = {
                        this.dns = dns
                        through(ResolvedProxy.https("proxy.internal", proxyPort))
                    }).use { c ->
                        assertEquals("through|null", c.get("https://server.test:$originPort/").bodyAsText())
                    }
                    assertEquals(listOf("proxy.internal"), dns.asked().distinct(), "the resolver was asked for the origin")
                    val hello = seen.hellos().single()
                    assertEquals("proxy.internal", hello.serverName, "SNI to the proxy")
                    assertEquals(listOf("http/1.1"), hello.alpn, "ALPN offered to the proxy")
                    assertEquals("CONNECT server.test:$originPort HTTP/1.1", seen.heads().single().first())
                }
            }
        }

    /**
     * Plain `http` through an `https://` proxy: the absolute form (RFC 9112 section 3.2.2) inside TLS to the proxy, with the
     * credentials, and the connection to the proxy kept for the next request (one handshake, one connection).
     */
    @Test fun plainOriginGoesInAbsoluteFormOverTlsAndIsPooled() =
        clientTest {
            val lines = ArrayList<String>()
            tlsProxy(absolute = { head, out ->
                lines += head.first()
                val body = head.firstOrNull { it.startsWith("Proxy-Authorization:", ignoreCase = true) }.orEmpty()
                out.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n$body")
            }) { proxyPort, seen ->
                val credentials = ProxyCredentials("alice", "S3cRtQ")
                testClient(engine = { through(ResolvedProxy.https("proxy.internal", proxyPort, credentials)) }).use { c ->
                    val expected = "Proxy-Authorization: Basic " + Base64.encode("alice:S3cRtQ".encodeToByteArray())
                    assertEquals(expected, c.get("http://server.test:8080/x").bodyAsText())
                    assertEquals(expected, c.get("http://server.test:8080/y").bodyAsText())
                }
                assertEquals(listOf("GET http://server.test:8080/x HTTP/1.1", "GET http://server.test:8080/y HTTP/1.1"), lines)
                assertEquals(1, seen.accepted(), "the TLS connection to the proxy was not reused")
                assertEquals(1, seen.hellos().size)
            }
        }

    /**
     * A proxy whose certificate comes from a CA the engine does not trust: the handshake with the proxy fails with
     * [ProxyTlsException] (its cause the verification failure), and nothing of the request, credentials included, crosses
     * the wire: the tap in front of the proxy sees only the ClientHello and the alert.
     */
    @Test fun negative_proxyCertificateFromAnUntrustedCaFails() =
        clientTest {
            tlsProxy(cert = TestCerts.serverOtherCa, key = TestCerts.serverOtherCaKey) { proxyPort, seen ->
                wireTap(proxyPort) { tapPort, sent ->
                    val credentials = ProxyCredentials("alice", "S3cRtQ")
                    testClient(engine = { through(ResolvedProxy.https("server.test", tapPort, credentials)) }).use { c ->
                        val e = assertFailsWith<ProxyTlsException> { c.get("https://server.test:1/").bodyAsText() }
                        assertIs<TlsException.Verify>(e.cause, "$e")
                        assertNull(e.replyCode)
                        assertTrue("server.test" in e.message!!, e.message)
                    }
                    assertNoCredentials(sent())
                }
                assertEquals(emptyList(), seen.heads(), "a request reached the proxy")
            }
        }

    /**
     * The proxy presents the origin's certificate (valid for `server.test` and 127.0.0.1, under the trusted CA) while it
     * is configured as `proxy.internal`: its name is checked against the proxy's name, so the handshake fails with a
     * host-name mismatch. The origin's [TrustConfig.ExpectedName] (which names `server.test`) does not carry over to the
     * proxy: it would make exactly this certificate pass.
     */
    @Test fun negative_proxyCertificateValidForTheOriginButNotTheProxyFails() =
        clientTest {
            tlsProxy(cert = TestCerts.server, key = TestCerts.serverKey) { proxyPort, seen ->
                for (originTrust in listOf(ClientFixtures.trust, TrustConfig.ExpectedName("server.test", ClientFixtures.trust))) {
                    testClient(engine = {
                        trust = originTrust
                        through(ResolvedProxy.https("proxy.internal", proxyPort))
                    }).use { c ->
                        val e = assertFailsWith<ProxyTlsException>("$originTrust") { c.get("https://server.test:1/").bodyAsText() }
                        val verify = assertIs<TlsException.Verify>(e.cause, "$e")
                        assertIs<VerifyReason.HostnameMismatch>(verify.reason, "$verify")
                    }
                }
                assertEquals(emptyList(), seen.heads(), "a request reached the proxy")
            }
        }

    /**
     * A proxy named by an IP address is checked against that address (an IP-ID, RFC 9525 section 6.2.1) and gets no SNI
     * (RFC 6066 section 3: "Literal IPv4 and IPv6 addresses are not permitted in HostName"): the origin's certificate
     * carries IP 127.0.0.1 and passes there, the proxy's (DNS `proxy.internal` only) does not.
     */
    @Test fun proxyNamedByAddressIsCheckedAgainstTheAddressWithoutSni() =
        clientTest {
            origin { originPort ->
                tlsProxy(originPort, cert = TestCerts.server, key = TestCerts.serverKey) { proxyPort, seen ->
                    testClient(engine = { through(ResolvedProxy.https("127.0.0.1", proxyPort)) }).use { c ->
                        assertEquals("through|null", c.get("https://server.test:$originPort/").bodyAsText())
                    }
                    assertNull(seen.hellos().single().serverName, "SNI with an IP literal")
                }
            }
            tlsProxy { proxyPort, _ ->
                testClient(engine = { through(ResolvedProxy.https("127.0.0.1", proxyPort)) }).use { c ->
                    val e = assertFailsWith<ProxyTlsException> { c.get("https://server.test:1/").bodyAsText() }
                    assertIs<VerifyReason.HostnameMismatch>(assertIs<TlsException.Verify>(e.cause).reason)
                }
            }
        }

    /**
     * A failure of the origin's TLS inside the tunnel stays the origin's: a [TlsException], never a [ProxyException]. The
     * origin's pins apply to the origin only: the proxy (another key) is not checked against them, and a wrong pin still
     * fails the origin.
     */
    @Test fun negative_originTlsFailureIsNotAProxyFailure() =
        clientTest {
            origin { originPort ->
                tlsProxy(originPort) { proxyPort, _ ->
                    // a name the origin's certificate does not carry
                    testClient(engine = { through(ResolvedProxy.https("proxy.internal", proxyPort)) }).use { c ->
                        val e = assertFailsWith<Throwable> { c.get("https://wrong.test:$originPort/").bodyAsText() }
                        assertOriginTlsFailure(e)
                    }
                }
                tlsProxy(originPort) { proxyPort, _ ->
                    val right = TrustConfig.Pinned(setOf(SpkiSha256(TestCerts.serverSpkiSha256)), base = ClientFixtures.trust)
                    testClient(engine = {
                        trust = right
                        through(ResolvedProxy.https("proxy.internal", proxyPort))
                    }).use { c ->
                        assertEquals("through|null", c.get("https://server.test:$originPort/").bodyAsText())
                    }
                }
                tlsProxy(originPort) { proxyPort, _ ->
                    val wrong = TrustConfig.Pinned(setOf(SpkiSha256(ByteArray(32))), base = ClientFixtures.trust)
                    testClient(engine = {
                        trust = wrong
                        through(ResolvedProxy.https("proxy.internal", proxyPort))
                    }).use { c ->
                        val e = assertFailsWith<Throwable> { c.get("https://server.test:$originPort/").bodyAsText() }
                        assertOriginTlsFailure(e)
                    }
                }
            }
        }

    private fun assertOriginTlsFailure(e: Throwable) {
        val chain = generateSequence(e) { it.cause }.toList()
        assertTrue(chain.any { it is TlsException }, "$e")
        assertFalse(chain.any { it is ProxyException }, "an origin failure reported as the proxy's: $e")
    }

    /**
     * The proxy's trust is configured on its own (`proxyTls`): a proxy under another CA passes with that CA there while
     * the origin keeps the engine's `trust`.
     */
    @Test fun proxyTrustIsConfiguredSeparately() =
        clientTest {
            origin { originPort ->
                tlsProxy(originPort, cert = TestCerts.serverOtherCa, key = TestCerts.serverOtherCaKey) { proxyPort, _ ->
                    testClient(engine = {
                        through(ResolvedProxy.https("server.test", proxyPort))
                        proxyTls = { trust = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.otherCa))) }
                    }).use { c ->
                        assertEquals("through|null", c.get("https://server.test:$originPort/").bodyAsText())
                    }
                }
            }
        }

    /**
     * Credentials for an `https://` proxy cross the wire only inside TLS: the tap in front of the proxy sees neither the
     * user name, the password, their Basic encoding nor the field name, for a CONNECT (with configured credentials and
     * with a request's own `Proxy-Authorization`, the application's authenticator hook) and for the absolute form; the
     * proxy, inside TLS, got them all.
     */
    @Test fun negative_proxyCredentialsNeverCrossThePlainSocket() =
        clientTest {
            origin { originPort ->
                tlsProxy(originPort, absolute = { _, out ->
                    out.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabs")
                }) { proxyPort, seen ->
                    wireTap(proxyPort) { tapPort, sent ->
                        val credentials = ProxyCredentials("alice", "S3cRtQ")
                        testClient(engine = { through(ResolvedProxy.https("proxy.internal", tapPort, credentials)) }).use { c ->
                            assertEquals("through|null", c.get("https://server.test:$originPort/").bodyAsText())
                            assertEquals("abs", c.get("http://server.test:8080/").bodyAsText())
                        }
                        // a new client: the first one's tunnel would carry this request without a new CONNECT
                        testClient(engine = { through(ResolvedProxy.https("proxy.internal", tapPort)) }).use { c ->
                            val own = "Basic " + Base64.encode("bob:S3cRtQ".encodeToByteArray())
                            val body =
                                c
                                    .get("https://server.test:$originPort/") {
                                        header(HttpHeaders.ProxyAuthorization, own)
                                    }.bodyAsText()
                            assertEquals("through|null", body, "the origin got the proxy's credentials (HTTP/1.1 in the tunnel)")
                        }
                        assertNoCredentials(sent())
                        assertFalse(sent().containsBytes("bob".encodeToByteArray()))
                    }
                    val authorizations =
                        seen.heads().map { head -> head.firstOrNull { it.startsWith("Proxy-Authorization:", ignoreCase = true) } }
                    val basic = "Proxy-Authorization: Basic " + Base64.encode("alice:S3cRtQ".encodeToByteArray())
                    assertEquals(
                        listOf(basic, basic, "Proxy-Authorization: Basic " + Base64.encode("bob:S3cRtQ".encodeToByteArray())),
                        authorizations,
                    )
                }
            }
        }

    private fun assertNoCredentials(wire: ByteArray) {
        assertTrue(wire.isNotEmpty(), "the tap saw nothing: the test proves nothing")
        for (secret in listOf("alice", "S3cRtQ", Base64.encode("alice:S3cRtQ".encodeToByteArray()), "Proxy-Authorization", "CONNECT")) {
            assertFalse(wire.containsBytes(secret.encodeToByteArray()), "'$secret' crossed the wire outside TLS")
        }
    }

    /**
     * A proxy that answers every CONNECT with 407, credentials or not: the request fails with [ProxyException] 407 after
     * one CONNECT (the configured credentials went with it), never a loop of retries; a request's own
     * `Proxy-Authorization` gets one CONNECT too. A plain `http` request (absolute form) gets the proxy's 407 as its
     * response, once.
     */
    @Test fun negative_proxyAuthenticationLoopEndsAfterOneAttempt() =
        clientTest {
            val challenge =
                "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"p\"\r\n" +
                    "Content-Length: 0\r\n\r\n"
            tlsProxy(connectResponse = challenge, absolute = { _, out -> out.writeStringUtf8(challenge) }) { proxyPort, seen ->
                val credentials = ProxyCredentials("alice", "S3cRtQ")
                testClient(engine = { through(ResolvedProxy.https("proxy.internal", proxyPort, credentials)) }).use { c ->
                    val e = assertFailsWith<ProxyException> { c.get("https://server.test:1/").bodyAsText() }
                    assertEquals(407, e.replyCode)
                    assertFalse(e is ProxyTlsException, "a refusal inside TLS is not a TLS failure")
                    assertEquals(1, seen.heads().size, "CONNECTs sent: ${seen.heads()}")
                    assertEquals(
                        407,
                        assertFailsWith<ProxyException> {
                            c.get("https://server.test:2/") { header(HttpHeaders.ProxyAuthorization, "Basic Ym9iOng=") }.bodyAsText()
                        }.replyCode,
                    )
                    assertEquals(2, seen.heads().size, "CONNECTs sent: ${seen.heads()}")
                    assertEquals(407, c.get("http://server.test:8080/").status.value)
                    assertEquals(3, seen.heads().size, "requests sent: ${seen.heads()}")
                }
            }
        }

    /**
     * A proxy that takes the ClientHello and closes the connection: the request fails at once with [ProxyTlsException],
     * not after the connect timeout and not as an origin failure.
     */
    @Test fun negative_proxyClosingMidHandshakeFails() =
        clientTest {
            val selector = SelectorManager(Dispatchers.IO)
            val listener = bindTcp(selector, "127.0.0.1", 0)
            try {
                coroutineScope {
                    val helloBytes = CompletableDeferred<Int>()
                    val proxy =
                        async {
                            repeat(1) {
                                listener.accept().use { s ->
                                    val input = s.openReadChannel()
                                    val buf = ByteArray(64)
                                    helloBytes.complete(input.readAvailable(buf, 0, buf.size))
                                }
                            }
                        }
                    val proxyPort = (listener.localAddress as InetSocketAddress).port
                    testClient(engine = {
                        through(ResolvedProxy.https("proxy.internal", proxyPort))
                        connectTimeout = 30.seconds
                    }).use { c ->
                        val started =
                            kotlin.time.TimeSource.Monotonic
                                .markNow()
                        val e = assertFailsWith<ProxyTlsException> { c.get("https://server.test:1/").bodyAsText() }
                        assertTrue(started.elapsedNow() < 20.seconds, "failed only after ${started.elapsedNow()}: $e")
                    }
                    assertTrue(helloBytes.await() > 0, "the proxy got no ClientHello")
                    proxy.await()
                }
            } finally {
                listener.close()
                selector.close()
            }
        }

    /**
     * HTTP/3 cannot go through a CONNECT tunnel (QUIC is UDP; CONNECT-UDP, RFC 9298, is not supported): `H3Only` through an
     * `https://` proxy fails without contacting the proxy, and is never sent around it.
     */
    @Test fun negative_h3OnlyThroughAnHttpsProxyFails() =
        clientTest {
            tlsProxy { proxyPort, seen ->
                testClient(Http3DiscoveryMode.H3Only, engine = { through(ResolvedProxy.https("proxy.internal", proxyPort)) }).use { c ->
                    val e = assertFailsWith<UnsupportedOperationException> { c.get("https://server.test:1/").bodyAsText() }
                    assertTrue("proxy" in e.message!!, e.message)
                }
                assertEquals(0, seen.accepted(), "the proxy was contacted")
            }
        }

    /** Through an `https://` proxy no `Alt-Svc` is learned (RFC 7838 section 2.1: the alternative would leave the proxy). */
    @Test fun negative_altSvcIsNotLearnedThroughAnHttpsProxy() =
        clientTest {
            val puts = ArrayList<String>()
            val store =
                object : AltSvcStore by InMemoryAltSvcStore() {
                    override fun put(
                        origin: String,
                        entries: List<AltSvcEntry>,
                    ) {
                        puts += origin
                    }
                }
            origin(altSvc = true) { originPort ->
                tlsProxy(originPort) { proxyPort, _ ->
                    testClient(Http3DiscoveryMode.Auto, engine = {
                        http3 { altSvcStore = store }
                        through(ResolvedProxy.https("proxy.internal", proxyPort))
                    }).use { c ->
                        assertEquals("through|null", c.get("https://server.test:$originPort/").bodyAsText())
                        assertEquals("through|null", c.get("https://server.test:$originPort/").bodyAsText())
                    }
                }
            }
            assertEquals(emptyList(), puts, "Alt-Svc learned through the proxy")
        }

    /** An `https://` proxy and an `http://` one on the same host and port are different routes: never one pooled connection for both. */
    @Test fun negative_httpAndHttpsProxiesAreDifferentRoutes() {
        val credentials = ProxyCredentials("u", "p")
        val tls = ResolvedProxy.https("p.test", 3128, credentials)
        val plain = ResolvedProxy.http("p.test", 3128, credentials)
        assertTrue(tls.routeKey != plain.routeKey, tls.routeKey)
        assertFalse(tls == plain)
        assertTrue(tls.tls)
        assertFalse(plain.tls)
        assertEquals("https://p.test:3128", tls.toString())
        assertEquals("http://p.test:3128", plain.toString())
        assertFalse("p" == tls.routeKey.substringAfterLast(':'), "the password reached the key")
    }

    /**
     * The proxy's default trust is the origin's base trust, without what names the origin: an [TrustConfig.ExpectedName]
     * is the origin's name and a [TrustConfig.Pinned] the origin's keys, so both are taken off (curl's `--pinnedpubkey`
     * does not apply to its proxy either); the CA set, the platform, a custom verifier and TOFU stay.
     */
    @Test fun proxyTrustDropsTheOriginsNameAndPins() {
        val ca = ClientFixtures.trust
        assertEquals(TrustConfig.Platform, proxyTrustOf(TrustConfig.Platform))
        assertTrue(proxyTrustOf(ca) === ca)
        assertTrue(proxyTrustOf(TrustConfig.ExpectedName("server.test", ca)) === ca)
        val pins = setOf(SpkiSha256(ByteArray(32)))
        assertTrue(proxyTrustOf(TrustConfig.Pinned(pins, base = ca)) === ca)
        assertTrue(proxyTrustOf(TrustConfig.Pinned(pins, base = TrustConfig.ExpectedName("server.test", ca))) === ca)
        val config = KuicksilverEngineConfig().apply { trust = TrustConfig.ExpectedName("server.test", ca) }
        val built = config.proxyTlsConfigFor("proxy.internal")
        assertEquals("proxy.internal", built.serverName)
        assertEquals(listOf("http/1.1"), built.alpn)
        assertTrue(built.trust === ca, "${built.trust}")
        assertNull(built.identity, "the origin's client certificate went to the proxy")
    }

    /**
     * TLS in TLS with HTTP/2 to the origin: ALPN `h2` inside the tunnel (the origin's own TLS session), `http/1.1` alone
     * to the proxy; several requests share the one tunnel; `Proxy-Authorization` never reaches the origin's HTTP/2 fields
     * (RFC 9110 section 11.7.2).
     */
    @Test fun negative_originHttp2InsideTheTunnelGetsNoProxyAuthorization() =
        clientTest {
            origin(http2 = true) { originPort ->
                tlsProxy(originPort) { proxyPort, seen ->
                    testClient(engine = { through(ResolvedProxy.https("proxy.internal", proxyPort)) }).use { c ->
                        repeat(3) {
                            // a request's own Proxy-Authorization goes on the CONNECT only, never in the HTTP/2 fields
                            val r = c.get("https://server.test:$originPort/") { header(HttpHeaders.ProxyAuthorization, "Basic Ym9iOng=") }
                            assertEquals(io.ktor.http.HttpProtocolVersion.HTTP_2_0, r.version)
                            assertEquals("through|null", r.bodyAsText(), "the origin got the proxy's credentials over HTTP/2")
                        }
                    }
                    assertEquals(listOf("http/1.1"), seen.hellos().single().alpn)
                    assertEquals(1, seen.heads().size, "one tunnel for the three requests")
                }
            }
        }

    /** A `ws://` WebSocket through an `https://` proxy: a CONNECT inside TLS to the proxy (RFC 6455 section 4.1), then the handshake. */
    @Test fun webSocketGoesThroughTheHttpsProxy() =
        clientTest {
            val (server, port) =
                testServer(plain = true) {
                    install(io.ktor.server.websocket.WebSockets)
                    routing {
                        serverWebSocket("/ws") {
                            outgoing.send(
                                io.ktor.websocket.Frame
                                    .Text("ws through"),
                            )
                        }
                    }
                }
            try {
                tlsProxy(port) { proxyPort, seen ->
                    testClient(
                        engine = { through(ResolvedProxy.https("proxy.internal", proxyPort)) },
                        block = { install(io.ktor.client.plugins.websocket.WebSockets) },
                    ).use { c ->
                        c.webSocket("ws://server.test:$port/ws") {
                            val frame = incoming.receive() as io.ktor.websocket.Frame.Text
                            assertEquals("ws through", frame.readText())
                        }
                    }
                    assertEquals("CONNECT server.test:$port HTTP/1.1", seen.heads().single().first())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A proxy whose ALPN shares nothing with `http/1.1` (it offers `h2` alone) ends the handshake (RFC 7301 section 3.2,
     * no_application_protocol): [ProxyTlsException], nothing sent.
     */
    @Test fun negative_proxyOfferingNoCommonAlpnFails() =
        clientTest {
            tlsProxy(alpn = listOf("h2")) { proxyPort, seen ->
                testClient(engine = { through(ResolvedProxy.https("proxy.internal", proxyPort)) }).use { c ->
                    assertFailsWith<ProxyTlsException> { c.get("https://server.test:1/").bodyAsText() }
                }
                assertEquals(emptyList(), seen.heads())
            }
        }

    /** A proxy that takes no part in ALPN is spoken to in HTTP/1.1 (RFC 7301 section 3.1: without ALPN, the protocol both know). */
    @Test fun proxyWithoutAlpnIsSpokenToInHttp11() =
        clientTest {
            origin { originPort ->
                tlsProxy(originPort, alpn = emptyList()) { proxyPort, _ ->
                    testClient(engine = { through(ResolvedProxy.https("proxy.internal", proxyPort)) }).use { c ->
                        assertEquals("through|null", c.get("https://server.test:$originPort/").bodyAsText())
                    }
                }
            }
        }

    /**
     * A `proxyTls` block that sets `serverName` or `alpn` changes neither: the proxy is still verified as `proxy.internal`
     * (the origin's certificate there fails) and offered `http/1.1` alone.
     */
    @Test fun negative_proxyTlsBlockCannotChangeTheProxysName() =
        clientTest {
            tlsProxy(cert = TestCerts.server, key = TestCerts.serverKey) { proxyPort, _ ->
                testClient(engine = {
                    through(ResolvedProxy.https("proxy.internal", proxyPort))
                    proxyTls = {
                        trust = ClientFixtures.trust
                        serverName = "server.test"
                    }
                }).use { c ->
                    val e = assertFailsWith<ProxyTlsException> { c.get("https://server.test:1/").bodyAsText() }
                    assertIs<VerifyReason.HostnameMismatch>(assertIs<TlsException.Verify>(e.cause).reason)
                }
            }
            origin { originPort ->
                tlsProxy(originPort) { proxyPort, seen ->
                    testClient(engine = {
                        through(ResolvedProxy.https("proxy.internal", proxyPort))
                        proxyTls = {
                            trust = ClientFixtures.trust
                            alpn = listOf("h2")
                        }
                    }).use { c ->
                        assertEquals("through|null", c.get("https://server.test:$originPort/").bodyAsText())
                    }
                    assertEquals(listOf("http/1.1"), seen.hellos().single().alpn)
                    assertEquals("proxy.internal", seen.hellos().single().serverName)
                }
            }
        }

    /**
     * A proxy that accepts TCP and never answers the ClientHello: the request ends at the connect timeout
     * (`ConnectTimeoutException`, the timeout is the subject here), not hanging and not as a proxy TLS failure.
     */
    @Test fun negative_silentProxyHandshakeEndsAtTheConnectTimeout() =
        clientTest {
            val selector = SelectorManager(Dispatchers.IO)
            val listener = bindTcp(selector, "127.0.0.1", 0)
            try {
                coroutineScope {
                    val held = async { listener.accept() } // accepted and never read
                    val proxyPort = (listener.localAddress as InetSocketAddress).port
                    testClient(engine = {
                        through(ResolvedProxy.https("proxy.internal", proxyPort))
                        connectTimeout = 500.milliseconds
                    }).use { c ->
                        assertFailsWith<ConnectTimeoutException> { c.get("https://server.test:1/").bodyAsText() }
                    }
                    held.await().close()
                }
            } finally {
                listener.close()
                selector.close()
            }
        }
}
