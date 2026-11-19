// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.network.sockets.ConnectTimeoutException
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.request.httpMethod
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.UdpProxy
import io.kuicksilver.http3.UdpProxyConfig
import io.kuicksilver.http3.UdpProxyTemplate
import io.kuicksilver.http3.UdpTargetFilter
import io.kuicksilver.ktor.server.KuicksilverTlsConnector
import io.kuicksilver.ktor.server.connectUdp
import io.kuicksilver.ktor.server.peerCertificates
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyReason
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.update
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The TLS of the QUIC connection to a CONNECT-UDP proxy (RFC 9298) is the proxy's, as for the TCP hop to an `https://`
 * proxy (ADR-0023, `proxyTlsConfigFor`): the proxy's name and trust (`proxyTls`, by default the origin's without its
 * `ExpectedName` and pins), no client certificate of the origin's, ALPN `h3`, and session tickets and endpoints of its
 * own. The origin's connection inside the tunnel keeps the origin's configuration: its client certificate and pins.
 * The proxy (`proxy.internal`, its own certificate and key) and the origin (127.0.0.1, the server certificate) both ask
 * for a client certificate (`ClientAuth.Optional`) and record the one they got.
 */
@OptIn(ExperimentalAtomicApi::class)
class ClientConnectUdpProxyTlsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** What the proxy's CONNECT-UDP requests and the origin's requests came with. */
    private class Seen {
        private val lock = Mutex()
        private val proxy = ArrayList<List<Certificate>>()
        private val origin = ArrayList<List<Certificate>>()

        suspend fun proxy(certs: List<Certificate>) = lock.withLock { proxy += certs }

        suspend fun origin(certs: List<Certificate>) = lock.withLock { origin += certs }

        suspend fun atProxy(): List<List<Certificate>> = lock.withLock { proxy.toList() }

        suspend fun atOrigin(): List<List<Certificate>> = lock.withLock { origin.toList() }
    }

    /** Answers 127.0.0.1 for `proxy.internal` only: the origin's name is the proxy's to resolve. */
    private object ProxyName : Dns {
        override suspend fun lookup(host: String): List<IpAddress> =
            if (host == "proxy.internal") listOf(IpAddress.parse("127.0.0.1")) else emptyList()
    }

    private fun clientIdentity() = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())

    private fun loopbackProxy() =
        UdpProxy(
            UdpProxyConfig(
                targetFilter = UdpTargetFilter.addresses("127.0.0.1"),
                refuseOwnAddresses = false,
                packetTooBig = false,
                socketFactory = { DatagramIo.open(InetSocketAddress("127.0.0.1", 0)) },
            ),
        )

    /** Asks for a client certificate, verified under the test CA. */
    private val askForClientCertificate: KuicksilverTlsConnector.Builder.() -> Unit = {
        clientAuth = ClientAuth.Optional
        trust = ClientFixtures.trust
    }

    /**
     * An origin and a CONNECT-UDP proxy in front of [proxy], the proxy with [proxyCert] and [proxyKey] (by default its own,
     * for `proxy.internal`); [block] gets the proxy's and the origin's ports.
     */
    private suspend fun withProxyAndOrigin(
        proxy: UdpProxy,
        seen: Seen,
        proxyCert: ByteArray = TestCerts.proxy,
        proxyKey: ByteArray = TestCerts.proxyKey,
        // QUIC session tickets come with 0-RTT on (QuicServerConfig.earlyData), which excludes client certificates
        proxyIssuesTickets: Boolean = false,
        block: suspend (proxyPort: Int, originPort: Int) -> Unit,
    ) {
        val (origin, originPort) =
            testServer(tls = askForClientCertificate) {
                routing {
                    get("/") {
                        seen.origin(call.request.peerCertificates)
                        call.respondText("origin")
                    }
                }
            }
        val (proxyServer, proxyPort) =
            testServer(configure = {
                connectUdp = true
                quicEarlyData = proxyIssuesTickets
            }, tls = {
                identity = TlsIdentity.fromDer(listOf(proxyCert), proxyKey.copyOf())
                if (!proxyIssuesTickets) askForClientCertificate()
            }) {
                routing {
                    get("/") { call.respondText("proxy as an origin") }
                    route("/") {
                        intercept(ApplicationCallPipeline.Plugins) {
                            if (call.request.httpMethod.value == "CONNECT") seen.proxy(call.request.peerCertificates)
                        }
                        connectUdp(proxy)
                    }
                }
            }
        try {
            block(proxyPort, originPort)
        } finally {
            proxyServer.stop(100, 500)
            origin.stop(100, 500)
        }
    }

    private fun udpProxy(proxyPort: Int) = ConnectUdpProxy(UdpProxyTemplate.wellKnown("proxy.internal:$proxyPort")) { it.port != proxyPort }

    /**
     * The origin's client certificate (`identity`) is never shown to the CONNECT-UDP proxy: it identifies the user to the
     * origin, not to an intermediary (ADR-0023). The origin, inside the tunnel, still gets it.
     */
    @Test fun negative_proxyHopNeverPresentsTheOriginsClientCertificate() =
        h3Test {
            val seen = Seen()
            val proxy = loopbackProxy()
            withProxyAndOrigin(proxy, seen) { proxyPort, originPort ->
                testClient(Http3DiscoveryMode.H3Only, engine = {
                    dns = ProxyName
                    identity = clientIdentity()
                    connectUdpProxy = udpProxy(proxyPort)
                }).use { c ->
                    assertEquals("origin", c.get("https://127.0.0.1:$originPort/").bodyAsText())
                }
                assertEquals(1, proxy.stats.tunnelsOpened)
                assertEquals(listOf(emptyList()), seen.atProxy(), "the origin's client certificate went to the proxy")
                val atOrigin = seen.atOrigin().single()
                assertEquals(listOf("client.test"), atOrigin.firstOrNull()?.dnsNames, "the origin lost its client certificate")
            }
        }

    /** A `proxyTls` block that sets an identity shows that one to the proxy (a proxy that wants a client certificate). */
    @Test fun proxyTlsIdentityIsShownToTheProxy() =
        h3Test {
            val seen = Seen()
            withProxyAndOrigin(loopbackProxy(), seen) { proxyPort, originPort ->
                testClient(Http3DiscoveryMode.H3Only, engine = {
                    dns = ProxyName
                    proxyTls = { identity = clientIdentity() }
                    connectUdpProxy = udpProxy(proxyPort)
                }).use { c ->
                    assertEquals("origin", c.get("https://127.0.0.1:$originPort/").bodyAsText())
                }
                assertEquals(
                    listOf("client.test"),
                    seen
                        .atProxy()
                        .single()
                        .firstOrNull()
                        ?.dnsNames,
                )
                assertEquals(listOf(emptyList()), seen.atOrigin(), "the proxy's client certificate went to the origin")
            }
        }

    /**
     * The origin's pins (`TrustConfig.Pinned`) are not applied to the proxy, which holds another key; inside the tunnel they
     * still apply to the origin: the right pin passes, a wrong one fails the origin's handshake, as the origin's
     * `TlsException` and never a `ProxyException`, after the tunnel to it was opened.
     */
    @Test fun negative_originPinsApplyToTheOriginOnlyNotToTheProxyHop() =
        h3Test {
            val seen = Seen()
            val proxy = loopbackProxy()
            withProxyAndOrigin(proxy, seen) { proxyPort, originPort ->
                val right = TrustConfig.Pinned(setOf(SpkiSha256(TestCerts.serverSpkiSha256)), base = ClientFixtures.trust)
                testClient(Http3DiscoveryMode.H3Only, engine = {
                    trust = right
                    dns = ProxyName
                    connectUdpProxy = udpProxy(proxyPort)
                }).use { c ->
                    assertEquals("origin", c.get("https://127.0.0.1:$originPort/").bodyAsText())
                }
                assertEquals(1, proxy.stats.tunnelsOpened)
                val wrong = TrustConfig.Pinned(setOf(SpkiSha256(ByteArray(32))), base = ClientFixtures.trust)
                testClient(Http3DiscoveryMode.H3Only, engine = {
                    trust = wrong
                    dns = ProxyName
                    connectUdpProxy = udpProxy(proxyPort)
                }).use { c ->
                    val e = assertFailsWith<Throwable> { c.get("https://127.0.0.1:$originPort/").bodyAsText() }
                    val chain = generateSequence(e) { it.cause }.toList()
                    val verify = chain.filterIsInstance<TlsException.Verify>().firstOrNull()
                    assertIs<VerifyReason.PinMismatch>(verify?.reason, "$e")
                    assertFalse(chain.any { it is ProxyException }, "an origin failure reported as the proxy's: $e")
                }
                assertEquals(2, proxy.stats.tunnelsOpened, "the proxy hop was checked against the origin's pins")
                assertEquals(1, seen.atOrigin().size)
            }
        }

    /**
     * `proxyTls` is the proxy hop's trust: a pin there that the proxy's key does not match fails the proxy's handshake
     * with [ProxyTlsException], before any tunnel or request.
     */
    @Test fun negative_proxyTlsTrustAppliesToTheProxyHop() =
        h3Test {
            val seen = Seen()
            val proxy = loopbackProxy()
            withProxyAndOrigin(proxy, seen) { proxyPort, originPort ->
                testClient(Http3DiscoveryMode.H3Only, engine = {
                    dns = ProxyName
                    proxyTls = { trust = TrustConfig.Pinned(setOf(SpkiSha256(ByteArray(32))), base = ClientFixtures.trust) }
                    connectUdpProxy = udpProxy(proxyPort)
                }).use { c ->
                    val e = assertFailsWith<ProxyTlsException> { c.get("https://127.0.0.1:$originPort/").bodyAsText() }
                    assertIs<VerifyReason.PinMismatch>(assertIs<TlsException.Verify>(e.cause, "$e").reason)
                }
                assertEquals(0, proxy.stats.tunnelsOpened)
                assertEquals(emptyList(), seen.atProxy(), "a request reached the proxy")
                assertEquals(emptyList(), seen.atOrigin(), "a request reached the origin")
            }
        }

    /**
     * The origin's `ExpectedName` names the origin: on the proxy hop it would accept the origin's certificate from whoever
     * answers at the proxy's address. The proxy is verified against its own name, so a proxy presenting the origin's
     * certificate (`server.test`) as `proxy.internal` fails with [ProxyTlsException] (host-name mismatch).
     */
    @Test fun negative_originExpectedNameDoesNotCarryToTheProxyHop() =
        h3Test {
            val seen = Seen()
            val proxy = loopbackProxy()
            withProxyAndOrigin(proxy, seen, proxyCert = TestCerts.server, proxyKey = TestCerts.serverKey) { proxyPort, originPort ->
                testClient(Http3DiscoveryMode.H3Only, engine = {
                    trust = TrustConfig.ExpectedName("server.test", ClientFixtures.trust)
                    dns = ProxyName
                    connectUdpProxy = udpProxy(proxyPort)
                }).use { c ->
                    val e = assertFailsWith<ProxyTlsException> { c.get("https://127.0.0.1:$originPort/").bodyAsText() }
                    assertIs<VerifyReason.HostnameMismatch>(assertIs<TlsException.Verify>(e.cause, "$e").reason)
                }
                assertEquals(0, proxy.stats.tunnelsOpened)
                assertEquals(emptyList(), seen.atOrigin())
            }
        }

    /**
     * No session of the proxy hop resumes a connection to an origin, even one to the same host (the proxy reached as an
     * origin): the proxy hop takes and stores no ticket at all (a full handshake each time, `Http3Endpoint.connect`), and
     * leaves from endpoints of its own whose cache is the proxies' (as the TCP hop's `proxySessions`). Here the proxy issues
     * tickets (0-RTT on, so it asks for no client certificate) and the client sends 0-RTT where it can: after a request
     * through the proxy, both caches are empty, the first direct connection to `proxy.internal` attempts no 0-RTT (no
     * ticket of that host), and only the second, with the ticket of the first, does (the control: this setup resumes).
     */
    @Test fun negative_proxyHopKeepsItsOwnEndpointsAndTickets() =
        h3Test {
            val seen = Seen()
            withProxyAndOrigin(loopbackProxy(), seen, proxyIssuesTickets = true) { proxyPort, originPort ->
                testClient(Http3DiscoveryMode.H3Only, engine = {
                    dns = ProxyName
                    connectUdpProxy = udpProxy(proxyPort)
                    http3 { earlyData = true }
                }).use { c ->
                    val h3 = (c.engine as KuicksilverEngine).h3
                    val chosen = AtomicReference(emptyList<Pair<Int, Http3Endpoint>>())
                    h3.endpointChosenForTest = { remote, ep -> chosen.update { it + (remote.port to ep) } }
                    assertEquals("origin", c.get("https://127.0.0.1:$originPort/").bodyAsText()) // through the proxy
                    // the tunnelled connection and with it the connection to the proxy end: a ticket the proxy hop had
                    // received would be stored by now
                    h3.dropConnectionsForTest().forEach { conn ->
                        conn.close()
                        withTimeout(10.seconds) { conn.quic.closed.await() }
                    }
                    assertEquals(0, h3.proxyTicketsForTest.size(), "the proxy hop stored a ticket")
                    assertEquals(0, h3.directTicketsForTest.size(), "a proxy ticket went to the origins' cache")
                    assertEquals("proxy as an origin", c.get("https://proxy.internal:$proxyPort/").bodyAsText()) // direct
                    val first = h3.dropConnectionsForTest().single()
                    assertNull(first.quic.earlyDataAccepted, "the first direct connection resumed a session of the proxy hop")
                    first.close()
                    assertEquals("proxy as an origin", c.get("https://proxy.internal:$proxyPort/").bodyAsText())
                    val second = h3.connectionsForTest().single()
                    assertEquals(true, second.quic.earlyDataAccepted, "the control: the direct connection's own ticket resumes")
                    val toProxy =
                        chosen
                            .load()
                            .filter { it.first == proxyPort }
                            .map { it.second }
                            .distinct()
                    assertEquals(2, toProxy.size, "the proxy hop left from a direct connections' endpoint: $toProxy")
                }
            }
        }

    /** A raw QUIC server for the proxy's port with [tls] (no HTTP/3 behind it); [block] gets its port. */
    private suspend fun withQuicProxy(
        tls: TlsConfig,
        block: suspend (proxyPort: Int) -> Unit,
    ) {
        val ep =
            QuicEndpoint.bind(
                InetSocketAddress("127.0.0.1", 0),
                QuicEndpointConfig.Builder().apply { server = QuicServerConfig.Builder(tls).build() }.build(),
            )
        try {
            block(ep.localAddress.port)
        } finally {
            ep.closeAndJoin()
        }
    }

    private fun proxyServerTls(block: TlsConfig.Builder.() -> Unit = {}) =
        tlsConfig(TlsRole.Server) {
            identity = TlsIdentity.fromDer(listOf(TestCerts.proxy), TestCerts.proxyKey.copyOf())
            alpn = listOf(Http3Endpoint.H3)
            block()
        }

    /**
     * The request through [proxyPort] fails with [ProxyTlsException] from the race to the proxy's single address, not
     * from the 30-second connect timeout (whose path would carry a [ConnectTimeoutException] suppressed in it).
     */
    private suspend fun assertProxyTlsFailure(proxyPort: Int): ProxyTlsException {
        lateinit var e: ProxyTlsException
        testClient(Http3DiscoveryMode.H3Only, engine = {
            dns = ProxyName
            identity = clientIdentity()
            connectUdpProxy = udpProxy(proxyPort)
            connectTimeout = 30.seconds
        }).use { c ->
            e = assertFailsWith<ProxyTlsException> { c.get("https://127.0.0.1:1/").bodyAsText() }
            assertTrue(e.suppressedExceptions.none { it is ConnectTimeoutException }, "failed at the connect timeout: $e")
        }
        return e
    }

    /** Answers ::1 and 127.0.0.1 for `proxy.internal`: ::1 comes first (RFC 6724 precedence), 127.0.0.1 after it failed. */
    private object TwoProxyAddresses : Dns {
        override suspend fun lookup(host: String): List<IpAddress> =
            if (host == "proxy.internal") listOf(IpAddress.parse("::1"), IpAddress.parse("127.0.0.1")) else emptyList()
    }

    /**
     * A QUIC server on `[::1]:`[port] whose ALPN shares nothing with `h3` (its handshakes fail in TLS), counting the
     * ClientHellos in [hellos]; null when that port is taken on ::1 (the caller skips).
     */
    private suspend fun badTlsOnIpv6(
        port: Int,
        hellos: AtomicReference<Int>,
    ): QuicEndpoint? {
        val tls =
            proxyServerTls {
                alpn = listOf("hq-interop")
                sniSelector = {
                    hellos.update { it + 1 }
                    null
                }
            }
        return runCatching {
            QuicEndpoint.bind(
                InetSocketAddress("::1", port),
                QuicEndpointConfig.Builder().apply { server = QuicServerConfig.Builder(tls).build() }.build(),
            )
        }.getOrNull()
    }

    /**
     * The proxy's name has two addresses: ::1 answers and fails TLS, 127.0.0.1 then stays silent (a socket that never
     * answers) or has nothing bound. The request fails with the proxy's [ProxyTlsException], not with the timeout the
     * other address ran into (kept as a suppressed [ConnectTimeoutException] when it came to that) nor a refusal; and no
     * exception is suppressed in itself.
     */
    @Test fun negative_aProxyTlsFailureOnOneAddressIsReportedOverTheOthersTimeout() =
        h3Test {
            for (silent in listOf(true, false)) {
                val hellos = AtomicReference(0)
                val listening = DatagramIo.open(InetSocketAddress("127.0.0.1", 0))
                val port = listening.localAddress.port
                if (!silent) listening.close()
                val bad = badTlsOnIpv6(port, hellos)
                if (bad == null) {
                    listening.close()
                    println("negative_aProxyTlsFailureOnOneAddressIsReportedOverTheOthersTimeout skipped: [::1]:$port taken")
                    return@h3Test
                }
                try {
                    testClient(Http3DiscoveryMode.H3Only, engine = {
                        dns = TwoProxyAddresses
                        connectUdpProxy = udpProxy(port)
                        connectTimeout = 1.seconds
                    }).use { c ->
                        val e = assertFailsWith<ProxyTlsException>("silent = $silent") { c.get("https://127.0.0.1:1/").bodyAsText() }
                        assertIs<TlsException>(e.cause, "$e")
                        val seen = HashSet<Throwable>()

                        fun walk(t: Throwable) {
                            assertTrue(seen.add(t), "an exception suppressed in itself: $t")
                            t.suppressedExceptions.forEach(::walk)
                        }
                        walk(e)
                    }
                    assertTrue(hellos.load() > 0, "the ::1 proxy got no ClientHello (silent = $silent)")
                } finally {
                    bad.closeAndJoin()
                    if (silent) listening.close()
                }
            }
        }

    /**
     * Address ::1 of the proxy fails TLS and 127.0.0.1 wins the race; then the tunnel's CONNECT goes out and the origin's
     * handshake through it (to a target that never answers) runs into the connect timeout. That is a
     * [ConnectTimeoutException], not the losing address's [ProxyTlsException]: the CONNECT and its credentials did go to
     * the proxy, which a `ProxyTlsException` says never happened.
     */
    @Test fun negative_aTimeoutAfterTheProxyAnsweredIsNotTheLosingAddresssTlsFailure() =
        h3Test {
            val proxy = loopbackProxy()
            val silentTarget = DatagramIo.open(InetSocketAddress("127.0.0.1", 0))
            val (proxyServer, proxyPort) =
                testServer(configure = { connectUdp = true }, tls = {
                    identity = TlsIdentity.fromDer(listOf(TestCerts.proxy), TestCerts.proxyKey.copyOf())
                }) { routing { route("/") { connectUdp(proxy) } } }
            val hellos = AtomicReference(0)
            val bad = badTlsOnIpv6(proxyPort, hellos)
            try {
                if (bad == null) {
                    println("negative_aTimeoutAfterTheProxyAnsweredIsNotTheLosingAddresssTlsFailure skipped: [::1]:$proxyPort taken")
                    return@h3Test
                }
                testClient(Http3DiscoveryMode.H3Only, engine = {
                    dns = TwoProxyAddresses
                    connectUdpProxy = udpProxy(proxyPort)
                    connectTimeout = 3.seconds
                }).use { c ->
                    val e = assertFailsWith<Throwable> { c.get("https://127.0.0.1:${silentTarget.localAddress.port}/").bodyAsText() }
                    assertIs<ConnectTimeoutException>(e, "$e")
                }
                assertTrue(hellos.load() > 0, "the ::1 proxy got no ClientHello")
                assertEquals(1, proxy.stats.tunnelsOpened, "the tunnel's CONNECT did not reach the proxy")
            } finally {
                bad?.closeAndJoin()
                proxyServer.stop(100, 500)
                silentTarget.close()
            }
        }

    /**
     * A proxy whose ALPN shares nothing with `h3` ends the handshake (RFC 7301 section 3.2, RFC 9001 section 8.1:
     * no_application_protocol): [ProxyTlsException], as over TCP (`ClientHttpsProxyTest.negative_proxyOfferingNoCommonAlpnFails`).
     */
    @Test fun negative_quicProxyOfferingNoCommonAlpnFails() =
        h3Test {
            withQuicProxy(proxyServerTls { alpn = listOf("hq-interop") }) { proxyPort ->
                val e = assertProxyTlsFailure(proxyPort)
                assertIs<TlsException>(e.cause, "$e")
            }
        }

    /**
     * A proxy that ends the handshake once it has the ClientHello (its certificate choice fails) fails the request at once
     * with [ProxyTlsException], not after the connect timeout and not as an origin failure, as over TCP
     * (`ClientHttpsProxyTest.negative_proxyClosingMidHandshakeFails`).
     */
    @Test fun negative_quicProxyClosingMidHandshakeFails() =
        h3Test {
            val hellos = AtomicReference(0)
            val tls =
                proxyServerTls {
                    sniSelector = {
                        hellos.update { it + 1 }
                        throw IllegalStateException("the proxy gives up")
                    }
                }
            withQuicProxy(tls) { proxyPort ->
                val e = assertProxyTlsFailure(proxyPort)
                assertIs<TlsException>(e.cause, "$e")
            }
            assertTrue(hellos.load() > 0, "the proxy got no ClientHello")
        }

    /**
     * A proxy that requires a client certificate gets none (the origin's `identity` is not the proxy's, and `proxyTls` gives
     * none): it answers with certificate_required (RFC 8446 section 6.2), a [ProxyTlsException] around the
     * [TlsException.AlertReceived].
     */
    @Test fun negative_quicProxyRequiringAClientCertificateGetsNoneOfTheOrigins() =
        h3Test {
            val tls =
                proxyServerTls {
                    clientAuth = ClientAuth.Required
                    trust = ClientFixtures.trust
                }
            withQuicProxy(tls) { proxyPort ->
                val e = assertProxyTlsFailure(proxyPort)
                assertIs<TlsException.AlertReceived>(e.cause, "$e")
            }
        }
}
