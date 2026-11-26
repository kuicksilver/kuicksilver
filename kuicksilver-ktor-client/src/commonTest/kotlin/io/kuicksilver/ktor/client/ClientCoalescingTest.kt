// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    io.kuicksilver.annotations.ExperimentalKuicksilverApi::class,
    io.kuicksilver.annotations.InternalKuicksilverApi::class,
    io.kuicksilver.annotations.DelicateKuicksilverApi::class,
)

package io.kuicksilver.ktor.client

import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.HttpStatusCode
import io.ktor.http.takeFrom
import io.ktor.server.request.host
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.client.h3.Destination
import io.kuicksilver.ktor.server.webTransport
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.ServerTlsOverride
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyResult
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.io.readString
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Connection coalescing (`connectionCoalescing`, ADR-0018; RFC 9113 section 9.1.1, RFC 9114 section 3.3, RFC 9110 sections
 * 4.3.3 and 15.5.20). The test server's certificate names `server.test`, `*.wild.test`, 127.0.0.1 and ::1; the resolver maps
 * the names to 127.0.0.1 unless a test says otherwise. Over HTTP/2 the server answers with the client's TCP port, which
 * tells connections apart; over HTTP/3 the engine's pool says how many connections there are.
 */
@OptIn(ExperimentalAtomicApi::class)
class ClientCoalescingTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A resolver over [map] that the test may change between calls; names it does not hold resolve to 127.0.0.1. */
    private class MapDns(
        var map: Map<String, List<IpAddress>> = emptyMap(),
    ) : Dns {
        override suspend fun lookup(host: String): List<IpAddress> = map[host] ?: listOf(IpAddress.parse("127.0.0.1"))
    }

    private fun client(
        coalescing: Boolean = true,
        dns: Dns = MapDns(),
        discovery: Http3DiscoveryMode = Http3DiscoveryMode.H1Only,
        engine: KuicksilverEngineConfig.() -> Unit = {},
    ) = testClient(discovery, engine = {
        connectionCoalescing = coalescing
        this.dns = dns
        proxyResolver = ProxyResolvers.None
        engine()
    })

    private fun engine(c: io.ktor.client.HttpClient) = c.engine as KuicksilverEngine

    /** The engine's Warn lines and above. */
    private class RecordingLogger : io.kuicksilver.quic.KuicksilverLogger {
        private val all = kotlin.concurrent.atomics.AtomicReference(emptyList<String>())
        val lines: List<String> get() = all.load()

        override fun isEnabled(level: io.kuicksilver.quic.LogLevel): Boolean = level >= io.kuicksilver.quic.LogLevel.Warn

        override fun log(
            level: io.kuicksilver.quic.LogLevel,
            message: String,
            cause: Throwable?,
        ) {
            while (true) {
                val l = all.load()
                if (all.compareAndSet(l, l + message)) break
            }
        }
    }

    /** A TLS server with HTTP/2 (no HTTP/3) answering `<host>|<client port>`; [sni] gives it an `sniSelector` (every name). */
    private suspend fun h2Server(
        sni: Boolean = false,
        extra: io.ktor.server.routing.Routing.() -> Unit = {},
    ) = testServer(configure = {
        http2 = true
        http3 = false
    }, tls = {
        if (sni) sniSelector = { ServerTlsOverride(ClientFixtures.identity()) }
    }) {
        routing {
            get("/") { call.respondText("${call.request.host()}|${call.request.local.remotePort}") }
            post("/") { call.respondText("${call.request.host()}|${call.request.local.remotePort}|${call.receiveText()}") }
            extra()
        }
    }

    private suspend fun io.ktor.client.HttpClient.text(url: String): Pair<String, String> {
        val r = get(url)
        assertEquals(HttpProtocolVersion.HTTP_2_0, r.version, url)
        val (host, port) = r.bodyAsText().split('|')
        return host to port
    }

    // ---- HTTP/2 ----

    /** Two origins under one wildcard certificate at one address: the second origin's request goes on the first's connection. */
    @Test fun h2CoalescesAnOriginTheCertificateCovers() =
        clientTest {
            val (server, port) = h2Server()
            try {
                client().use { c ->
                    val a = c.text("https://a.wild.test:$port/")
                    val b = c.text("https://b.wild.test:$port/")
                    assertEquals("a.wild.test", a.first)
                    assertEquals("b.wild.test", b.first, "the request names its own origin")
                    assertEquals(a.second, b.second, "one TCP connection")
                    assertEquals(1, engine(c).h1.h2.connectionCount)
                    // and back: the first origin's route still finds its own connection
                    assertEquals(a.second, c.text("https://a.wild.test:$port/").second)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** The address literal 127.0.0.1 is an origin too (RFC 9110 section 4.3.5): the certificate's iPAddress entry covers it. */
    @Test fun h2CoalescesAnIpLiteralTheCertificateNames() =
        clientTest {
            val (server, port) = h2Server()
            try {
                client().use { c ->
                    val a = c.text("https://a.wild.test:$port/")
                    val ip = c.text("https://127.0.0.1:$port/")
                    assertEquals(a.second, ip.second)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** ADR-0018, off by default: without the setting every origin gets connections of its own, as before. */
    @Test fun negative_h2OffByDefaultNeverCoalesces() =
        clientTest {
            assertFalse(KuicksilverEngineConfig().connectionCoalescing)
            val (server, port) = h2Server()
            try {
                client(coalescing = false).use { c ->
                    val a = c.text("https://a.wild.test:$port/")
                    val b = c.text("https://b.wild.test:$port/")
                    assertNotEquals(a.second, b.second)
                    assertEquals(2, engine(c).h1.h2.connectionCount)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 9113 section 9.1.1: "connection reuse additionally depends on having a certificate that is valid for the host in
     * the URI". `other.test`, `wild.test` and `x.b.wild.test` resolve to the connection's address, but the certificate names
     * none of them: each request takes a connection of its own, whose handshake then fails the name check. The server here
     * answers any authority (no 421 of its own), so a request that had gone on the open connection would have succeeded.
     */
    @Test fun negative_h2ACertificateThatDoesNotCoverTheHostIsNotReused() =
        clientTest {
            tlsH2WithSilentUdp(onRequest = { _, r ->
                r.respond(200, listOf("content-type" to "text/plain"))
                r.sendBody(ByteReadChannel("ok".encodeToByteArray()))
            }) { port, log ->
                client().use { c ->
                    assertEquals("ok", c.get("https://a.wild.test:$port/").bodyAsText())
                    for (host in listOf("other.test", "wild.test", "x.b.wild.test")) {
                        val e = assertFailsWith<Throwable>(host) { c.get("https://$host:$port/") }
                        assertTrue(generateSequence(e) { it.cause }.any { it is TlsException }, "$host: $e")
                    }
                    assertEquals(1, engine(c).h1.h2.connectionCount)
                    assertEquals(1, log.acceptCount, "only the first handshake completed")
                }
            }
        }

    /**
     * RFC 9110 section 4.3.3: the client must believe "that it could open a connection to that host for that URI", in practice
     * "a DNS query to check that the origin's host contains the same server IP address as the established connection".
     * `b.wild.test` resolves to ::1 only, where nothing listens: it is not sent on the connection to 127.0.0.1, whose
     * certificate covers it, and fails on its own connection.
     */
    @Test fun negative_h2AnotherAddressIsNotReused() =
        clientTest {
            val (server, port) = h2Server()
            try {
                val dns = MapDns(mapOf("b.wild.test" to listOf(IpAddress.parse("::1"))))
                client(dns = dns).use { c ->
                    c.text("https://a.wild.test:$port/")
                    assertFailsWith<Throwable> { c.get("https://b.wild.test:$port/") }
                    assertEquals(1, engine(c).h1.h2.connectionCount)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** The address is checked for every request: once `b.wild.test` resolves elsewhere, its requests leave the connection. */
    @Test fun negative_h2AnAddressThatChangedEndsTheReuse() =
        clientTest {
            val (server, port) = h2Server()
            try {
                val dns = MapDns()
                client(dns = dns).use { c ->
                    val a = c.text("https://a.wild.test:$port/")
                    assertEquals(a.second, c.text("https://b.wild.test:$port/").second)
                    dns.map = mapOf("b.wild.test" to listOf(IpAddress.parse("::1")))
                    assertFailsWith<Throwable> { c.get("https://b.wild.test:$port/") }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Another port is another origin and another destination: a second server on it serves it, not the first's connection. */
    @Test fun negative_h2AnotherPortIsNotReused() =
        clientTest {
            val (one, port1) = h2Server()
            val (two, port2) = h2Server()
            try {
                client().use { c ->
                    val a = c.text("https://a.wild.test:$port1/")
                    val b = c.text("https://b.wild.test:$port2/")
                    assertNotEquals(a.second, b.second)
                    assertEquals(2, engine(c).h1.h2.connectionCount)
                }
            } finally {
                one.stop(100, 500)
                two.stop(100, 500)
            }
        }

    /**
     * RFC 9113 section 9.1.1: "TLS termination might be performed by a middlebox that uses the TLS Server Name Indication
     * ... to select an origin server", and such a server answers 421 to a request for another name (our server does, with an
     * `sniSelector`). RFC 9110 section 15.5.20: the client "MAY retry the request, whether or not the request method is
     * idempotent, over a different connection, such as a fresh connection specific to the target resource's origin". The
     * coalesced request goes once more on a connection of its own; later requests of that origin stay there, and the first
     * origin keeps its connection.
     */
    @Test fun h2MisdirectedIsSentOnceMoreOnAConnectionOfItsOwn() =
        clientTest {
            val (server, port) = h2Server(sni = true)
            try {
                client().use { c ->
                    val a = c.text("https://a.wild.test:$port/")
                    val r = c.get("https://b.wild.test:$port/")
                    assertEquals(HttpStatusCode.OK, r.status)
                    assertEquals(2, r.kuicksilverDiagnostics!!.attempts, "the 421 and the repeat")
                    val b = r.bodyAsText().split('|')
                    assertNotEquals(a.second, b[1])
                    // a POST is repeated too (section 15.5.20: "whether or not the request method is idempotent")
                    val p = c.post("https://c.wild.test:$port/") { setBody("payload") }
                    assertEquals(HttpStatusCode.OK, p.status)
                    assertTrue(p.bodyAsText().endsWith("|payload"))
                    assertEquals(b[1], c.text("https://b.wild.test:$port/").second, "b.wild.test now has its own connection")
                    assertEquals(a.second, c.text("https://a.wild.test:$port/").second)
                    assertEquals(3, engine(c).h1.h2.connectionCount)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Exactly once: a 421 on the origin's own connection is the call's answer, not another repeat. */
    @Test fun negative_h2MisdirectedIsRepeatedOnlyOnce() =
        clientTest {
            val asked = AtomicInt(0)
            val (server, port) =
                h2Server(extra = {
                    get("/always") {
                        asked.addAndFetch(1)
                        call.respondText("no", status = HttpStatusCode(421, "Misdirected Request"))
                    }
                })
            try {
                client().use { c ->
                    c.text("https://a.wild.test:$port/")
                    val r = c.get("https://b.wild.test:$port/always")
                    assertEquals(421, r.status.value)
                    assertEquals(2, asked.load())
                    assertEquals(2, engine(c).h1.h2.connectionCount)
                    // a 421 to a request on its own connection repeats nothing
                    assertEquals(421, c.get("https://a.wild.test:$port/always").status.value)
                    assertEquals(3, asked.load())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** A streamed body the 421'd attempt consumed cannot go again: the call fails with H3BodyConsumed, as after other 421s. */
    @Test fun negative_h2MisdirectedStreamedBodyIsNotReplayed() =
        clientTest {
            val (server, port) = h2Server(sni = true)
            try {
                client().use { c ->
                    c.text("https://a.wild.test:$port/")
                    assertFailsWith<H3BodyConsumed> {
                        c.post("https://b.wild.test:$port/") { setBody(ByteReadChannel("streamed".encodeToByteArray())) }
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * ADR-0018: "Connections through a proxy ... are never shared". `b.wild.test` goes through a CONNECT proxy, `a.wild.test`
     * directly: b's request takes the tunnel, never a's direct connection (another route, the application's privacy choice).
     */
    @Test fun negative_h2ARequestThroughAProxyNeverTakesADirectConnection() =
        clientTest {
            val (server, port) = h2Server()
            try {
                ClientProxyTest().tunnelProxy(port) { proxyPort, head ->
                    client(engine = {
                        proxyResolver =
                            ProxyResolver { u -> if (u.host == "b.wild.test") ResolvedProxy.http("127.0.0.1", proxyPort) else null }
                    }).use { c ->
                        val a = c.text("https://a.wild.test:$port/")
                        val b = c.text("https://b.wild.test:$port/")
                        assertNotEquals(a.second, b.second)
                    }
                    assertTrue(head().first().startsWith("CONNECT b.wild.test:$port "), "${head()}")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** And the other way: a connection through a proxy carries no other origin, whatever its certificate covers. */
    @Test fun negative_h2AConnectionThroughAProxyCarriesNoOtherOrigin() =
        clientTest {
            val (server, port) = h2Server()
            try {
                ClientProxyTest().tunnelProxy(port) { proxyPort, head ->
                    client(engine = {
                        proxyResolver =
                            ProxyResolver { u -> if (u.host == "a.wild.test") ResolvedProxy.http("127.0.0.1", proxyPort) else null }
                    }).use { c ->
                        val a = c.text("https://a.wild.test:$port/")
                        val b = c.text("https://b.wild.test:$port/")
                        assertNotEquals(a.second, b.second)
                        assertEquals(2, engine(c).h1.h2.connectionCount)
                    }
                    assertTrue(head().first().startsWith("CONNECT a.wild.test:$port "), "${head()}")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** TOFU keeps a key per name from a handshake with that name: no request of another name goes on the connection. */
    @Test fun negative_h2TofuNeverCoalesces() =
        clientTest {
            val (server, port) = h2Server()
            try {
                val store =
                    object : io.kuicksilver.tls.TofuStore {
                        val pins = HashMap<String, io.kuicksilver.tls.SpkiSha256>()

                        override suspend fun get(name: String) = pins[name]

                        override suspend fun put(
                            name: String,
                            pin: io.kuicksilver.tls.SpkiSha256,
                        ) {
                            pins[name] = pin
                        }
                    }
                client(engine = { trust = TrustConfig.Tofu(store) }).use { c ->
                    val a = c.text("https://a.wild.test:$port/")
                    val b = c.text("https://b.wild.test:$port/")
                    assertNotEquals(a.second, b.second)
                    // and a's own connection is left alone: Tofu's refusal is no reason to retire it
                    assertEquals(a.second, c.text("https://a.wild.test:$port/").second)
                    assertEquals(2, engine(c).h1.h2.connectionCount)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    private fun tofuStore() =
        object : io.kuicksilver.tls.TofuStore {
            private val pins = HashMap<String, io.kuicksilver.tls.SpkiSha256>()
            private val lock = kotlinx.coroutines.sync.Mutex()

            override suspend fun get(name: String) = lock.withLock { pins[name] }

            override suspend fun put(
                name: String,
                pin: io.kuicksilver.tls.SpkiSha256,
            ) {
                lock.withLock { pins[name] = pin }
            }
        }

    /**
     * RFC 9110 section 4.3.3 attributes authority over another origin's connection only "if the URI origin's host matches
     * any of the hosts present in the server's certificate": under an ExpectedName the certificate is checked against a
     * configured name instead, so nothing is coalesced (plain and pinned).
     */
    @Test fun negative_h2ExpectedNameNeverCoalesces() =
        clientTest {
            val (server, port) = h2Server()
            try {
                val named = TrustConfig.ExpectedName("server.test", ClientFixtures.trust)
                val pinned = TrustConfig.Pinned(setOf(Certificate(TestCerts.server).spkiSha256), base = named)
                for (trust in listOf(named, pinned)) {
                    client(engine = { this.trust = trust }).use { c ->
                        val a = c.text("https://a.wild.test:$port/")
                        val b = c.text("https://b.wild.test:$port/")
                        assertNotEquals(a.second, b.second, "$trust")
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** A trust that the verifier of each check decides: [revoked] refuses every chain, [refusedHosts] only those names. */
    private class Switchable {
        @kotlin.concurrent.Volatile var revoked = false

        @kotlin.concurrent.Volatile var refusedHosts: Set<String> = emptySet()

        @kotlin.concurrent.Volatile var ownReason: io.kuicksilver.tls.VerifyReason = io.kuicksilver.tls.VerifyReason.Revoked

        val trust =
            TrustConfig.Custom { chain, name, _ ->
                if (revoked || name in refusedHosts) {
                    VerifyResult.Rejected(io.kuicksilver.tls.VerifyReason.Revoked)
                } else {
                    VerifyResult.Accepted(chain)
                }
            }
    }

    /**
     * RFC 9114 section 3.3: "If the reason the certificate cannot be verified might apply to other origins already
     * associated with the connection, the client SHOULD revalidate the server certificate for those origins". The
     * certificate is revoked after a's handshake: b's check fails, a's own check fails too, so a's connection is retired
     * (GOAWAY) and the retirement is logged; b's own handshake is refused as it should be, and a's next request (the
     * certificate fine again) opens a new connection, whose handshake verified it.
     */
    @Test fun negative_h2ARevokedCertificateRetiresTheConnection() =
        clientTest {
            val (server, port) = h2Server()
            try {
                val sw = Switchable()
                val log = RecordingLogger()
                client(engine = {
                    trust = sw.trust
                    logger = log
                }).use { c ->
                    val a = c.text("https://a.wild.test:$port/")
                    sw.revoked = true
                    val e = assertFailsWith<Throwable> { c.get("https://b.wild.test:$port/") }
                    assertTrue(generateSequence(e) { it.cause }.any { it is TlsException }, "$e")
                    assertTrue(log.lines.any { "no longer passes" in it && "Revoked" in it }, "${log.lines}")
                    sw.revoked = false
                    assertNotEquals(a.second, c.text("https://a.wild.test:$port/").second, "a new connection for a")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * Retirement only for a reason that holds for the connection's own origin: a verifier that refuses b alone (its own
     * policy, its pins) refuses b and leaves a's connection as it is.
     */
    @Test fun negative_h2ARefusalOfTheNewHostAloneKeepsTheConnection() =
        clientTest {
            val (server, port) = h2Server()
            try {
                val sw = Switchable()
                client(engine = { trust = sw.trust }).use { c ->
                    val a = c.text("https://a.wild.test:$port/")
                    sw.refusedHosts = setOf("b.wild.test")
                    assertFailsWith<Throwable> { c.get("https://b.wild.test:$port/") }
                    assertEquals(a.second, c.text("https://a.wild.test:$port/").second, "a keeps its connection")
                    assertEquals(1, engine(c).h1.h2.connectionCount)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A 421 refuses the host on that connection for good: once b's own connection is gone, b opens another rather than
     * going back to a's connection (and getting the 421 again).
     */
    @Test fun negative_h2AfterA421TheHostNeverReturnsToTheConnection() =
        clientTest {
            val (server, port) = h2Server(sni = true)
            try {
                client().use { c ->
                    val a = c.text("https://a.wild.test:$port/")
                    assertEquals(2, c.get("https://b.wild.test:$port/").kuicksilverDiagnostics!!.attempts)
                    val own =
                        engine(c)
                            .h1.h2
                            .connectionsForTest()
                            .single { it.ownHost == "b.wild.test" }
                    own.client.shutdown()
                    withTimeout(10.seconds) { own.client.awaitClosed() }
                    val r = c.get("https://b.wild.test:$port/")
                    assertEquals(HttpStatusCode.OK, r.status)
                    assertEquals(1, r.kuicksilverDiagnostics!!.attempts, "no second 421")
                    assertNotEquals(a.second, r.bodyAsText().split('|')[1])
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 7541 section 7.1: a shared compression context lets one origin's requests probe another's field values. On a
     * connection other origins may share, `cookie` goes as a literal never indexed whatever its length; on one that never
     * carries another origin (coalescing off) a cookie of 20 bytes or more is indexed as before (shorter ones never are,
     * section 7.1.3).
     */
    @Test fun negative_cookiesAreNeverIndexedOnAConnectionOthersMayShare() =
        clientTest {
            val seen = kotlin.concurrent.atomics.AtomicReference(emptyList<Pair<String?, List<String>>>())
            tlsH2WithSilentUdp(onRequest = { _, r ->
                val e = r.authority to r.neverIndexed.map { it.first.lowercase() }
                while (true) {
                    val l = seen.load()
                    if (seen.compareAndSet(l, l + e)) break
                }
                r.respond(200, listOf("content-type" to "text/plain"))
                r.sendBody(ByteReadChannel("ok".encodeToByteArray()))
            }) { port, _ ->
                for (coalescing in listOf(true, false)) {
                    seen.store(emptyList())
                    client(coalescing = coalescing).use { c ->
                        c.get("https://a.wild.test:$port/") { header("Cookie", "session=0123456789abcdefghij") }.bodyAsText()
                        c.get("https://b.wild.test:$port/") { header("Cookie", "tracker=0123456789abcdefghij") }.bodyAsText()
                    }
                    val all = seen.load()
                    assertEquals(2, all.size)
                    assertTrue(all.all { ("cookie" in it.second) == coalescing }, "coalescing=$coalescing: $all")
                }
            }
        }

    /**
     * A resumed connection keeps the chain of its full handshake (the ticket's), intermediates included: it is checked for
     * another origin as a fresh one is, not taken for a leaf without its issuer.
     */
    @Test fun aResumedConnectionKeepsItsWholeChain() =
        clientTest {
            val identity =
                io.kuicksilver.tls.TlsIdentity.fromDer(
                    listOf(TestCerts.serverViaIntermediate, TestCerts.intermediate),
                    TestCerts.serverViaIntermediateKey.copyOf(),
                )
            val (server, port) =
                testServer(configure = {
                    http2 = true
                    http3 = false
                }, tls = { sniSelector = { ServerTlsOverride(identity) } }) {
                    routing { get("/") { call.respondText("ok") } }
                }
            try {
                client().use { c ->
                    assertEquals("ok", c.get("https://server.test:$port/").bodyAsText())
                    val first =
                        engine(c)
                            .h1.h2
                            .connectionsForTest()
                            .single()
                    first.client.shutdown()
                    withTimeout(10.seconds) { first.client.awaitClosed() }
                    assertEquals("ok", c.get("https://server.test:$port/").bodyAsText())
                    val again =
                        engine(c)
                            .h1.h2
                            .connectionsForTest()
                            .single()
                    assertTrue(again.resumed, "the second connection resumed")
                    assertEquals(2, again.peerChain.size, "leaf and intermediate")
                    val config = (c.engine.config as KuicksilverEngineConfig)
                    assertEquals(
                        Coalesce.Yes,
                        config.checkCoalescing(again.peer!!, "server.test", port, config.newRequestDns(), listOf("h2", "http/1.1")),
                    )
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 7838 section 4: an ALTSVC frame on a request stream is for that stream's origin, which the frame does not name. On
     * a connection that carries other origins too it would be taken for the connection's own: such frames are ignored
     * there (the `Alt-Svc` field of the response is the response's origin's, as always). On the origin's own connection
     * the same frame is heard.
     */
    @Test fun negative_anAltSvcFrameOnACoalescedStreamIsNotTakenForTheConnectionsOrigin() =
        clientTest {
            tlsH2WithSilentUdp(onRequest = { _, r ->
                if (r.authority?.startsWith("b.wild.test") == true) r.altSvc("h3=\":1\"; ma=60")
                r.respond(200, listOf("content-type" to "text/plain"))
                r.sendBody(ByteReadChannel("ok".encodeToByteArray()))
            }) { port, _ ->
                for (coalescing in listOf(true, false)) {
                    client(coalescing = coalescing, discovery = Http3DiscoveryMode.Auto).use { c ->
                        assertEquals("ok", c.get("https://a.wild.test:$port/").bodyAsText())
                        assertEquals("ok", c.get("https://b.wild.test:$port/").bodyAsText())
                        assertEquals(if (coalescing) 1 else 2, engine(c).h1.h2.connectionCount)
                        assertEquals(if (coalescing) 0L else 1L, engine(c).altSvcFramesReceived, "coalescing=$coalescing")
                    }
                }
            }
        }

    // ---- HTTP/3 ----

    private suspend fun h3Server(sni: Boolean = false) =
        testServer(tls = { if (sni) sniSelector = { ServerTlsOverride(ClientFixtures.identity()) } }) {
            routing { get("/") { call.respondText("${call.request.host()}|${call.request.local.version}") } }
        }

    private suspend fun io.ktor.client.HttpClient.h3(url: String): String {
        val r = get(url)
        assertEquals(HttpProtocolVersion.HTTP_3_0, r.version, url)
        return r.bodyAsText()
    }

    /** RFC 9114 section 3.3: "this connection MAY be reused for requests with multiple different URI authority components". */
    @Test fun h3CoalescesAnOriginTheCertificateCovers() =
        h3Test {
            val (server, port) = h3Server()
            try {
                client(discovery = Http3DiscoveryMode.H3Only).use { c ->
                    assertEquals("a.wild.test|HTTP/3", c.h3("https://a.wild.test:$port/"))
                    assertEquals("b.wild.test|HTTP/3", c.h3("https://b.wild.test:$port/"))
                    assertEquals("b.wild.test|HTTP/3", c.h3("https://b.wild.test:$port/"))
                    assertEquals(1, engine(c).h3.connectionsForTest().size)
                    assertEquals(1, engine(c).h3.sharedForTest.load())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun negative_h3OffByDefaultNeverCoalesces() =
        h3Test {
            val (server, port) = h3Server()
            try {
                client(coalescing = false, discovery = Http3DiscoveryMode.H3Only).use { c ->
                    c.h3("https://a.wild.test:$port/")
                    c.h3("https://b.wild.test:$port/")
                    assertEquals(2, engine(c).h3.connectionsForTest().size)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 9114 section 3.3: "If the certificate is not acceptable with regard to the new origin for any reason, the
     * connection MUST NOT be reused and a new connection SHOULD be established for the new origin": `other.test`'s own
     * handshake then fails its name check.
     */
    @Test fun negative_h3ACertificateThatDoesNotCoverTheHostIsNotReused() =
        h3Test {
            val (server, port) = h3Server()
            try {
                client(discovery = Http3DiscoveryMode.H3Only).use { c ->
                    c.h3("https://a.wild.test:$port/")
                    val e = assertFailsWith<Throwable> { c.get("https://other.test:$port/") }
                    assertTrue(generateSequence(e) { it.cause }.any { it is TlsException }, "$e")
                    assertEquals(0, engine(c).h3.sharedForTest.load())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** RFC 9114 section 3.3 with RFC 9110 section 15.5.20: the coalesced request's 421 sends it once more on its own connection. */
    @Test fun h3MisdirectedIsSentOnceMoreOnAConnectionOfItsOwn() =
        h3Test {
            val (server, port) = h3Server(sni = true)
            try {
                client(discovery = Http3DiscoveryMode.H3Only).use { c ->
                    c.h3("https://a.wild.test:$port/")
                    val r = c.get("https://b.wild.test:$port/")
                    assertEquals(HttpStatusCode.OK, r.status)
                    assertEquals("b.wild.test|HTTP/3", r.bodyAsText())
                    assertEquals(2, r.kuicksilverDiagnostics!!.attempts)
                    assertEquals(2, engine(c).h3.connectionsForTest().size)
                    // b.wild.test's own connection from now on
                    assertEquals("b.wild.test|HTTP/3", c.h3("https://b.wild.test:$port/"))
                    assertEquals(2, engine(c).h3.connectionsForTest().size)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Tofu never coalesces over HTTP/3 either, and a's connection stays a's. */
    @Test fun negative_h3TofuNeverCoalesces() =
        h3Test {
            val (server, port) = h3Server()
            try {
                client(discovery = Http3DiscoveryMode.H3Only, engine = { trust = TrustConfig.Tofu(tofuStore()) }).use { c ->
                    c.h3("https://a.wild.test:$port/")
                    val a = engine(c).h3.connectionsForTest().single()
                    c.h3("https://b.wild.test:$port/")
                    c.h3("https://a.wild.test:$port/")
                    assertEquals(0, engine(c).h3.sharedForTest.load())
                    assertTrue(a in engine(c).h3.connectionsForTest(), "a keeps its connection")
                    assertEquals(2, engine(c).h3.connectionsForTest().size)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** RFC 9110 section 4.3.3 over HTTP/3: an alternative name resolving elsewhere is not sent on a's connection. */
    @Test fun negative_h3AnotherAddressIsNotReused() =
        h3Test {
            val (server, port) = h3Server()
            try {
                val dns = MapDns(mapOf("b.wild.test" to listOf(IpAddress.parse("::1"))))
                client(dns = dns, discovery = Http3DiscoveryMode.H3Only, engine = { connectTimeout = 3.seconds }).use { c ->
                    c.h3("https://a.wild.test:$port/")
                    assertFailsWith<Throwable> { c.get("https://b.wild.test:$port/") }
                    assertEquals(0, engine(c).h3.sharedForTest.load())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** The address is checked for every request over HTTP/3 too: a filing under a's connection is left once b moves. */
    @Test fun negative_h3AnAddressThatChangedEndsTheReuse() =
        h3Test {
            val (server, port) = h3Server()
            try {
                val dns = MapDns()
                client(dns = dns, discovery = Http3DiscoveryMode.H3Only, engine = { connectTimeout = 3.seconds }).use { c ->
                    c.h3("https://a.wild.test:$port/")
                    c.h3("https://b.wild.test:$port/")
                    assertEquals(1, engine(c).h3.sharedForTest.load())
                    dns.map = mapOf("b.wild.test" to listOf(IpAddress.parse("::1")))
                    assertFailsWith<Throwable> { c.get("https://b.wild.test:$port/") }
                    assertEquals("a.wild.test|HTTP/3", c.h3("https://a.wild.test:$port/"), "a's connection is a's still")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** A 421 over HTTP/3 refuses the host on that connection for good, as over HTTP/2. */
    @Test fun negative_h3AfterA421TheHostNeverReturnsToTheConnection() =
        h3Test {
            val (server, port) = h3Server(sni = true)
            try {
                client(discovery = Http3DiscoveryMode.H3Only).use { c ->
                    c.h3("https://a.wild.test:$port/")
                    val a = engine(c).h3.connectionsForTest().single()
                    assertEquals(2, c.get("https://b.wild.test:$port/").kuicksilverDiagnostics!!.attempts)
                    val own = engine(c).h3.connectionsForTest().single { it !== a }
                    own.close()
                    withTimeout(10.seconds) { own.closed.join() }
                    val r = c.get("https://b.wild.test:$port/")
                    assertEquals(HttpStatusCode.OK, r.status)
                    assertEquals(1, r.kuicksilverDiagnostics!!.attempts, "no second 421")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    private suspend fun h3StrictServer(asked: AtomicInt) =
        testServer {
            routing {
                get("/") { call.respondText("${call.request.host()}|${call.request.local.version}") }
                get("/always") {
                    asked.addAndFetch(1)
                    call.respondText("no", status = HttpStatusCode(421, "Misdirected Request"))
                }
                post("/always") {
                    // the body is read first: the 421 comes after the client sent it all
                    call.receiveText()
                    asked.addAndFetch(1)
                    call.respondText("no", status = HttpStatusCode(421, "Misdirected Request"))
                }
            }
        }

    /** Exactly once over HTTP/3: a 421 on the origin's own connection is the call's answer. */
    @Test fun negative_h3MisdirectedIsRepeatedOnlyOnce() =
        h3Test {
            val asked = AtomicInt(0)
            val (server, port) = h3StrictServer(asked)
            try {
                client(discovery = Http3DiscoveryMode.H3Only).use { c ->
                    c.h3("https://a.wild.test:$port/")
                    val r = c.get("https://b.wild.test:$port/always")
                    assertEquals(421, r.status.value)
                    assertEquals(2, asked.load())
                    assertEquals(421, c.get("https://a.wild.test:$port/always").status.value)
                    assertEquals(3, asked.load())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** A streamed body the coalesced attempt sent cannot go again over HTTP/3 either: H3BodyConsumed, no repeat. */
    @Test fun negative_h3MisdirectedStreamedBodyIsNotReplayed() =
        h3Test {
            val asked = AtomicInt(0)
            val (server, port) = h3StrictServer(asked)
            try {
                client(discovery = Http3DiscoveryMode.H3Only).use { c ->
                    c.h3("https://a.wild.test:$port/")
                    assertFailsWith<H3BodyConsumed> {
                        c.post("https://b.wild.test:$port/always") { setBody(ByteReadChannel("streamed".encodeToByteArray())) }
                    }
                    assertEquals(1, asked.load())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 9110 section 15.5.20 over HTTP/3 with a streamed body: the server answers 421 before the body has a byte (the
     * application writes it only once the request reached a handler), so nothing of it was taken and the same channel goes
     * again, on b's own connection, and gets its 200.
     */
    @Test fun h3MisdirectedStreamedBodyNotYetSentIsSentAgain() =
        h3Test {
            val arrived = kotlinx.coroutines.CompletableDeferred<Unit>()
            val (server, port) =
                testServer(tls = { sniSelector = { ServerTlsOverride(ClientFixtures.identity()) } }) {
                    routing {
                        get("/") { call.respondText("${call.request.host()}|${call.request.local.version}") }
                        post("/echo") {
                            arrived.complete(Unit)
                            call.respondText("${call.request.host()}|${call.receiveText()}")
                        }
                    }
                }
            try {
                client(discovery = Http3DiscoveryMode.H3Only).use { c ->
                    c.h3("https://a.wild.test:$port/")
                    val body =
                        io.ktor.utils.io
                            .ByteChannel()
                    // the first attempt's sender waits in the empty channel: it is stopped and waited for before the repeat
                    // reads, never two readers at once
                    val left = kotlin.concurrent.atomics.AtomicInt(-1)
                    engine(c).h3.misdirectedSettledForTest = { left.store(it) }
                    kotlinx.coroutines.coroutineScope {
                        val writer =
                            launch {
                                arrived.await()
                                body.writeStringUtf8("streamed")
                                body.flushAndClose()
                            }
                        val r = c.post("https://b.wild.test:$port/echo") { setBody(body) }
                        assertEquals(HttpStatusCode.OK, r.status)
                        assertEquals("b.wild.test|streamed", r.bodyAsText())
                        assertEquals(2, r.kuicksilverDiagnostics!!.attempts, "the 421 and the repeat")
                        writer.join()
                    }
                    assertEquals(0, left.load(), "no reader of the first attempt was left")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * Another origin's connection filed under b by a concurrent request between b's own check and its look for candidates is
     * not taken unchecked: b runs its check on it (here it passes, the address is the same) and uses it; no connection of
     * b's own is set up.
     */
    @Test fun negative_h3AFilingMadeMeanwhileIsCheckedAgain() =
        h3Test {
            val (server, port) = h3Server()
            try {
                client(discovery = Http3DiscoveryMode.H3Only).use { c ->
                    val pool = engine(c).h3
                    c.h3("https://a.wild.test:$port/")
                    val a = pool.connectionsForTest().single()
                    val once = kotlin.concurrent.atomics.AtomicBoolean(true)
                    pool.beforeCandidatesForTest = { t ->
                        if (t.originHost == "b.wild.test" && once.compareAndSet(true, false)) {
                            pool.fileUnderForTest(
                                io.kuicksilver.ktor.client.h3
                                    .H3Target("a.wild.test", "a.wild.test", port),
                                t,
                            )
                        }
                    }
                    assertEquals("b.wild.test|HTTP/3", c.h3("https://b.wild.test:$port/"))
                    assertEquals(listOf(a), pool.connectionsForTest(), "b went on a's connection after its own check")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * The race once more, later: b chose one connection (and checked it), and before b files it a concurrent request files
     * another origin's connection under b. b does not take that one unchecked, nor does it skip it: it goes round again and
     * checks it for itself. Here every connection belongs to one origin each (the server answers 421 to any name but its
     * SNI, so c ended on a connection of its own); b's first attempt goes on the re-checked filing (and gets its 421), so
     * the call takes two attempts. Had b skipped the filing, it would have connected on its own at once.
     */
    @Test fun negative_h3AFilingMadeBeforeTheChosenOneIsFiledIsCheckedAgain() =
        h3Test {
            val (server, port) = h3Server(sni = true)
            try {
                client(discovery = Http3DiscoveryMode.H3Only).use { c ->
                    val pool = engine(c).h3
                    c.h3("https://a.wild.test:$port/")
                    assertEquals(2, c.get("https://c.wild.test:$port/").kuicksilverDiagnostics!!.attempts) // c: a 421, then its own
                    assertEquals(2, pool.connectionsForTest().size)
                    val once = kotlin.concurrent.atomics.AtomicBoolean(true)
                    pool.beforeFilingForTest = { t, chosen ->
                        if (t.originHost == "b.wild.test" && once.compareAndSet(true, false)) {
                            // whichever b chose, the other origin's connection is filed under b meanwhile
                            val other = if (chosen == "a.wild.test") "c.wild.test" else "a.wild.test"
                            pool.fileUnderForTest(
                                io.kuicksilver.ktor.client.h3
                                    .H3Target(other, other, port),
                                t,
                            )
                        }
                    }
                    val r = c.get("https://b.wild.test:$port/")
                    assertEquals(HttpStatusCode.OK, r.status)
                    assertEquals(2, r.kuicksilverDiagnostics!!.attempts, "b's first attempt went on the filing it checked again")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * The same race when b resolves elsewhere: b's own check of the filing fails, so b never uses a's connection and
     * connects on its own (to ::1, where nothing listens: it fails).
     */
    @Test fun negative_h3AFilingMadeMeanwhileThatFailsTheCheckIsNotUsed() =
        h3Test {
            val asked = AtomicInt(0)
            val (server, port) =
                testServer {
                    routing {
                        get("/") {
                            if (call.request.host() == "b.wild.test") asked.addAndFetch(1)
                            call.respondText("${call.request.host()}|${call.request.local.version}")
                        }
                    }
                }
            try {
                val dns = MapDns(mapOf("b.wild.test" to listOf(IpAddress.parse("::1"))))
                client(dns = dns, discovery = Http3DiscoveryMode.H3Only, engine = { connectTimeout = 3.seconds }).use { c ->
                    val pool = engine(c).h3
                    c.h3("https://a.wild.test:$port/")
                    val once = kotlin.concurrent.atomics.AtomicBoolean(true)
                    pool.beforeCandidatesForTest = { t ->
                        if (t.originHost == "b.wild.test" && once.compareAndSet(true, false)) {
                            pool.fileUnderForTest(
                                io.kuicksilver.ktor.client.h3
                                    .H3Target("a.wild.test", "a.wild.test", port),
                                t,
                            )
                        }
                    }
                    assertFailsWith<Throwable> { c.get("https://b.wild.test:$port/") }
                    assertEquals(0, asked.load(), "no request of b reached the server over a's connection")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * Bounded: a filing that comes back before every round costs at most three rounds, after which it is not there for this
     * request (b then connects on its own), rather than holding b in the loop.
     */
    @Test fun negative_h3AFilingThatKeepsComingBackEndsAfterThreeRounds() =
        h3Test {
            val (server, port) = h3Server()
            try {
                val dns = MapDns(mapOf("b.wild.test" to listOf(IpAddress.parse("::1"))))
                client(dns = dns, discovery = Http3DiscoveryMode.H3Only, engine = { connectTimeout = 3.seconds }).use { c ->
                    val pool = engine(c).h3
                    c.h3("https://a.wild.test:$port/")
                    val rounds = AtomicInt(0)
                    pool.beforeCandidatesForTest = { t ->
                        if (t.originHost == "b.wild.test") {
                            rounds.addAndFetch(1)
                            pool.fileUnderForTest(
                                io.kuicksilver.ktor.client.h3
                                    .H3Target("a.wild.test", "a.wild.test", port),
                                t,
                            )
                        }
                    }
                    withTimeout(20.seconds) { assertFailsWith<Throwable> { c.get("https://b.wild.test:$port/") } }
                    assertEquals(3, rounds.load())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    private suspend fun h3EchoServer(arrived: kotlinx.coroutines.CompletableDeferred<Unit>? = null) =
        testServer(tls = { sniSelector = { ServerTlsOverride(ClientFixtures.identity()) } }) {
            routing {
                get("/") { call.respondText("${call.request.host()}|${call.request.local.version}") }
                post("/echo") {
                    arrived?.complete(Unit)
                    call.respondText("${call.request.host()}|${call.receiveText()}")
                }
            }
        }

    /**
     * The 421's decision races the old attempt's sender: the application writes its whole body exactly while the 421 is
     * handled. The sender either took a byte first (the body is consumed: H3BodyConsumed) or the channel was kept before it
     * could (the repeat sends all of it): never a repeat that lost the start of the body. Twenty rounds.
     */
    @Test fun negative_h3ABodyWrittenAsThe421IsHandledIsRepeatedWholeOrNotAtAll() =
        h3Test {
            val (server, port) = h3EchoServer()
            val payload = (0 until 48 * 1024).map { 'a' + it % 26 }.joinToString("")
            var whole = 0
            var consumed = 0
            try {
                repeat(20) {
                    client(discovery = Http3DiscoveryMode.H3Only).use { c ->
                        c.h3("https://a.wild.test:$port/")
                        val body =
                            io.ktor.utils.io
                                .ByteChannel()
                        engine(c).h3.misdirectedForTest = {
                            body.writeStringUtf8(payload)
                            body.flushAndClose()
                            kotlinx.coroutines.yield()
                        }
                        try {
                            val r = c.post("https://b.wild.test:$port/echo") { setBody(body) }
                            assertEquals(HttpStatusCode.OK, r.status)
                            assertEquals("b.wild.test|$payload", r.bodyAsText(), "the repeat sent the whole body")
                            whole++
                        } catch (_: H3BodyConsumed) {
                            consumed++
                        }
                    }
                }
                assertEquals(20, whole + consumed)
                // the window is reached both ways: a test that stopped reaching it would prove nothing
                assertTrue(whole > 0 && consumed > 0, "whole=$whole consumed=$consumed")
            } finally {
                server.stop(100, 500)
            }
        }

    /** A content that opens a new channel per readFrom() (as a file's does): the channels it opened. */
    private class FreshChannels : io.ktor.http.content.OutgoingContent.ReadChannelContent() {
        val made = kotlin.concurrent.atomics.AtomicReference(emptyList<io.ktor.utils.io.ByteChannel>())

        override fun readFrom(): io.ktor.utils.io.ByteReadChannel =
            io.ktor.utils.io.ByteChannel().also { ch ->
                while (true) {
                    val l = made.load()
                    if (made.compareAndSet(l, l + ch)) break
                }
            }
    }

    /**
     * The repeat after a 421 sends the very channel the first attempt kept untouched: a content that opens a new channel per
     * readFrom() is not asked again, so no channel of it is left open behind the call.
     */
    @Test fun h3TheRepeatTakesTheKeptChannel() =
        h3Test {
            val arrived = kotlinx.coroutines.CompletableDeferred<Unit>()
            val (server, port) = h3EchoServer(arrived)
            try {
                client(discovery = Http3DiscoveryMode.H3Only).use { c ->
                    c.h3("https://a.wild.test:$port/")
                    val content = FreshChannels()
                    kotlinx.coroutines.coroutineScope {
                        val writer =
                            launch {
                                arrived.await()
                                val ch = content.made.load().last()
                                ch.writeStringUtf8("from a file")
                                ch.flushAndClose()
                            }
                        val r = c.post("https://b.wild.test:$port/echo") { setBody(content) }
                        assertEquals("b.wild.test|from a file", r.bodyAsText())
                        assertEquals(2, r.kuicksilverDiagnostics!!.attempts)
                        writer.join()
                    }
                    assertEquals(1, content.made.load().size, "readFrom() was called once: the repeat took the kept channel")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A repeat that goes over TCP (HTTP/1.1, or HTTP/2's body source) sends the kept channel too: a content that opens a new
     * channel per readFrom() is not opened again. The TCP writers are driven directly with a request that carries a kept
     * channel, as the engine hands it over after a 421 over HTTP/3.
     */
    @Test fun aRepeatOverTcpTakesTheKeptChannel() =
        kotlinx.coroutines.test.runTest {
            fun request(content: FreshChannels) =
                HttpRequestBuilder()
                    .apply {
                        url.takeFrom("https://b.wild.test/echo")
                        method = io.ktor.http.HttpMethod.Post
                        setBody(content)
                    }.build()
            // HTTP/1.1: the body as chunks
            val h1 = FreshChannels()
            val data = request(h1)
            data.attributes.put(io.kuicksilver.ktor.client.h3.KeptRequestBodyKey, keptWith("kept body"))
            val wire =
                io.ktor.utils.io
                    .ByteChannel()
            io.kuicksilver.ktor.client.h1
                .writeBody(data, wire, coroutineContext)
            wire.flushAndClose()
            assertTrue("kept body" in wire.readBuffer().readString())
            assertEquals(0, h1.made.load().size, "readFrom() was not called again")
            // HTTP/2 (and HTTP/3): the body source
            val h2 = FreshChannels()
            val source =
                io.kuicksilver.ktor.client.h3.H3Pool.bodyChannel(
                    h2,
                    coroutineContext,
                    keptWith("kept body"),
                )!!
            assertEquals("kept body", source.readBuffer().readString())
            assertEquals(0, h2.made.load().size)
        }

    private suspend fun keptWith(text: String): io.kuicksilver.ktor.client.h3.KeptRequestBody {
        val ch =
            io.ktor.utils.io
                .ByteChannel()
        ch.writeStringUtf8(text)
        ch.flushAndClose()
        return io.kuicksilver.ktor.client.h3
            .KeptRequestBody(ch)
    }

    /** A call that ends before its repeat took the kept channel (b's own handshake is refused) cancels that channel. */
    @Test fun negative_aKeptChannelIsCancelledWhenTheCallEndsBeforeTheRepeat() =
        h3Test {
            val (server, port) = h3EchoServer()
            try {
                val sw = Switchable()
                client(discovery = Http3DiscoveryMode.H3Only, engine = { trust = sw.trust }).use { c ->
                    c.h3("https://a.wild.test:$port/")
                    engine(c).h3.misdirectedForTest = { sw.refusedHosts = setOf("b.wild.test") }
                    val content = FreshChannels()
                    assertFailsWith<Throwable> { c.post("https://b.wild.test:$port/echo") { setBody(content) } }
                    val first = content.made.load().first()
                    withTimeout(10.seconds) { while (first.closedCause == null) kotlinx.coroutines.yield() }
                    assertEquals(1, content.made.load().size)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** The H3 counterpart of the revoked-certificate test: a's connection is retired under every key. */
    @Test fun negative_h3ARevokedCertificateRetiresTheConnection() =
        h3Test {
            val (server, port) = h3Server()
            try {
                val sw = Switchable()
                val log = RecordingLogger()
                client(discovery = Http3DiscoveryMode.H3Only, engine = {
                    trust = sw.trust
                    logger = log
                }).use { c ->
                    c.h3("https://a.wild.test:$port/")
                    val a = engine(c).h3.connectionsForTest().single()
                    sw.revoked = true
                    assertFailsWith<Throwable> { c.get("https://b.wild.test:$port/") }
                    assertTrue(log.lines.any { "no longer passes" in it && "Revoked" in it }, "${log.lines}")
                    sw.revoked = false
                    c.h3("https://a.wild.test:$port/")
                    assertTrue(a !in engine(c).h3.connectionsForTest(), "a's next request went on a new connection")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** And a refusal of b alone leaves a's HTTP/3 connection in place. */
    @Test fun negative_h3ARefusalOfTheNewHostAloneKeepsTheConnection() =
        h3Test {
            val (server, port) = h3Server()
            try {
                val sw = Switchable()
                client(discovery = Http3DiscoveryMode.H3Only, engine = { trust = sw.trust }).use { c ->
                    c.h3("https://a.wild.test:$port/")
                    val a = engine(c).h3.connectionsForTest().single()
                    sw.refusedHosts = setOf("b.wild.test")
                    assertFailsWith<Throwable> { c.get("https://b.wild.test:$port/") }
                    c.h3("https://a.wild.test:$port/")
                    assertTrue(a in engine(c).h3.connectionsForTest())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A 0-RTT connection's server is not authenticated until its handshake completes: no other origin goes on it before. The
     * resumed connection's replies are held back 1.5 s, and b asks while a's request holds it, still in its handshake.
     */
    @Test fun negative_h3AZeroRttConnectionCarriesNoOtherOrigin() =
        h3Test {
            val (server, port) =
                testServer(configure = { quicEarlyData = true }) {
                    routing { get("/") { call.respondText("${call.request.host()}|${call.request.local.version}") } }
                }
            val ios = FaultyIos()
            try {
                client(discovery = Http3DiscoveryMode.H3Only, engine = {
                    http3 {
                        earlyData = true
                        endpoint =
                            io.kuicksilver.quic.QuicEndpointConfig
                                .Builder()
                                .apply { io = { local -> ios.open(local) } }
                                .build()
                    }
                }).use { c ->
                    val engine = engine(c)
                    c.h3("https://a.wild.test:$port/")
                    c.h3("https://a.wild.test:$port/") // the ticket arrived meanwhile
                    engine.h3.dropConnectionsForTest().forEach { it.close() }
                    ios.delayReceived(1500.milliseconds)
                    val armed = kotlin.concurrent.atomics.AtomicBoolean(true)
                    var early: Boolean? = null
                    var b: String? = null
                    engine.h3.afterAcquireForTest = {
                        if (armed.compareAndSet(true, false)) {
                            early = engine.h3
                                .connectionsForTest()
                                .singleOrNull()
                                ?.quic
                                ?.isHandshakeComplete == false
                            b = c.get("https://b.wild.test:$port/").bodyAsText()
                        }
                    }
                    assertEquals("a.wild.test|HTTP/3", c.h3("https://a.wild.test:$port/"))
                    assertEquals(true, early, "b asked while a's resumed connection was still in its handshake")
                    assertEquals("b.wild.test|HTTP/3", b)
                    assertEquals(0, engine.h3.sharedForTest.load())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** A WebTransport session takes a connection of its own origin, never another origin's (WebTransport-capable or not). */
    @Test fun negative_webTransportNeverCoalesces() =
        h3Test {
            val (server, port) =
                testServer(configure = { webTransport = true }) {
                    routing { webTransport("/wt") { it.closed.await() } }
                }
            try {
                client(discovery = Http3DiscoveryMode.H3Only).use { c ->
                    val a = c.webTransport("https://a.wild.test:$port/wt")
                    val b = c.webTransport("https://b.wild.test:$port/wt")
                    assertEquals(0, engine(c).h3.sharedForTest.load())
                    assertEquals(2, engine(c).h3.connectionsForProbe())
                    a.close()
                    b.close()
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    // ---- the checks on their own ----

    /** The gate: on, https, direct, no WebSocket, not the repeat of a 421'd attempt. */
    @Test fun negative_onlyDirectHttpsRequestsMayCoalesce() {
        val on = KuicksilverEngineConfig().apply { connectionCoalescing = true }

        fun data(
            url: String,
            block: HttpRequestBuilder.() -> Unit = {},
        ) = HttpRequestBuilder()
            .apply {
                this.url.takeFrom(url)
                block()
            }.build()
        assertTrue(on.mayCoalesce(data("https://b.wild.test/"), viaProxy = false))
        assertFalse(KuicksilverEngineConfig().mayCoalesce(data("https://b.wild.test/"), viaProxy = false))
        assertFalse(on.mayCoalesce(data("http://b.wild.test/"), viaProxy = false))
        assertFalse(on.mayCoalesce(data("https://b.wild.test/"), viaProxy = true))
        assertFalse(on.mayCoalesce(data("https://b.wild.test/") { attributes.put(NoCoalescingKey, Unit) }, viaProxy = false))
        @OptIn(io.ktor.utils.io.InternalAPI::class)
        val ws =
            data("wss://b.wild.test/") {
                attributes.put(
                    io.ktor.client.plugins.websocket.WEBSOCKETS_KEY,
                    io.ktor.client.plugins.websocket
                        .WebSockets(),
                )
            }
        assertFalse(on.mayCoalesce(ws, viaProxy = false))
        // trusts that do not name the host, or learn keys per name
        for (t in listOf(
            TrustConfig.Tofu(tofuStore()),
            TrustConfig.ExpectedName("server.test", ClientFixtures.trust),
            TrustConfig.Pinned(setOf(Certificate(TestCerts.server).spkiSha256), base = TrustConfig.ExpectedName("server.test")),
        )) {
            val config =
                KuicksilverEngineConfig().apply {
                    connectionCoalescing = true
                    trust = t
                }
            assertFalse(config.mayCoalesce(data("https://b.wild.test/"), viaProxy = false), "$t")
        }
    }

    /** A 421 is final for the connection: an acceptance that a check finishes afterwards never undoes it. */
    @Test fun negative_aRefusalIsNeverUndone() {
        val hosts = CoalescedHosts()
        hosts.record("b.wild.test", accepted = false)
        hosts.record("b.wild.test", accepted = true)
        assertEquals(false, hosts.verdict("b.wild.test"))
        assertFalse(hosts.anyAccepted())
        hosts.record("c.wild.test", accepted = true)
        assertEquals(true, hosts.verdict("c.wild.test"))
        repeat(300) { hosts.record("h$it.wild.test", accepted = true) }
        assertEquals(null, hosts.verdict("c.wild.test"), "bounded: the oldest acceptances are forgotten (and checked again)")
        assertTrue(hosts.anyAccepted(), "the connection carried another origin once, whatever the bound forgot")
        // one host however it is written: case and a trailing dot change nothing (RFC 9525 section 6.3)
        assertEquals(false, hosts.verdict("B.Wild.Test."))
        assertEquals(false, hosts.verdict("b.wild.test"), "a refusal is not forgotten with the bound")
    }

    /**
     * The refusals a connection keeps are bounded too, and never forgotten: past the bound the connection refuses every
     * host it holds no acceptance for, so a flood of hosts can neither grow the set nor make an old refusal fall out.
     */
    @Test fun negative_tooManyRefusalsRefuseEveryNewHost() {
        val hosts = CoalescedHosts()
        hosts.record("kept.wild.test", accepted = true)
        repeat(CoalescedHosts.MAX_REFUSED) { hosts.record("r$it.wild.test", accepted = false) }
        assertEquals(null, hosts.verdict("new.wild.test"), "at the bound, an unknown host is still checked")
        hosts.record("one-more.wild.test", accepted = false)
        assertEquals(false, hosts.verdict("one-more.wild.test"))
        assertEquals(false, hosts.verdict("new.wild.test"), "past the bound, every unknown host is refused")
        assertEquals(false, hosts.verdict("r0.wild.test"), "the old refusals stay")
        assertEquals(true, hosts.verdict("kept.wild.test"), "an acceptance it holds still stands")
        hosts.record("new.wild.test", accepted = true)
        assertEquals(false, hosts.verdict("new.wild.test"), "and no new host is accepted")
    }

    /**
     * [checkCoalescing] on its own, under a trust that counts its verifications: the address first (no verification when it
     * does not match), then the certificate once per connection and host; an expired certificate (which fails for the
     * connection's own origin too) retires the connection (RFC 9114 section 3.3), a name it does not carry only refuses the
     * host, a refusal of the new host alone too, and a Tofu trust never retires.
     */
    @Test fun negative_theChecksInOrder() =
        runBlocking {
            val verified = AtomicInt(0)
            val sw = Switchable()
            val config =
                KuicksilverEngineConfig().apply {
                    trust =
                        TrustConfig.Custom { chain, name, _ ->
                            verified.addAndFetch(1)
                            when {
                                name == "a.wild.test" && name in sw.refusedHosts -> VerifyResult.Rejected(sw.ownReason)
                                name in sw.refusedHosts -> VerifyResult.Rejected(io.kuicksilver.tls.VerifyReason.Revoked)
                                else -> VerifyResult.Accepted(chain)
                            }
                        }
                    dns = MapDns(mapOf("far.wild.test" to listOf(IpAddress.parse("127.0.0.2"))))
                }
            val chain = listOf(Certificate(TestCerts.server))
            val here = Destination(byteArrayOf(127, 0, 0, 1), 443, 0)

            fun peer(
                c: List<Certificate> = chain,
                own: String = "a.wild.test",
            ) = CoalescingPeer(own, here, c, 0L, false, CoalescedHosts())
            val p = peer()
            val dns = config.newRequestDns()
            val alpn = listOf("h2", "http/1.1")
            assertEquals(Coalesce.No, config.checkCoalescing(p, "far.wild.test", 443, dns, alpn))
            assertEquals(0, verified.load(), "no verification for another address")
            assertEquals(Coalesce.No, config.checkCoalescing(p, "b.wild.test", 8443, dns, alpn), "another port")
            assertEquals(Coalesce.Yes, config.checkCoalescing(p, "b.wild.test", 443, dns, alpn))
            assertEquals(Coalesce.Yes, config.checkCoalescing(p, "B.wild.test.", 443, dns, alpn), "the same host, written otherwise")
            assertEquals(1, verified.load(), "once per connection and host")
            assertEquals(Coalesce.No, config.checkCoalescing(p, "other.test", 443, dns, alpn))
            assertEquals(Coalesce.No, config.checkCoalescing(peer(emptyList()), "c.wild.test", 443, dns, alpn))
            // the new host's own refusal: its origin's check passes, the connection stays
            sw.refusedHosts = setOf("e.wild.test")
            val retired = ArrayList<Pair<io.kuicksilver.tls.VerifyReason, io.kuicksilver.tls.VerifyReason>>()
            assertEquals(
                Coalesce.No,
                config.checkCoalescing(p, "e.wild.test", 443, dns, alpn) { own, forHost -> retired += own to forHost },
            )
            assertTrue(retired.isEmpty())
            // a refusal that holds for the connection's own origin too retires it, and says why
            sw.refusedHosts = setOf("f.wild.test", "a.wild.test")
            sw.ownReason = io.kuicksilver.tls.VerifyReason.Expired
            assertEquals(
                Coalesce.Retire,
                config.checkCoalescing(p, "f.wild.test", 443, dns, alpn) { own, forHost ->
                    retired +=
                        own to forHost
                },
            )
            // the reason it is retired is its own origin's; the new host's comes with it
            assertEquals(
                listOf<Pair<io.kuicksilver.tls.VerifyReason, io.kuicksilver.tls.VerifyReason>>(
                    io.kuicksilver.tls.VerifyReason.Expired to io.kuicksilver.tls.VerifyReason.Revoked,
                ),
                retired.toList(),
            )
            // once per connection: another host that meets the same retires it again, without a second line
            sw.refusedHosts = sw.refusedHosts + "g.wild.test"
            assertEquals(
                Coalesce.Retire,
                config.checkCoalescing(p, "g.wild.test", 443, dns, alpn) { own, forHost ->
                    retired +=
                        own to forHost
                },
            )
            assertEquals(1, retired.size)
            val expired = listOf(Certificate(TestCerts.expired))
            val anchored =
                KuicksilverEngineConfig().apply {
                    trust = ClientFixtures.trust
                    this.dns = MapDns()
                }
            assertEquals(
                Coalesce.Retire,
                anchored.checkCoalescing(peer(expired, own = "server.test"), "server.test", 443, anchored.newRequestDns(), alpn),
            )
            // under Tofu nothing is coalesced, and a's connection is never retired for it
            val tofu =
                KuicksilverEngineConfig().apply {
                    trust = TrustConfig.Tofu(tofuStore())
                    this.dns = MapDns()
                }
            assertEquals(Coalesce.No, tofu.checkCoalescing(peer(expired), "b.wild.test", 443, tofu.newRequestDns(), alpn))
            // a host refused on the connection stays refused (no lookup, no verification)
            p.hosts.record("d.wild.test", accepted = false)
            val before = verified.load()
            assertEquals(Coalesce.No, config.checkCoalescing(p, "d.wild.test", 443, dns, alpn))
            assertEquals(before, verified.load())
        }
}
