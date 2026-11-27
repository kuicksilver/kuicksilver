// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    io.kuicksilver.annotations.ExperimentalKuicksilverApi::class,
    io.kuicksilver.annotations.InternalKuicksilverApi::class,
    io.kuicksilver.annotations.DelicateKuicksilverApi::class,
)

package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.request.host
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.ktor.client.h3.Destination
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.PinScope
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyReason
import io.kuicksilver.tls.VerifyResult
import kotlinx.coroutines.runBlocking
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * `engine { tls { pins { } } }` at work: the per-host pins over HTTP/1.1, HTTP/2 and HTTP/3, the message of a mismatch, the
 * refusals when the engine is created, the proxy hop and connection coalescing. The test server's certificate names
 * `server.test`, `*.wild.test`, 127.0.0.1 and ::1 under the test CA.
 */
class ClientHostPinsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val leaf = SpkiSha256(TestCerts.serverSpkiSha256)
    private val ca by lazy { Certificate(TestCerts.testCa).spkiSha256 }
    private val wrong = SpkiSha256(ByteArray(32) { 7 })

    /** Names resolve to 127.0.0.1. */
    private object Loopback : Dns {
        override suspend fun lookup(host: String): List<IpAddress> = listOf(IpAddress.parse("127.0.0.1"))
    }

    private fun client(
        discovery: Http3Discovery? = null,
        engine: KuicksilverEngineConfig.() -> Unit,
    ): HttpClient =
        testClient(discovery, engine = {
            network { dns = Loopback }
            proxies { resolver = ProxyResolvers.None }
            engine()
        })

    private fun pinsOf(block: HostPinsConfig.() -> Unit) = block

    private fun pinMismatch(e: Throwable): VerifyReason.PinMismatch {
        val v = generateSequence(e) { it.cause }.filterIsInstance<TlsException.Verify>().firstOrNull()
        return assertIs<VerifyReason.PinMismatch>(v?.reason, "$e")
    }

    private suspend fun server(
        http2: Boolean = false,
        http3: Boolean = false,
    ) = testServer(configure = {
        http2 { enabled = http2 }
        http3 { enabled = http3 }
    }) {
        routing { get("/") { call.respondText("${call.request.host()}|${call.request.local.version}") } }
    }

    // ---- the protocols ----

    /** A host whose pins miss the chain fails over HTTP/1.1, HTTP/2 and HTTP/3 alike, and the message names it and the chain. */
    @Test fun negative_aMismatchFailsOnEveryProtocolNamingTheHostAndTheChain() =
        clientTest {
            for ((http2, discovery) in listOf(false to null, true to null) +
                (if (quicServerSupported()) listOf(false to Http3Discovery.H3Only) else emptyList())) {
                val (server, port) = server(http2 = http2, http3 = discovery != null)
                try {
                    client(discovery) {
                        if (!http2) this.http2 { enabled = false }
                        tls { pins { add("*.wild.test", wrong.toString()) } }
                    }.use { c ->
                        val e = assertFailsWith<Throwable>("h2=$http2 $discovery") { c.get("https://a.wild.test:$port/") }
                        val m = pinMismatch(e)
                        assertEquals("a.wild.test", m.host)
                        assertEquals(listOf(leaf, ca), m.chainPins, "the validated chain's pins, leaf first")
                        val v = generateSequence(e) { it.cause }.filterIsInstance<TlsException.Verify>().first()
                        assertContains(v.message!!, "PinMismatch(host=a.wild.test, chain=[$leaf, $ca])")
                        // a host no pattern matches has no pins: the same server and connection setup pass
                        val ok = c.get("https://server.test:$port/").bodyAsText()
                        assertTrue(ok.startsWith("server.test|"), ok)
                    }
                    client(discovery) {
                        if (!http2) this.http2 { enabled = false }
                        tls { pins { add("*.wild.test", wrong.toString(), leaf.toString()) } }
                    }.use { c ->
                        val r = c.get("https://a.wild.test:$port/")
                        val want =
                            when {
                                discovery != null -> HttpProtocolVersion.HTTP_3_0
                                http2 -> HttpProtocolVersion.HTTP_2_0
                                else -> HttpProtocolVersion.HTTP_1_1
                            }
                        assertEquals(want, r.version)
                        assertTrue(r.bodyAsText().startsWith("a.wild.test|"))
                    }
                } finally {
                    server.stop(100, 500)
                }
            }
        }

    /** Q7: Leaf by default, so the CA's pin alone fails; `scope = AnyInValidatedChain` lets it match (OkHttp's semantics). */
    @Test fun negative_theScopeIsLeafByDefault() =
        clientTest {
            val (server, port) = server()
            try {
                client { tls { pins { add("server.test", ca) } } }.use { c ->
                    val m = pinMismatch(assertFailsWith<Throwable> { c.get("https://server.test:$port/") })
                    assertEquals(listOf(leaf, ca), m.chainPins, "the CA's pin is in the chain, but Leaf only looks at the leaf")
                }
                client {
                    tls {
                        pins {
                            add("server.test", ca)
                            scope = PinScope.AnyInValidatedChain
                        }
                    }
                }.use { c ->
                    assertTrue(c.get("https://server.test:$port/").bodyAsText().startsWith("server.test|"))
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** The pins sit on top of the base trust (AND): the right pin with an untrusted chain still fails, as the CA's verdict. */
    @Test fun negative_pinsNeverReplaceTheTrust() =
        clientTest {
            val (server, port) = server()
            try {
                client {
                    tls {
                        trust = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.otherCa)))
                        pins { add("server.test", leaf) }
                    }
                }.use { c ->
                    val e = assertFailsWith<Throwable> { c.get("https://server.test:$port/") }
                    val v = generateSequence(e) { it.cause }.filterIsInstance<TlsException>().firstOrNull()
                    assertTrue(v != null, "$e")
                    assertFalse((v as? TlsException.Verify)?.reason is VerifyReason.PinMismatch, "$e")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    // ---- the configuration ----

    /** Each connection's trust is `Pinned(host's set, scope, base = trust)`; a host without pins keeps `trust` itself. */
    @Test fun theConnectionsTrustIsPinnedPerHost() {
        val config =
            KuicksilverEngineConfig().apply {
                tls {
                    trust = ClientFixtures.trust
                    pins {
                        add("**.wild.test", leaf)
                        add("a.wild.test", wrong)
                        scope = PinScope.AnyInValidatedChain
                    }
                }
            }
        val a = assertIs<TrustConfig.Pinned>(config.tlsConfigFor("A.wild.test", listOf("h3"), quic = true).trust)
        assertEquals(setOf(leaf, wrong), a.pins)
        assertEquals(PinScope.AnyInValidatedChain, a.scope)
        assertSame(ClientFixtures.trust, a.base)
        assertEquals(setOf(leaf), assertIs<TrustConfig.Pinned>(config.tlsConfigFor("b.wild.test", listOf("h2"), quic = false).trust).pins)
        assertSame(ClientFixtures.trust, config.tlsConfigFor("server.test", listOf("h2"), quic = false).trust)
    }

    /** Pins and `trust = Pinned(…)` are two sources of one concept: refused when the engine is created, with both names. */
    @Test fun negative_pinsWithAPinnedTrustAreRefused() {
        val e =
            assertFailsWith<IllegalArgumentException> {
                HttpClient(Kuicksilver) {
                    engine {
                        tls {
                            trust = TrustConfig.Pinned(setOf(leaf), base = ClientFixtures.trust)
                            pins { add("server.test", leaf) }
                        }
                    }
                }.close()
            }
        assertContains(e.message!!, "tls { pins { } } and tls { trust = TrustConfig.Pinned(…) } are two sources of pins")
    }

    /** Pins never sit on a trust that decides alone (ADR-0011), as `TrustConfig.Pinned` refuses it. */
    @Test fun negative_pinsOnTofuOrCustomAreRefused() {
        val custom = TrustConfig.Custom { chain, _, _ -> VerifyResult.Accepted(chain) }
        val store =
            object : io.kuicksilver.tls.TofuStore {
                override suspend fun get(name: String): SpkiSha256? = null

                override suspend fun put(
                    name: String,
                    pin: SpkiSha256,
                ) = Unit
            }
        for (t in listOf(TrustConfig.Tofu(store), custom, TrustConfig.ExpectedName("server.test", custom))) {
            val e =
                assertFailsWith<IllegalArgumentException>("$t") {
                    HttpClient(Kuicksilver) {
                        engine {
                            tls {
                                trust = t
                                pins { add("server.test", leaf) }
                            }
                        }
                    }.close()
                }
            assertContains(e.message!!, "tls { pins { } } cannot be combined with trust")
        }
        // without pins the same trusts are fine; with ExpectedName over the CA pins are fine too
        HttpClient(Kuicksilver) {
            engine {
                tls {
                    trust = TrustConfig.ExpectedName("server.test", ClientFixtures.trust)
                    pins { add("server.test", leaf) }
                }
            }
        }.close()
    }

    @Test fun negative_proxyPinsWithAPinnedProxyTrustAreRefused() {
        val e =
            assertFailsWith<IllegalArgumentException> {
                HttpClient(Kuicksilver) {
                    engine {
                        proxies {
                            tls {
                                trust = TrustConfig.Pinned(setOf(leaf), base = ClientFixtures.trust)
                                pins { add("proxy.internal", leaf) }
                            }
                        }
                    }
                }.close()
            }
        assertContains(e.message!!, "proxies { tls { pins { } } } and proxies { tls { trust = TrustConfig.Pinned(…) } }")
    }

    // ---- proxies ----

    private fun KuicksilverEngineConfig.through(proxyPort: Int) {
        network { dns = Loopback }
        proxies { resolver = ProxyResolver { ResolvedProxy.https("proxy.internal", proxyPort) } }
    }

    private suspend fun origin(block: suspend (Int) -> Unit) {
        val (server, port) = server()
        try {
            block(port)
        } finally {
            server.stop(100, 500)
        }
    }

    /**
     * Through an `https://` proxy the origin's TLS inside the tunnel meets the origin's pins, never the proxy's; the engine's
     * pins never reach the proxy hop, even a pattern that matches the proxy's name; `proxies { tls { pins } }` pins the proxy.
     */
    @Test fun negative_aTunnelCarriesTheOriginsPinsAndTheProxyHopItsOwn() =
        clientTest {
            origin { originPort ->
                // the origin's pins hold inside the tunnel
                tlsProxy(originPort) { proxyPort, _ ->
                    testClient(engine = {
                        through(proxyPort)
                        tls { pins { add("server.test", wrong) } }
                    }).use { c ->
                        val e = assertFailsWith<Throwable> { c.get("https://server.test:$originPort/") }
                        assertEquals("server.test", pinMismatch(e).host)
                        assertFalse(generateSequence(e) { it.cause }.any { it is ProxyException }, "the proxy's failure: $e")
                    }
                }
                // a pattern of the engine's that also matches the proxy's name does not pin the proxy
                tlsProxy(originPort) { proxyPort, _ ->
                    testClient(engine = {
                        through(proxyPort)
                        tls {
                            pins {
                                add("server.test", leaf)
                                add("**.internal", wrong)
                            }
                        }
                    }).use { c ->
                        assertTrue(c.get("https://server.test:$originPort/").bodyAsText().startsWith("server.test|"))
                    }
                }
                // the proxy's own block pins the proxy's host
                tlsProxy(originPort) { proxyPort, _ ->
                    testClient(engine = {
                        through(proxyPort)
                        proxies { tls { pins { add("proxy.internal", wrong) } } }
                    }).use { c ->
                        val e = assertFailsWith<Throwable> { c.get("https://server.test:$originPort/") }
                        assertEquals("proxy.internal", pinMismatch(e).host)
                    }
                }
                tlsProxy(originPort) { proxyPort, _ ->
                    testClient(engine = {
                        through(proxyPort)
                        proxies { tls { pins { add("proxy.internal", Certificate(TestCerts.proxy).spkiSha256) } } }
                        tls { pins { add("server.test", leaf) } }
                    }).use { c ->
                        assertTrue(c.get("https://server.test:$originPort/").bodyAsText().startsWith("server.test|"))
                    }
                }
            }
        }

    // ---- coalescing ----

    /** RFC 9113 section 9.1.1 lets a client decline reuse: two hosts share a connection only with the same pins. */
    @Test fun negative_coalescingNeedsEqualPins() =
        runBlocking {
            val chain = listOf(Certificate(TestCerts.server))
            val here = Destination(byteArrayOf(127, 0, 0, 1), 443, 0)
            val alpn = listOf("h2", "http/1.1")

            fun config(pins: HostPinsConfig.() -> Unit) =
                KuicksilverEngineConfig().apply {
                    tls {
                        trust = ClientFixtures.trust
                        pins(pins)
                    }
                    network { dns = Loopback }
                }
            val peer = CoalescingPeer("a.wild.test", here, chain, 0L, false, CoalescedHosts())
            // the same set (also as two patterns): shared
            val same =
                config {
                    add("a.wild.test", leaf)
                    add("*.wild.test", leaf)
                }
            assertEquals(Coalesce.Yes, same.checkCoalescing(peer, "b.wild.test", 443, same.newRequestDns(), alpn))
            // b's pins are a superset that the chain passes, a's are a subset: still another policy, not shared
            for (other in listOf(
                pinsOf {
                    add("a.wild.test", leaf)
                    add("b.wild.test", leaf, wrong)
                },
                pinsOf { add("b.wild.test", leaf) },
                pinsOf { add("a.wild.test", leaf) },
            )) {
                val c = config(other)
                val p = CoalescingPeer("a.wild.test", here, chain, 0L, false, CoalescedHosts())
                assertEquals(Coalesce.No, c.checkCoalescing(p, "b.wild.test", 443, c.newRequestDns(), alpn))
                assertFalse(c.samePins("b.wild.test", "a.wild.test"))
            }
            // no pins anywhere: shared as before
            val none = config {}
            assertEquals(Coalesce.Yes, none.checkCoalescing(peer, "c.wild.test", 443, none.newRequestDns(), alpn))
        }

    /** The same over real HTTP/2 connections: equal sets share one, unequal ones get one each. */
    @Test fun negative_h2CoalescesOnlyHostsWithEqualPins() =
        clientTest {
            val (server, port) = server(http2 = true)
            try {
                for ((pins, connections) in listOf(
                    pinsOf { add("*.wild.test", leaf) } to 1,
                    pinsOf {
                        add("a.wild.test", leaf)
                        add("b.wild.test", leaf, ca)
                    } to 2,
                )) {
                    client {
                        pool { coalescing = true }
                        tls { pins(pins) }
                    }.use { c ->
                        assertEquals(HttpProtocolVersion.HTTP_2_0, c.get("https://a.wild.test:$port/").version)
                        assertEquals(HttpProtocolVersion.HTTP_2_0, c.get("https://b.wild.test:$port/").version)
                        assertEquals(connections, (c.engine as KuicksilverEngine).h1.h2.connectionCount)
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** HTTP/3 too (RFC 9114 section 3.3). */
    @Test fun negative_h3CoalescesOnlyHostsWithEqualPins() =
        h3Test {
            val (server, port) = server(http3 = true)
            try {
                for ((pins, connections) in listOf(
                    pinsOf { add("**.wild.test", leaf) } to 1,
                    pinsOf { add("b.wild.test", leaf) } to 2,
                )) {
                    client(Http3Discovery.H3Only) {
                        pool { coalescing = true }
                        tls { pins(pins) }
                    }.use { c ->
                        assertEquals(HttpProtocolVersion.HTTP_3_0, c.get("https://a.wild.test:$port/").version)
                        assertEquals(HttpProtocolVersion.HTTP_3_0, c.get("https://b.wild.test:$port/").version)
                        assertEquals(connections, (c.engine as KuicksilverEngine).h3.connectionsForTest().size)
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Self-attack: a redirect to another host meets that host's pins, not the first one's. */
    @Test fun negative_aRedirectMeetsTheNewHostsPins() =
        clientTest {
            val (server, port) =
                testServer(configure = { http2 { enabled = false } }) {
                    routing {
                        get("/") { call.respondText("${call.request.host()}|ok") }
                        get("/go") {
                            call.response.headers.append("Location", "https://b.wild.test:${call.request.local.localPort}/")
                            call.respondText("", status = io.ktor.http.HttpStatusCode.Found)
                        }
                    }
                }
            try {
                client {
                    tls {
                        pins {
                            add("a.wild.test", leaf)
                            add("b.wild.test", wrong)
                        }
                    }
                }.use { c ->
                    val e = assertFailsWith<Throwable> { c.get("https://a.wild.test:$port/go") }
                    assertEquals("b.wild.test", pinMismatch(e).host)
                    assertNotEquals("", c.get("https://a.wild.test:$port/").bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    // ---- escapes (review B1, M2) ----

    /**
     * Every spelling of a pinned host that could reach a server fails: the OWS spellings (B1: `" server.test"` was served
     * unpinned through a custom `dns`) meet the host's pins, and the address forms the TLS layer does not take as a
     * reference identifier (`2130706433`, `127.1`, `0x7f.0.0.1`, an IPv6 zone) fail closed, never unpinned.
     */
    @Test fun negative_noSpellingOfAPinnedHostEscapesThePins() =
        clientTest {
            val (server, port) = server()
            try {
                client {
                    tls {
                        pins {
                            add("server.test", wrong)
                            add("127.0.0.1", wrong)
                        }
                    }
                }.use { c ->
                    for (host in listOf(" server.test", "server.test ", "\tserver.test", "SERVER.test.", " 127.0.0.1")) {
                        val e =
                            assertFailsWith<Throwable>("[$host]") {
                                c.get {
                                    url {
                                        protocol = io.ktor.http.URLProtocol.HTTPS
                                        this.host = host
                                        this.port = port
                                    }
                                }
                            }
                        val m = pinMismatch(e)
                        assertEquals(if ('1' in host) "127.0.0.1" else "server.test", m.host, "[$host]: the normalized host")
                    }
                    for (url in listOf(
                        "https://2130706433:$port/",
                        "https://127.1:$port/",
                        "https://0x7f.0.0.1:$port/",
                        "https://[fe80::1%25en0]:$port/",
                        "https://[::ffff:127.0.0.1]:$port/",
                    )) {
                        val e = runCatching { c.get(url).bodyAsText() }
                        assertTrue(e.isFailure, "$url was served: ${e.getOrNull()}")
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * An `Alt-Svc` alternative on another host (RFC 7838 section 2.1: it must present the origin's certificate) meets the
     * origin's pins, never its own host's: with the alternative's host pinned wrong the HTTP/3 request goes through, with
     * the origin pinned wrong it fails, over HTTP/3 and the TCP fallback alike.
     */
    @Test fun negative_anAltSvcAlternativeMeetsTheOriginsPins() =
        h3Test {
            val (server, port) = server(http3 = true)
            try {
                for (originPinned in listOf(true, false)) {
                    val store = InMemoryAltSvcStore()
                    val far = Long.MAX_VALUE
                    store.put(
                        AltSvcStore.originOf(io.ktor.http.Url("https://a.wild.test:$port/")),
                        listOf(AltSvcEntry("h3", "alt.wild.test", port, far, false)),
                    )
                    client(Http3Discovery.Auto) {
                        http3 {
                            altSvcStore = store
                            expert { raceHeadStart = RaceHeadStart.NoRace }
                        }
                        tls {
                            pins {
                                add("a.wild.test", if (originPinned) leaf else wrong)
                                add("alt.wild.test", if (originPinned) wrong else leaf)
                            }
                        }
                    }.use { c ->
                        if (originPinned) {
                            val r = c.get("https://a.wild.test:$port/")
                            assertEquals(HttpProtocolVersion.HTTP_3_0, r.version, "the alternative carried it")
                        } else {
                            val e = assertFailsWith<Throwable> { c.get("https://a.wild.test:$port/") }
                            assertEquals("a.wild.test", pinMismatch(e).host)
                        }
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** An HTTPS record's endpoint with another TargetName (RFC 9460) meets the origin's pins, as the origin's certificate is checked. */
    @Test fun negative_anHttpsRecordTargetMeetsTheOriginsPins() =
        clientTest {
            val (server, port) = server()
            try {
                val name = "_$port._https.server.test"
                val record =
                    io.kuicksilver.ktor.client.dns.SvcbRecord(
                        1,
                        "svc.wild.test",
                        listOf("h2"),
                        false,
                        port,
                        emptyList(),
                        emptyList(),
                        300,
                        name,
                    )
                for (originPinned in listOf(true, false)) {
                    client(Http3Discovery.Auto) {
                        network { httpsRecords = HttpsRecordsForTest { if (it == name) listOf(record) else emptyList() } }
                        tls {
                            pins {
                                add("server.test", if (originPinned) leaf else wrong)
                                add("svc.wild.test", if (originPinned) wrong else leaf)
                            }
                        }
                    }.use { c ->
                        if (originPinned) {
                            assertTrue(c.get("https://server.test:$port/").bodyAsText().startsWith("server.test|"))
                        } else {
                            assertEquals(
                                "server.test",
                                pinMismatch(assertFailsWith<Throwable> { c.get("https://server.test:$port/") }).host,
                            )
                        }
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * Session resumption is no way around the pins: a host that passed under `AnyInValidatedChain` with its CA's pin, then
     * meets `Leaf` (the same pins, the scope changed on the live configuration), fails on its next connection; the session
     * cache keys a ticket by the trust, pins and scope included, so the old ticket resumes nothing. The control: without the
     * change the next connection passes.
     */
    @Test fun negative_aResumedConnectionIsHeldToThePins() =
        clientTest {
            val (server, port) = server()
            try {
                for (change in listOf(false, true)) {
                    client {
                        http2 { enabled = false }
                        tls {
                            pins {
                                add("server.test", ca)
                                scope = PinScope.AnyInValidatedChain
                            }
                        }
                    }.use { c ->
                        // Connection: close, so the next request makes a new connection, which offers the session's ticket
                        c.get("https://server.test:$port/") { headers.append("Connection", "close") }.bodyAsText()
                        if (change) (c.engine.config as KuicksilverEngineConfig).tls.pins.scope = PinScope.Leaf
                        val second = runCatching { c.get("https://server.test:$port/").bodyAsText() }
                        if (change) {
                            assertEquals(listOf(leaf, ca), pinMismatch(second.exceptionOrNull()!!).chainPins)
                        } else {
                            assertTrue(second.getOrThrow().startsWith("server.test|"))
                        }
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** 0-RTT likewise: an HTTP/3 ticket earned under one pin policy is not used to send early data under another. */
    @Test fun negative_zeroRttIsHeldToThePins() =
        h3Test {
            val (server, port) =
                testServer(configure = {
                    http2 { enabled = false }
                    http3 { earlyData { enabled = true } }
                }) { routing { get("/") { call.respondText("${call.request.host()}|${call.request.local.version}") } } }
            try {
                client(Http3Discovery.H3Only) {
                    http3 { earlyData { enabled = true } }
                    tls {
                        pins {
                            add("server.test", ca)
                            scope = PinScope.AnyInValidatedChain
                        }
                    }
                }.use { c ->
                    assertEquals(HttpProtocolVersion.HTTP_3_0, c.get("https://server.test:$port/").version)
                    c.closeHttp3Connections()
                    (c.engine.config as KuicksilverEngineConfig).tls.pins.scope = PinScope.Leaf
                    val e = assertFailsWith<Throwable> { c.get("https://server.test:$port/").bodyAsText() }
                    assertEquals("server.test", pinMismatch(e).host)
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
