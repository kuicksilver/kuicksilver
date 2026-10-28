// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.Url
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The built-in proxy resolvers' parsing (environment, Windows strings, CFNetwork answers) and the engine's use of them. */
class ProxyResolverTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun env(vararg kv: Pair<String, String>) = environmentResolver(mapOf(*kv))

    private fun ProxyResolver.at(url: String): ResolvedProxy? = runBlocking { proxyFor(Url(url)) }

    @Test fun noProxyMatchesOnDomainBoundary() {
        val no = NoProxy.parse("example.com, .other.test")
        assertTrue(no.matches("example.com", 443))
        assertTrue(no.matches("a.example.com", 443))
        assertFalse(no.matches("badexample.com", 443))
        assertTrue(no.matches("x.other.test", 443))
        assertTrue(no.matches("other.test", 443))
        assertTrue(no.matches("A.EXAMPLE.COM.", 443), "case and a trailing dot")
        val r = env("https_proxy" to "http://p.test:3128", "no_proxy" to "example.com")
        assertNull(r.at("https://a.example.com/"))
        assertEquals(ResolvedProxy.http("p.test", 3128), r.at("https://badexample.com/"))
    }

    @Test fun noProxyStarAndCidr() {
        assertTrue(NoProxy.parse("*").matches("anything.test", 443))
        val no = NoProxy.parse("10.0.0.0/8 192.168.1.7 [2001:db8::]/32")
        assertTrue(no.matches("10.1.2.3", 443))
        assertFalse(no.matches("11.1.2.3", 443))
        assertTrue(no.matches("192.168.1.7", 443))
        assertFalse(no.matches("192.168.1.8", 443))
        assertTrue(no.matches("[2001:db8::5]", 443))
        assertFalse(no.matches("2001:db9::5", 443))
        assertNull(env("http_proxy" to "p.test:1", "NO_PROXY" to "*").at("http://x.test/"))
    }

    /** An entry with a port exempts that port only (as Go); `[v6]:port` keeps the address whole. */
    @Test fun noProxyPortRestricted() {
        val no = NoProxy.parse("example.com:8080, 10.0.0.1:443, [2001:db8::1]:443, [2001:db8::2], 2001:db8::3")
        assertTrue(no.matches("a.example.com", 8080))
        assertFalse(no.matches("a.example.com", 443))
        assertTrue(no.matches("10.0.0.1", 443))
        assertFalse(no.matches("10.0.0.1", 80))
        assertTrue(no.matches("[2001:db8::1]", 443))
        assertFalse(no.matches("[2001:db8::1]", 80))
        assertTrue(no.matches("2001:db8::2", 80), "brackets without a port: every port")
        assertTrue(no.matches("2001:db8::3", 80), "a bare IPv6 address has no port")
        val r = env("https_proxy" to "http://p.test:1", "no_proxy" to "example.com:8443")
        assertNull(r.at("https://example.com:8443/"))
        assertEquals(ResolvedProxy.http("p.test", 1), r.at("https://example.com/"))
    }

    /** `HTTP_PROXY` can come from a request's `Proxy:` header in CGI ("httpoxy"): only the lower-case name counts. */
    @Test fun uppercaseHttpProxyIgnored() {
        assertNull(env("HTTP_PROXY" to "http://evil.test:80").at("http://x.test/"))
        assertEquals(ResolvedProxy.http("p.test", 8080), env("http_proxy" to "http://p.test:8080").at("http://x.test/"))
        assertEquals(ResolvedProxy.http("s.test", 3128), env("HTTPS_PROXY" to "s.test:3128").at("https://x.test/"))
    }

    @Test fun httpsProxyUsedForWss() {
        val r = env("https_proxy" to "http://s.test:1", "http_proxy" to "http://h.test:2", "ALL_PROXY" to "socks5h://a.test:3")
        assertEquals(ResolvedProxy.http("s.test", 1), r.at("wss://x.test/ws"))
        assertEquals(ResolvedProxy.http("h.test", 2), r.at("ws://x.test/ws"))
        assertEquals(ResolvedProxy.socks5("a.test", 3), env("ALL_PROXY" to "socks5h://a.test:3").at("https://x.test/"))
    }

    @Test fun socks5hKeepsRemoteDns() {
        assertTrue(env("all_proxy" to "socks5h://p.test:1080").at("https://x.test/")!!.remoteDns)
        val local = env("all_proxy" to "socks5://p.test").at("https://x.test/")!!
        assertFalse(local.remoteDns)
        assertEquals(1080, local.port, "curl's default proxy port")
    }

    @Test fun userinfoDecodedToCredentials() {
        val p = env("https_proxy" to "http://al%40ice:p%3As@p.test:3128/").at("https://x.test/")!!
        assertEquals(ProxyCredentials("al@ice", "p:s"), p.credentials)
        assertEquals("http://p.test:3128", p.toString(), "the credentials stay out of its text")
    }

    /**
     * A `socks5://` URL whose user info has no password (or an empty one) cannot authenticate: RFC 1929 section 2 gives
     * PASSWD 1 to 255 octets. The lookup fails, so the request fails rather than going direct; an HTTP proxy URL keeps
     * its empty password (Basic).
     */
    @Test fun negative_socks5UrlWithAnEmptyPasswordFails() {
        for (url in listOf("socks5://u@p.test:1080", "socks5h://u:@p.test:1080")) {
            val e = assertFailsWith<IllegalArgumentException>(url) { env("all_proxy" to url).at("https://x.test/") }
            assertFalse(e.message!!.contains("p.test"), "the message stays free of the URL: ${e.message}")
        }
        assertEquals(ProxyCredentials("u", ""), env("https_proxy" to "http://u@p.test:3128").at("https://x.test/")!!.credentials)
    }

    @Test fun loopbackAlwaysDirect() {
        val r = env("https_proxy" to "http://p.test:1", "http_proxy" to "http://p.test:1")
        for (u in listOf(
            "https://localhost/",
            "https://a.localhost/",
            "https://127.0.0.1/",
            "https://127.9.9.9/",
            "https://[::1]/",
            "http://[::ffff:127.0.0.1]/",
        )) {
            assertNull(r.at(u), u)
        }
        assertEquals(ResolvedProxy.http("p.test", 1), r.at("https://128.0.0.1/"))
    }

    @Test fun ipLiterals() {
        assertContentEquals(byteArrayOf(10, 0, 0, 1), parseIpLiteral("10.0.0.1"))
        assertContentEquals(ByteArray(16).also { it[15] = 1 }, parseIpLiteral("[::1]"))
        assertContentEquals(
            byteArrayOf(0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4),
            parseIpLiteral("2001:db8::102:304"),
        )
        assertContentEquals(parseIpLiteral("::ffff:1.2.3.4"), parseIpLiteral("::ffff:102:304"))
        for (bad in listOf(
            "1.2.3",
            "256.0.0.1",
            "1::2::3",
            "12345::",
            "a.b.c.d",
            "1:2:3:4:5:6:7:8:9",
            "x.test",
        )) {
            assertNull(parseIpLiteral(bad), bad)
        }
    }

    @Test fun wininetProxyStringParsed() {
        val list = "http=a:1;https=b:2;socks=c:3"
        assertEquals(ResolvedProxy.http("b", 2), parseWinInetProxy(list, null, Url("https://x.test/")))
        assertEquals(ResolvedProxy.http("a", 1), parseWinInetProxy(list, null, Url("http://x.test/")))
        assertEquals(ResolvedProxy.socks5("c", 3), parseWinInetProxy("socks=c:3", null, Url("https://x.test/")))
        assertEquals(ResolvedProxy.http("p", 8080), parseWinInetProxy("p:8080", null, Url("https://x.test/")))
        assertNull(parseWinInetProxy("p:8080", "<local>", Url("https://intranet/")))
        assertEquals(ResolvedProxy.http("p", 8080), parseWinInetProxy("p:8080", "<local>", Url("https://a.b/")))
        assertNull(parseWinInetProxy("p:8080", "*.corp.test;10.*", Url("https://x.corp.test/")))
        assertNull(parseWinInetProxy("p:8080", "*.corp.test;10.*", Url("https://10.1.2.3/")))
        assertNull(parseWinInetProxy(null, null, Url("https://x.test/")))
    }

    @Test fun negative_wininetHttpsProxyRefused() {
        val e = assertFailsWith<UnsupportedOperationException> { parseWinInetProxy("https=https://p:443", null, Url("https://x.test/")) }
        assertTrue("TLS to the proxy" in e.message!!, e.message)
        assertFailsWith<UnsupportedOperationException> { env("https_proxy" to "https://p.test:443").at("https://x.test/") }
    }

    /** The pool key carries an opaque id per credentials instance, nothing derived from the password. */
    @Test fun routeKeyHoldsNoPasswordHash() {
        val a = ResolvedProxy.http("p.test", 1, ProxyCredentials("u", "secret-1"))
        val b = ResolvedProxy.http("p.test", 1, ProxyCredentials("u", "secret-2"))
        assertEquals(a.hashCode(), b.hashCode(), "the hash does not depend on the password")
        assertTrue(a != b)
        assertFalse("secret".hashCode().toString() in a.routeKey || "secret-1".hashCode().toString() in a.routeKey)
        val same = ProxyCredentials("u", "secret-1")
        assertEquals(ResolvedProxy.http("p.test", 1, same).routeKey, ResolvedProxy.http("p.test", 1, same).routeKey)
        assertTrue(
            a.routeKey != ResolvedProxy.http("p.test", 1, ProxyCredentials("u", "secret-1")).routeKey,
            "another instance, another route",
        )
        val r = env("https_proxy" to "http://u:pw@p.test:3128")
        assertEquals(r.at("https://x.test/")!!.routeKey, r.at("https://y.test/")!!.routeKey, "the same variable, the same route")
        val two = env("https_proxy" to "http://u:a@s.test:1", "http_proxy" to "http://u:b@h.test:2")
        val secure = two.at("https://x.test/")!!.routeKey
        val plain = two.at("http://x.test/")!!.routeKey
        assertEquals(secure, two.at("https://y.test/")!!.routeKey, "alternating variables keep their routes")
        assertEquals(plain, two.at("http://y.test/")!!.routeKey)
    }

    /** A resolver that does not answer fails the request at the connect timeout instead of holding it. */
    @Test fun negative_hungResolverFailsAtConnectTimeout() =
        clientTest {
            val release = kotlinx.coroutines.CompletableDeferred<Unit>()
            try {
                testClient(engine = {
                    connectTimeout = kotlin.time.Duration.parse("300ms")
                    proxyResolver =
                        ProxyResolver {
                            kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) { release.await() }
                            null
                        }
                }).use { c ->
                    val e = assertFailsWith<ProxyException> { c.get("https://hung.test/") }
                    assertTrue("connect timeout" in e.message!!, e.message)
                    assertFailsWith<ProxyException> { c.get("https://hung.test/") } // joins the same lookup, fails again
                }
            } finally {
                release.complete(Unit)
            }
        }

    @Test fun cfAnswerPicked() {
        var warnings = 0
        val pac = listOf(CfProxy(CfProxy.Type.AutoConfiguration, null, null), CfProxy(CfProxy.Type.Http, "p", 1))
        assertNull(pickCfProxy(pac) { warnings++ }, "a PAC entry first: direct")
        assertEquals(1, warnings)
        assertEquals(ResolvedProxy.http("p", 3128), pickCfProxy(listOf(CfProxy(CfProxy.Type.Https, "p", 3128))) {})
        assertEquals(ResolvedProxy.socks5("s", 1080), pickCfProxy(listOf(CfProxy(CfProxy.Type.Socks, "s", null))) {})
        assertNull(pickCfProxy(listOf(CfProxy(CfProxy.Type.None, null, null), CfProxy(CfProxy.Type.Http, "p", 1))) {})
    }

    /** One resolver call per route for 30 s, a new one after; at most 256 routes kept; the PAC warning once per engine. */
    @Test fun routingCachesAndWarnsOnce() =
        runBlocking {
            var now = 0L
            var calls = 0
            val lines = ArrayList<String>()
            val resolver =
                object : WarningProxyResolver {
                    override suspend fun proxyFor(
                        url: Url,
                        warn: (String) -> Unit,
                    ): ResolvedProxy? {
                        calls++
                        warn(PAC_WARNING)
                        return null
                    }
                }
            val logger =
                object : KuicksilverLogger {
                    override fun isEnabled(level: LogLevel) = true

                    override fun log(
                        level: LogLevel,
                        message: String,
                        cause: Throwable?,
                    ) {
                        lines += message
                    }
                }
            val routing = ProxyRouting(KuicksilverEngineConfig().apply { proxyResolver = resolver }, logger) { now }
            repeat(3) { routing.lookup(Url("https://x.test/")) }
            assertEquals(1, calls)
            now += ProxyRouting.TTL_MILLIS
            routing.lookup(Url("https://x.test/"))
            assertEquals(2, calls)
            repeat(300) { routing.lookup(Url("https://h$it.test/")) }
            assertEquals(302, calls)
            routing.lookup(Url("https://h0.test/")) // pushed out by the bound
            assertEquals(303, calls)
            assertEquals(listOf(PAC_WARNING), lines)
        }

    /** A proxy from the environment carries a request (CONNECT to the origin's name). */
    @Test fun environmentResolverDrivesRequests() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("via env") } } }
            try {
                ClientProxyTest().tunnelProxy(port) { proxyPort, head ->
                    testClient(Http3DiscoveryMode.Auto, engine = {
                        proxyResolver = env("https_proxy" to "http://127.0.0.1:$proxyPort", "no_proxy" to "other.test")
                    }).use { c ->
                        assertEquals("via env", c.get("https://server.test:$port/").bodyAsText())
                        assertEquals("CONNECT server.test:$port HTTP/1.1", head().first())
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** A proxy the engine cannot speak fails the request; nothing goes to the origin around it. */
    @Test fun negative_unsupportedProxySchemeFailsClosed() =
        clientTest {
            kotlinx.coroutines.coroutineScope {
                unsupportedSchemeBody(
                    this,
                )
            }
        }

    private suspend fun unsupportedSchemeBody(scope: kotlinx.coroutines.CoroutineScope) {
        val selector = SelectorManager(Dispatchers.Default)
        val origin = aSocket(selector).tcp().bind("127.0.0.1", 0)
        var accepted = 0
        val acceptor = scope.launch { while (true) origin.accept().also { accepted++ }.close() }
        try {
            val port = (origin.localAddress as InetSocketAddress).port
            testClient(
                engine = { proxyResolver = env("https_proxy" to "socks4://127.0.0.1:1", "http_proxy" to "https://127.0.0.1:1") },
            ).use { c ->
                val e = assertFailsWith<UnsupportedOperationException> { c.get("https://origin.test:$port/") }
                assertTrue("socks4" in e.message!!, e.message)
                assertFailsWith<UnsupportedOperationException> { c.get("http://origin.test:$port/") }
            }
            assertEquals(0, accepted, "the origin was contacted around the proxy")
        } finally {
            acceptor.cancel()
            origin.close()
            selector.close()
        }
    }

    /** WebTransport refuses a URL the resolver proxies, as a request would go through the proxy. */
    @Test fun negative_webTransportRefusedThroughResolvedProxy() =
        clientTest {
            testClient(Http3DiscoveryMode.Auto, engine = { proxyResolver = env("https_proxy" to "http://p.test:3128") }).use { c ->
                val e = assertFailsWith<UnsupportedOperationException> { c.webTransport("https://wt.test:4433/") }
                assertTrue("proxy" in e.message!!, e.message)
            }
        }
}
