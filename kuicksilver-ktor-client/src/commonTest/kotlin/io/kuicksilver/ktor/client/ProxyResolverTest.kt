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
        assertTrue(no.matches("example.com"))
        assertTrue(no.matches("a.example.com"))
        assertFalse(no.matches("badexample.com"))
        assertTrue(no.matches("x.other.test"))
        assertTrue(no.matches("other.test"))
        assertTrue(no.matches("A.EXAMPLE.COM."), "case and a trailing dot")
        val r = env("https_proxy" to "http://p.test:3128", "no_proxy" to "example.com")
        assertNull(r.at("https://a.example.com/"))
        assertEquals(ResolvedProxy.http("p.test", 3128), r.at("https://badexample.com/"))
    }

    @Test fun noProxyStarAndCidr() {
        assertTrue(NoProxy.parse("*").matches("anything.test"))
        val no = NoProxy.parse("10.0.0.0/8 192.168.1.7 [2001:db8::]/32")
        assertTrue(no.matches("10.1.2.3"))
        assertFalse(no.matches("11.1.2.3"))
        assertTrue(no.matches("192.168.1.7"))
        assertFalse(no.matches("192.168.1.8"))
        assertTrue(no.matches("[2001:db8::5]"))
        assertFalse(no.matches("2001:db9::5"))
        assertNull(env("http_proxy" to "p.test:1", "NO_PROXY" to "*").at("http://x.test/"))
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
