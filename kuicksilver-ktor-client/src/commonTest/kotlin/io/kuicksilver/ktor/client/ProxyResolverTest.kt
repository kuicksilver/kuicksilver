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
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.Runnable
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The built-in proxy resolvers' parsing (environment, Windows strings, CFNetwork answers) and the engine's use of them. */
@OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
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

    /**
     * RFC 6455 section 4.1 step 3: "If the client is configured to use a proxy ... the client SHOULD connect to that
     * proxy". A PAC entry is run and its answer picked like the fixed entries; a script that fails is skipped with a
     * warning, so the next entry counts (before, every PAC entry meant a direct connection).
     */
    @Test fun pacEntryIsRunAndItsAnswerPicked() {
        val pac = CfProxy(CfProxy.Type.AutoConfiguration, null, null, pacUrl = "http://wpad/wpad.dat")
        val ran = ArrayList<String?>()
        val warnings = ArrayList<String>()
        val viaPac =
            pickCfProxyWithPac(listOf(pac), {
                ran += it.pacUrl
                PacOutcome.Answer(listOf(CfProxy(CfProxy.Type.Http, "pac.test", 3128)))
            }) { warnings += it }
        assertEquals(ResolvedProxy.http("pac.test", 3128), viaPac)
        assertEquals(listOf<String?>("http://wpad/wpad.dat"), ran)
        assertEquals(emptyList(), warnings)
        // "DIRECT"
        assertNull(
            pickCfProxyWithPac(
                listOf(pac, CfProxy(CfProxy.Type.Http, "p", 1)),
                { PacOutcome.Answer(listOf(CfProxy(CfProxy.Type.None, null, null))) },
            ) {},
        )
        // SOCKS from the script
        assertEquals(
            ResolvedProxy.socks5("s.test", 1080),
            pickCfProxyWithPac(listOf(pac), { PacOutcome.Answer(listOf(CfProxy(CfProxy.Type.Socks, "s.test", 1080))) }) {},
        )
    }

    @Test fun negative_failedPacFallsToTheNextEntryWithAWarning() {
        val pac = CfProxy(CfProxy.Type.AutoConfiguration, null, null, pacScript = "x")
        val warnings = ArrayList<String>()
        assertEquals(
            ResolvedProxy.http("next", 8080),
            pickCfProxyWithPac(listOf(pac, CfProxy(CfProxy.Type.Http, "next", 8080)), { PacOutcome.Failed }) { warnings += it },
        )
        assertEquals(listOf(PAC_FAILED), warnings)
        assertNull(pickCfProxyWithPac(listOf(pac), { PacOutcome.Failed }) {}, "nothing after the failed script: direct")
        val noted = ArrayList<String>()
        assertNull(pickCfProxyWithPac(listOf(pac), { PacOutcome.NoWpad }) { noted += it })
        assertEquals(listOf(WPAD_NOT_FOUND), noted)
    }

    /**
     * A script that answers only with proxies the engine cannot use (TLS to the proxy, SOCKS4) asked for a proxy: the
     * next setting is used with a warning, and with none the lookup fails, never a direct connection. Before, such an
     * answer meant a direct connection.
     */
    @Test fun negative_unsupportedOnlyPacAnswerFailsClosed() {
        val pac = CfProxy(CfProxy.Type.AutoConfiguration, null, null, pacScript = "x")
        val only = PacOutcome.Answer(listOf(CfProxy(CfProxy.Type.Unsupported, "tls.test", 443)))
        val warnings = ArrayList<String>()
        assertEquals(
            ResolvedProxy.http("next", 8080),
            pickCfProxyWithPac(listOf(pac, CfProxy(CfProxy.Type.Http, "next", 8080)), { only }) { warnings += it },
        )
        assertEquals(listOf(PAC_UNSUPPORTED), warnings)
        assertFailsWith<ProxyException> { pickCfProxyWithPac(listOf(pac), { only }) {} }
        // a DIRECT the script itself gives as a fallback stays its choice
        assertNull(
            pickCfProxyWithPac(
                listOf(pac),
                { PacOutcome.Answer(listOf(CfProxy(CfProxy.Type.Unsupported, "tls.test", 443), CfProxy(CfProxy.Type.None, null, null))) },
            ) {},
        )
    }

    /** Windows: WPAD and the PAC URL first (WinHTTP's order), the fixed proxy when neither is set or the script failed. */
    @Test fun windowsRunsPacBeforeTheFixedProxy() {
        val url = Url("https://x.test/")
        val both = IeProxySettings(autoDetect = true, autoConfigUrl = "http://cfg/proxy.pac", proxy = "fixed:1", bypass = null)
        val warnings = ArrayList<String>()
        assertEquals(
            ResolvedProxy.http("pac", 3128),
            windowsProxyFor(both, url, { WinPacAnswer.Proxies("pac:3128;other:1", null) }) { warnings += it },
        )
        assertNull(windowsProxyFor(both, url, { WinPacAnswer.Direct }) { warnings += it })
        assertEquals(emptyList(), warnings)
        assertEquals(ResolvedProxy.http("fixed", 1), windowsProxyFor(both, url, { WinPacAnswer.Failed }) { warnings += it })
        assertEquals(listOf(PAC_FAILED), warnings)
        // no WPAD script found is not a script that failed: its own warning
        assertEquals(ResolvedProxy.http("fixed", 1), windowsProxyFor(both, url, { WinPacAnswer.NoWpad }) { warnings += it })
        assertEquals(listOf(PAC_FAILED, WPAD_NOT_FOUND), warnings)
        var ran = false
        val fixedOnly = IeProxySettings(autoDetect = false, autoConfigUrl = null, proxy = "fixed:1", bypass = null)
        assertEquals(
            ResolvedProxy.http("fixed", 1),
            windowsProxyFor(fixedOnly, url, {
                ran = true
                WinPacAnswer.Direct
            }) {},
        )
        assertFalse(ran)
    }

    /**
     * Windows: detection, then the script URL, each call first without the user's credentials and again with them only
     * when the script's server asked (ERROR_WINHTTP_LOGIN_FAILURE). Before, every call sent them to any script server.
     */
    @Test fun windowsPacSendsCredentialsOnlyWhenAsked() {
        val both = IeProxySettings(autoDetect = true, autoConfigUrl = "http://cfg/proxy.pac", proxy = null, bypass = null)
        val calls = ArrayList<String>()
        val answer =
            runWinPac(both, WpadFailures { 0 }) { detect, configUrl, autoLogon ->
                calls += "${if (detect) "wpad" else configUrl} logon=$autoLogon"
                when {
                    detect -> WinPacCall.NoWpad
                    !autoLogon -> WinPacCall.LoginFailure
                    else -> WinPacCall.Answer(WinPacAnswer.Direct)
                }
            }
        assertEquals(WinPacAnswer.Direct, answer)
        assertEquals(listOf("wpad logon=false", "http://cfg/proxy.pac logon=false", "http://cfg/proxy.pac logon=true"), calls)
    }

    /**
     * Windows: a WPAD detection that found no script is remembered for [WPAD_RETRY_MILLIS], so the lookups in that time
     * do not run DHCP and DNS detection again; it is told apart from a script that failed. Before, every lookup the
     * engine's cache missed ran detection again.
     */
    @Test fun windowsRemembersThatWpadFoundNothing() {
        var now = 0L
        val wpad = WpadFailures { now }
        val detectOnly = IeProxySettings(autoDetect = true, autoConfigUrl = null, proxy = "fixed:1", bypass = null)
        var detections = 0
        val run = {
            runWinPac(detectOnly, wpad) { detect, _, _ ->
                if (detect) detections++
                WinPacCall.NoWpad
            }
        }
        assertEquals(WinPacAnswer.NoWpad, run())
        now += WPAD_RETRY_MILLIS - 1
        assertEquals(WinPacAnswer.NoWpad, run())
        assertEquals(1, detections)
        now += 1
        assertEquals(WinPacAnswer.NoWpad, run())
        assertEquals(2, detections)
        // a script detection found that could not be fetched or run is a failure, not "no WPAD", and is not remembered
        val failing = runWinPac(detectOnly, WpadFailures { 0 }) { _, _, _ -> WinPacCall.Failed }
        assertEquals(WinPacAnswer.Failed, failing)
        // with a script URL as well, the URL runs after a detection that found nothing
        val both = IeProxySettings(autoDetect = true, autoConfigUrl = "http://cfg/proxy.pac", proxy = null, bypass = null)
        assertEquals(
            WinPacAnswer.Direct,
            runWinPac(both, wpad) { detect, _, _ -> if (detect) WinPacCall.NoWpad else WinPacCall.Answer(WinPacAnswer.Direct) },
        )
    }

    /**
     * Windows: a lookup waits for WinHTTP's PAC call at most its bound, also when detection or the script's run hang
     * (WinHTTP's own timeouts bound only the download), and while that call still runs no other starts, also when many
     * lookups race: the counts are taken before a call starts. Before, two lookups could both pass the check and each
     * leave a hanging call behind.
     */
    @Test fun negative_windowsPacCallThatHangsIsBounded() =
        runBlocking {
            val bounded = BoundedPac(timeoutMillis = 200)
            val release = CompletableDeferred<Unit>()
            val started = AtomicInt(0)
            val hanging = {
                started.incrementAndFetch()
                runBlocking { release.await() }
                WinPacAnswer.Direct
            }
            withTimeout(10.seconds) {
                val answers = (1..16).map { async(Dispatchers.Default) { bounded.run(hanging) } }.awaitAll()
                assertTrue(answers.all { it == WinPacAnswer.Failed }, "$answers")
                assertTrue(started.load() in 1..BoundedPac.MAX_IN_FLIGHT, "${started.load()} calls started")
                val before = started.load()
                assertEquals(WinPacAnswer.Failed, bounded.run(hanging), "no call while one that overran still runs")
                assertEquals(before, started.load())
                release.complete(Unit)
                // the late calls end on their own, their answers dropped; then calls run again
                bounded.unfinished.first { it == 0 }
                assertEquals(WinPacAnswer.Direct, bounded.run { WinPacAnswer.Direct })
            }
        }

    /**
     * RFC 6455 section 4.1: "For the purpose of proxy autoconfiguration scripts, the URI to pass the function MUST be
     * constructed from /host/, /port/, /resource name/, and the /secure/ flag using the definition of a WebSocket URI".
     */
    @Test fun pacTargetIsTheWebSocketUri() {
        assertEquals("wss://h.test:8443/chat?room=1", pacTarget(Url("wss://h.test:8443/chat?room=1")))
        assertEquals("ws://h.test:80/", pacTarget(Url("ws://h.test")))
        assertEquals("ws://[::1]:8080/a", pacTarget(Url("ws://[::1]:8080/a")))
        assertEquals("https://h.test:443/", pacTarget(Url("https://h.test/a/b?q")))
        assertEquals("http://h.test:8080/", pacTarget(Url("http://h.test:8080/a")))
    }

    /** A WebSocket's resource name is part of the PAC input, so the answer is kept per resource for ws and wss only. */
    @Test fun webSocketAnswersAreKeptPerResource() =
        runBlocking {
            val seen = ArrayList<String>()
            val routing =
                ProxyRouting(
                    KuicksilverEngineConfig().apply {
                        proxyResolver =
                            ProxyResolver {
                                seen += it.toString()
                                null
                            }
                    },
                    NoLog,
                )
            routing.lookup(Url("wss://x.test/a"))
            routing.lookup(Url("wss://x.test/b"))
            routing.lookup(Url("wss://x.test/a"))
            routing.lookup(Url("https://x.test/a"))
            routing.lookup(Url("https://x.test/b"))
            assertEquals(listOf("wss://x.test/a", "wss://x.test/b", "https://x.test/a"), seen)
        }

    private object NoLog : KuicksilverLogger {
        override fun isEnabled(level: LogLevel) = false

        override fun log(
            level: LogLevel,
            message: String,
            cause: Throwable?,
        ) {}
    }

    /** One resolver call per route for 30 s, a new one after; at most 256 routes kept; the PAC warning once per engine. */

    /**
     * Windows' "no WPAD script found" is the common case where automatic detection is on by default: logged once at Info,
     * and it does not use up the one warning a failing script gets.
     */
    @Test fun negative_wpadNotFoundIsInfoNotWarn() =
        runBlocking {
            val lines = ArrayList<Pair<LogLevel, String>>()
            val resolver =
                object : WarningProxyResolver {
                    override suspend fun proxyFor(
                        url: Url,
                        warn: (String) -> Unit,
                    ): ResolvedProxy? {
                        warn(WPAD_NOT_FOUND)
                        if (url.host == "fail.test") warn(PAC_FAILED)
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
                        lines += level to message
                    }
                }
            val routing = ProxyRouting(KuicksilverEngineConfig().apply { proxyResolver = resolver }, logger)
            routing.lookup(Url("https://a.test/"))
            routing.lookup(Url("https://b.test/"))
            routing.lookup(Url("https://fail.test/"))
            assertEquals(listOf(LogLevel.Info to WPAD_NOT_FOUND, LogLevel.Warn to PAC_FAILED), lines)
        }

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

    /**
     * The race 96b7f862 fixed, made deterministic (review 2026-10-28 ci-fixes.md P1): a completed call's entry stays in the
     * in-flight map until its cleanup gets the lock, which the test holds back. A lookup whose cached answer expired in that
     * window must ask the resolver again, not take the completed call's old answer; once the cleanups run, nothing is left.
     */
    @Test fun anExpiredAnswerIsAskedAgainWhileTheOldCallIsStillListed() =
        runBlocking {
            var now = 0L
            var calls = 0
            val resolver = ProxyResolver { _ -> null.also { calls++ } }
            val held = HeldDispatcher()
            val routing = ProxyRouting(KuicksilverEngineConfig().apply { proxyResolver = resolver }, noLog, cleanup = held) { now }
            routing.lookup(Url("https://x.test/"))
            assertEquals(1, routing.inFlightSize(), "the completed call is still listed: its cleanup is held")
            now += ProxyRouting.TTL_MILLIS
            routing.lookup(Url("https://x.test/"))
            assertEquals(2, calls, "the expired answer was not asked for again")
            held.runAll()
            withTimeout(5.seconds) { while (routing.inFlightSize() != 0) yield() }
        }

    /** Two lookups of one route at once make one resolver call and get the same answer (review 2026-10-28 ci-fixes.md P2). */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    @Test
    fun concurrentLookupsShareOneCall() =
        runBlocking {
            val calls = kotlin.concurrent.atomics.AtomicInt(0)
            val started = CompletableDeferred<Unit>()
            val gate = CompletableDeferred<Unit>()
            val answer = ResolvedProxy.http("proxy.test", 3128)
            val resolver =
                ProxyResolver { _ ->
                    calls.addAndFetch(1)
                    started.complete(Unit)
                    gate.await()
                    answer
                }
            val routing = ProxyRouting(KuicksilverEngineConfig().apply { proxyResolver = resolver }, noLog)
            val a = async { routing.lookup(Url("https://x.test/")) }
            withTimeout(5.seconds) { started.await() }
            val b = async { routing.lookup(Url("https://x.test/")) }
            yield()
            gate.complete(Unit)
            assertEquals(answer, a.await())
            assertEquals(answer, b.await())
            assertEquals(1, calls.load(), "the second lookup asked the resolver too")
        }

    private val noLog =
        object : KuicksilverLogger {
            override fun isEnabled(level: LogLevel) = false

            override fun log(
                level: LogLevel,
                message: String,
                cause: Throwable?,
            ) {}
        }

    /** Runs nothing until [runAll]: a dispatcher that holds back what is dispatched to it. */
    private class HeldDispatcher : kotlinx.coroutines.CoroutineDispatcher() {
        private val queue = ArrayList<Runnable>()

        override fun dispatch(
            context: kotlin.coroutines.CoroutineContext,
            block: Runnable,
        ) {
            synchronizedAdd(block)
        }

        private fun synchronizedAdd(block: Runnable) = lock.withLock { queue += block }

        fun runAll() {
            val blocks = lock.withLock { queue.toList().also { queue.clear() } }
            blocks.forEach { it.run() }
        }

        private val lock =
            io.kuicksilver.ktor.client.h1
                .SpinLock()
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
        val selector = SelectorManager(Dispatchers.IO)
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
