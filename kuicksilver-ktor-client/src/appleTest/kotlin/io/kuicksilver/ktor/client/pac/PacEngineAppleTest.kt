// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.pac

import io.ktor.http.Url
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.client.CfProxy
import io.kuicksilver.ktor.client.PAC_FAILED
import io.kuicksilver.ktor.client.PAC_UNSUPPORTED
import io.kuicksilver.ktor.client.PacOutcome
import io.kuicksilver.ktor.client.ProxyException
import io.kuicksilver.ktor.client.ResolvedProxy
import io.kuicksilver.ktor.client.SystemProxySettings
import io.kuicksilver.ktor.client.applePacTarget
import io.kuicksilver.ktor.client.pickCfProxyWithPac
import io.kuicksilver.ktor.network.bindTcp
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import platform.Foundation.NSTemporaryDirectory
import platform.posix.fclose
import platform.posix.fopen
import platform.posix.fputs
import platform.posix.remove
import kotlin.concurrent.AtomicInt
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/** The engine's own PAC engine on Apple platforms: scripts from files and plain-http URLs, the URI the script gets, limits. */
@OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)
class PacEngineAppleTest {
    /** What the scripts' native calls get: blocking ones wait for [release]. */
    private class FakeHost : PacHost {
        val release = CompletableDeferred<Unit>()
        val entered = CompletableDeferred<Unit>()
        val resolveCalls = AtomicInt(0)

        override fun resolve(
            name: String,
            ipv4Only: Boolean,
        ): List<String> {
            resolveCalls.incrementAndGet()
            return when (name) {
                "slow.test" -> {
                    runBlocking { release.await() }
                    listOf("10.0.0.9")
                }

                else -> {
                    listOf("10.0.0.1")
                }
            }
        }

        /**
         * A script calling `myIpAddress()` blocks until [release]: a run that overruns, and ends when released.
         * `myIpAddressEx()` never blocks: it gives nothing until [release], so a script looping on it spins in JavaScript.
         */
        override fun myAddresses(ipv4Only: Boolean): List<String> {
            entered.complete(Unit)
            if (!ipv4Only) return if (release.isCompleted) listOf("192.168.1.2") else emptyList()
            runBlocking { release.await() }
            return listOf("192.168.1.2")
        }
    }

    private val host = FakeHost()

    @BeforeTest fun load() =
        runBlocking {
            KslLoader.ensureLoaded()
            PacScripts.clearForTest()
            PacHost.setForTest(host)
        }

    @AfterTest fun reset() =
        runBlocking {
            host.release.complete(Unit) // no thread is left blocked
            withTimeout(10.seconds) { PacRunner.awaitNoneAbandoned() }
            PacHost.setForTest(null)
            PacScripts.nowForTest = null
            PacRunner.nowForTest = null
        }

    /** Echoes what the script gets: the URL and host, made a host name. */
    private val echo =
        "function FindProxyForURL(url, host) { return 'PROXY ' + url.replace(/[^a-z0-9]/g, '-') + '.' + host + ':3128; DIRECT'; }"

    private val blocking = "function FindProxyForURL(url, host) { myIpAddress(); return 'DIRECT'; }"
    private val ok = "function FindProxyForURL(url, host) { return 'PROXY ok.test:1'; }"

    /**
     * The script of a PAC entry gets the origin of a `wss` URL (CVE-2016-3763, CVE-2016-5134; Chromium sends the same),
     * and the whole URI (RFC 6455 section 4.1) only with the opt-in and only when the entry is the PAC the settings
     * name; a script WPAD found never does. Before, every script got the whole `wss://` URI.
     */
    @Test fun negative_wssScriptsGetTheOriginUnlessTheSettingsNameThemAndTheAppOptsIn() =
        runBlocking {
            val url = Url("wss://h.test:8443/chat?token=secret")
            val inline = CfProxy(CfProxy.Type.AutoConfiguration, null, null, pacScript = echo)
            val byUrl = CfProxy(CfProxy.Type.AutoConfiguration, null, null, pacUrl = "http://cfg.test/proxy.pac")
            val wpad = CfProxy(CfProxy.Type.AutoConfiguration, null, null, wpad = true)
            val named = SystemProxySettings(false, emptyList(), pacEnabled = true, pacUrl = "http://cfg.test/proxy.pac", pacScript = echo)
            assertEquals("wss://h.test:8443/", applePacTarget(url, inline, named, fullWebSocketUrl = false))
            assertEquals("wss://h.test:8443/chat?token=secret", applePacTarget(url, inline, named, fullWebSocketUrl = true))
            assertEquals("wss://h.test:8443/chat?token=secret", applePacTarget(url, byUrl, named, fullWebSocketUrl = true))
            assertEquals("wss://h.test:8443/", applePacTarget(url, wpad, named, fullWebSocketUrl = true))
            val other = SystemProxySettings(true, emptyList(), pacEnabled = true, pacUrl = "http://other.test/p.pac")
            assertEquals("wss://h.test:8443/", applePacTarget(url, byUrl, other, fullWebSocketUrl = true))
            val off = SystemProxySettings(true, emptyList(), pacEnabled = false, pacUrl = "http://cfg.test/proxy.pac")
            assertEquals("wss://h.test:8443/", applePacTarget(url, byUrl, off, fullWebSocketUrl = true))
            assertEquals("https://h.test:8443/", applePacTarget(Url("https://h.test:8443/a?b"), byUrl, named, fullWebSocketUrl = true))
            // what the script itself sees, end to end
            val answer =
                assertIs<PacOutcome.Answer>(
                    evaluatePac(inline, applePacTarget(url, inline, named, fullWebSocketUrl = false), "h.test"),
                )
            assertEquals("wss---h-test-8443-.h.test", answer.proxies[0].host)
            val whole =
                assertIs<PacOutcome.Answer>(
                    evaluatePac(inline, applePacTarget(url, inline, named, fullWebSocketUrl = true), "h.test"),
                )
            assertEquals("wss---h-test-8443-chat-token-secret.h.test", whole.proxies[0].host)
        }

    @Test fun pacFileIsReadAndRun() =
        runBlocking {
            val path = NSTemporaryDirectory() + "kuicksilver-test-${kotlin.random.Random.nextInt(1 shl 30)}.pac"
            val f = fopen(path, "w")!!
            fputs("function FindProxyForURL(url, host) { return host == 'in.test' ? 'PROXY p.test:8080' : 'DIRECT'; }", f)
            fclose(f)
            try {
                val entry = CfProxy(CfProxy.Type.AutoConfiguration, null, null, pacUrl = "file://$path")
                assertEquals(
                    ResolvedProxy.http("p.test", 8080),
                    pickCfProxyWithPac(listOf(entry), { evaluatePac(it, "https://in.test:443/", "in.test") }) {},
                )
                assertNull(pickCfProxyWithPac(listOf(entry), { evaluatePac(it, "https://out.test:443/", "out.test") }) {})
                assertEquals(1, PacScripts.downloads, "the script is kept")
            } finally {
                remove(path)
            }
        }

    /** A plain `http://` PAC URL is fetched over plain HTTP by the engine (CFNetwork's engine went over TLS). */
    @Test fun plainHttpPacUrlIsFetchedAndRun() =
        runBlocking {
            val body = "function FindProxyForURL(url, host) { return 'SOCKS5 s.test:1080'; }".encodeToByteArray()
            val requests = ArrayList<String>()
            servePac(requests, "200 OK", body) { port ->
                val entry = CfProxy(CfProxy.Type.AutoConfiguration, null, null, pacUrl = "http://127.0.0.1:$port/proxy.pac")
                assertEquals(
                    ResolvedProxy.socks5("s.test", 1080),
                    pickCfProxyWithPac(listOf(entry), { evaluatePac(it, "https://x.test:443/", "x.test") }) {},
                )
            }
            assertEquals(listOf("GET /proxy.pac HTTP/1.1"), requests)
        }

    /** A script that cannot be had (404) or runs into an error: no answer, the next entry counts, one warning each. */
    @Test fun negative_failedScriptFallsToTheNextEntry() =
        runBlocking {
            servePac(ArrayList(), "404 Not Found", ByteArray(0)) { port ->
                val warnings = ArrayList<String>()
                val missing = CfProxy(CfProxy.Type.AutoConfiguration, null, null, pacUrl = "http://127.0.0.1:$port/proxy.pac")
                val broken = CfProxy(CfProxy.Type.AutoConfiguration, null, null, pacScript = "function FindProxyForURL( {")
                val fixed = CfProxy(CfProxy.Type.Http, "next.test", 3128)
                assertEquals(
                    ResolvedProxy.http("next.test", 3128),
                    pickCfProxyWithPac(listOf(missing, broken, fixed), { evaluatePac(it, "https://x.test:443/", "x.test") }) {
                        warnings += it
                    },
                )
                assertEquals(listOf(PAC_FAILED, PAC_FAILED), warnings)
            }
        }

    /** An answer with only proxies the engine cannot use fails closed: never a direct connection. */
    @Test fun negative_unsupportedOnlyAnswerFailsClosed() =
        runBlocking {
            val entry =
                CfProxy(
                    CfProxy.Type.AutoConfiguration,
                    null,
                    null,
                    pacScript = "function FindProxyForURL(url, host) { return 'HTTPS tls.test:443; SOCKS4 s4.test:1080'; }",
                )
            val warnings = ArrayList<String>()
            assertFailsWith<ProxyException> {
                pickCfProxyWithPac(listOf(entry), { evaluatePac(it, "https://x.test:443/", "x.test") }) { warnings += it }
            }
            assertEquals(listOf(PAC_UNSUPPORTED), warnings)
        }

    /** A Content-Length above the cap is refused before the body is read. */
    @Test fun negative_oversizedScriptIsRefused() =
        runBlocking {
            val big =
                (
                    "// " +
                        "x".repeat(
                            PAC_MAX_SCRIPT_BYTES,
                        ) + "\nfunction FindProxyForURL() { return 'PROXY p:1'; }"
                ).encodeToByteArray()
            servePac(ArrayList(), "200 OK", big) { port ->
                assertNull(PacScripts.script("http://127.0.0.1:$port/big.pac", 5_000))
            }
        }

    /**
     * A body without a length that never ends: the download stops at the cap instead of holding the whole body (before,
     * the body was read whole and only then measured), and fails quickly.
     */
    @Test fun negative_endlessScriptStopsAtTheCap() =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            val listener = bindTcp(selector, "127.0.0.1", 0)
            val sent = AtomicInt(0)
            try {
                coroutineScope {
                    val server =
                        launch {
                            listener.accept().use { s ->
                                val input = s.openReadChannel()
                                while (input.readLine(LineEnding.Lenient)?.isNotEmpty() == true) continue
                                val output = s.openWriteChannel(autoFlush = false)
                                output.writeStringUtf8("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                                val chunk = ByteArray(64 * 1024) { 'x'.code.toByte() }
                                runCatching {
                                    while (true) {
                                        output.writeFully(chunk)
                                        output.flush()
                                        sent.addAndGet(chunk.size)
                                    }
                                }
                            }
                        }
                    val mark = TimeSource.Monotonic.markNow()
                    assertNull(
                        PacScripts.script("http://127.0.0.1:${(listener.localAddress as InetSocketAddress).port}/endless.pac", 5_000),
                    )
                    assertTrue(mark.elapsedNow() < 4.seconds, "took ${mark.elapsedNow()}")
                    server.cancel()
                }
            } finally {
                listener.close()
                selector.close()
            }
            assertTrue(sent.value < 64 * PAC_MAX_SCRIPT_BYTES, "${sent.value} bytes sent before the client stopped")
        }

    /**
     * A PAC URL that never answers: no answer within the bound, and that timeout is remembered, so later lookups do not
     * pay the bound again.
     */
    @Test fun negative_pacUrlThatHangsTimesOut() =
        hangingServer { url ->
            assertNull(PacScripts.script(url, 300))
            assertEquals(false, PacScripts.cachedForTest(url), "the timeout is remembered")
            val mark = TimeSource.Monotonic.markNow()
            assertNull(PacScripts.script(url, 5_000))
            assertTrue(mark.elapsedNow() < 1.seconds, "the failure was remembered: ${mark.elapsedNow()}")
            assertEquals(1, PacScripts.downloads)
        }

    /**
     * Two lookups share one download; the first is cancelled (for its own reasons): the second keeps waiting, gets null
     * at its own timeout instead of an exception, and the cancellation records nothing. Before, the first to leave
     * cancelled the shared download, the other lookup failed with the cancellation, and a failure was cached.
     */
    @Test fun negative_aCancelledLookupDoesNotBreakTheOthers() =
        hangingServer { url ->
            coroutineScope {
                val first = async(Dispatchers.Default) { PacScripts.script(url, 2_000) }
                val second = async(Dispatchers.Default) { PacScripts.script(url, 2_000) }
                PacScripts.waitingForTest.first { it == 2 }
                first.cancel()
                first.join()
                assertNull(PacScripts.cachedForTest(url), "a cancelled lookup records nothing")
                assertNull(second.await()) // no exception: its own timeout
                assertEquals(1, PacScripts.downloads)
            }
        }

    /** A server that accepts and never answers, at the URL given to [block]. */
    private fun hangingServer(block: suspend (String) -> Unit) =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            val listener = bindTcp(selector, "127.0.0.1", 0)
            val accepted = launch { while (true) listener.accept() } // accepts, never answers
            try {
                withTimeout(30.seconds) { block("http://127.0.0.1:${(listener.localAddress as InetSocketAddress).port}/proxy.pac") }
            } finally {
                accepted.cancel()
                listener.close()
                selector.close()
            }
        }

    /**
     * A download that throws is a failure like any other: null, no exception, and no download left behind as under way
     * (the failure is cached, so the second lookup does not download again). Before, the exception reached the request
     * and the URL stayed "under way" for good. (A `file:` URL with a malformed escape such as `%zz` does not get there:
     * the URL parser encodes the `%`, so the file is just not found.)
     */
    @Test fun negative_downloadThatThrowsIsAFailure() =
        runBlocking {
            PacScripts.downloadForTest = { throw IllegalStateException("download failed oddly") }
            try {
                assertNull(PacScripts.script("http://throws.test/p.pac", 5_000))
                assertNull(PacScripts.script("http://throws.test/p.pac", 5_000))
                assertNull(PacScripts.script("file:///tmp/a%zz.pac", 5_000))
                assertEquals(2, PacScripts.downloads)
            } finally {
                PacScripts.downloadForTest = null
            }
        }

    /** Lookups of one URL while its download is under way share it: one download. */
    @Test fun downloadsAreSingleFlight() =
        runBlocking {
            val requests = ArrayList<String>()
            servePac(requests, "200 OK", ok.encodeToByteArray()) { port ->
                val url = "http://127.0.0.1:$port/p.pac"
                val scripts = (1..5).map { async { PacScripts.script(url, 5_000) } }.awaitAll()
                assertTrue(scripts.all { it == ok }, "$scripts")
            }
            assertEquals(1, PacScripts.downloads)
            assertEquals(1, requests.size)
        }

    /**
     * The sandbox: ECMAScript and the PAC functions only; nothing to reach the network, files, timers or modules, and
     * the natives cannot be replaced; an overlong argument to a native gives nothing.
     */
    @Test fun negative_theScriptHasNoHostAccess() {
        val ctx = PacContext("function FindProxyForURL(url, host) { return 'DIRECT'; }")
        try {
            for (name in listOf(
                "fetch",
                "XMLHttpRequest",
                "require",
                "process",
                "setTimeout",
                "setInterval",
                "WebSocket",
                "importScripts",
            )) {
                assertEquals("undefined", ctx.typeOf(name), name)
            }
            assertEquals("function", ctx.typeOf("dnsResolve"))
            ctx.eval("dnsResolve = function() { return '6.6.6.6'; }") // read-only: ignored outside strict mode
            assertEquals("function", ctx.typeOf("dnsResolve"))
            val before = host.resolveCalls.value
            assertEquals(null, ctx.eval("dnsResolve(new Array(2000).join('a'))"))
            assertEquals(before, host.resolveCalls.value, "an overlong name never reaches the resolver")
        } finally {
            ctx.close()
        }
    }

    /**
     * A resolver that never answers costs the script its DNS budget, not its run: the lookup gives nothing and the run
     * ends in time, so it is no runaway. Before, `getaddrinfo` held the run past its limit.
     */
    @Test fun negative_slowDnsIsNotARunaway() =
        runBlocking {
            val script =
                "function FindProxyForURL(url, host) { " +
                    "return dnsResolve('slow.test') === null ? 'PROXY nodns.test:1' : 'DIRECT'; }"
            assertEquals("PROXY nodns.test:1", PacRunner.findProxy("slow", script, "https://x.test:443/", "x.test", 2_000))
            assertEquals(0, PacRunner.abandonedThreads.value)
        }

    /**
     * A lookup queued behind a long run: its limit counts from its own start, so it is no runaway however long it waited.
     * Run A holds the thread until released (its limit is far away); B, with a short limit, waits behind it while the
     * test waits a while longer than B's limit (a lower bound only: correct code passes however long that is; before,
     * B's limit counted from its queueing and it was given up). Then A ends and B answers.
     */
    @Test fun negative_queuedRunsAreNotRunaways() =
        runBlocking {
            withTimeout(30.seconds) {
                val a = async(Dispatchers.Default) { PacRunner.findProxy("a", blocking, "https://a.test:443/", "a.test", 60_000) }
                host.entered.await() // A runs
                val b = async(Dispatchers.Default) { PacRunner.findProxy("b", ok, "https://b.test:443/", "b.test", 1_000) }
                PacRunner.queuedForTest.first { it == 1 } // B waits for its turn
                assertNull(withTimeoutOrNull(1_500) { b.await() }, "B cannot answer while A holds the thread")
                host.release.complete(Unit)
                assertEquals("DIRECT", a.await())
                assertEquals("PROXY ok.test:1", b.await())
            }
            assertEquals(0, PacRunner.abandonedThreads.value)
        }

    /**
     * A run that overruns gives no answer and its thread is abandoned; while [PacRunner.MAX_ABANDONED] are, no script
     * runs; once they end, their threads go and scripts run again.
     */
    @Test fun negative_runawayScriptIsAbandonedAndPacRecovers() =
        runBlocking {
            assertNull(PacRunner.findProxy("block1", blocking, "https://x.test:443/", "x.test", 200))
            assertEquals(1, PacRunner.abandonedThreads.value)
            assertEquals("PROXY ok.test:1", PacRunner.findProxy("ok", ok, "https://x.test:443/", "x.test", 2_000))
            assertNull(PacRunner.findProxy("block2", blocking, "https://x.test:443/", "x.test", 200))
            assertEquals(PacRunner.MAX_ABANDONED, PacRunner.abandonedThreads.value)
            assertNull(
                withTimeout(10.seconds) {
                    PacRunner.findProxy("ok", ok, "https://x.test:443/", "x.test", 2_000)
                },
                "no script runs while two hang",
            )
            host.release.complete(Unit)
            withTimeout(10.seconds) { PacRunner.awaitNoneAbandoned() }
            assertEquals("PROXY ok.test:1", PacRunner.findProxy("ok", ok, "https://x.test:443/", "x.test", 2_000))
        }

    /**
     * The caller's own timeout firing first (the lookup's 5 s, say) skips nothing: the next run finds the worker busy past
     * the limit and abandons it, instead of queueing behind it and failing too.
     */
    @Test fun negative_overrunAfterTheCallerGaveUpIsFoundByTheNextRun() =
        runBlocking {
            val base = TimeSource.Monotonic.markNow()
            var offset = 0L
            PacRunner.nowForTest = { base.elapsedNow().inWholeMilliseconds + offset }
            val caller = async(Dispatchers.Default) { PacRunner.findProxy("block", blocking, "https://x.test:443/", "x.test", 1_000) }
            withTimeout(10.seconds) { host.entered.await() } // the run is under way
            caller.cancel() // the caller gives up before the limit: no accounting
            caller.join()
            assertEquals(0, PacRunner.abandonedThreads.value, "not overrun yet when the caller gave up")
            offset += 2_000 // the run is now past its limit
            assertEquals(
                "PROXY ok.test:1",
                withTimeout(10.seconds) { PacRunner.findProxy("ok", ok, "https://x.test:443/", "x.test", 1_000) },
            )
            assertEquals(1, PacRunner.abandonedThreads.value)
        }

    /**
     * A script resolves at most [PAC_MAX_DNS_LOOKUPS] distinct names per run (Chromium's kMaxUniqueResolveDnsPerExec,
     * 20): later new names resolve to nothing without reaching the resolver, names already resolved still answer, and
     * the run goes on. Before, every name reached the resolver, a wider channel out and an oracle of the network.
     */
    @Test fun negative_dnsLookupsAreCappedPerRun() =
        runBlocking {
            val script =
                "function FindProxyForURL(url, host) { var ok = 0; " +
                    "for (var i = 0; i < 1000; i++) { if (dnsResolve('n' + i + '.test') !== null) ok++; } " +
                    "if (isResolvable('n0.test')) ok += 1000; " +
                    "if (dnsResolveEx('ex.test') === '') ok += 10000; " +
                    "return 'PROXY c' + ok + '.test:1'; }"
            val before = host.resolveCalls.value
            assertEquals("PROXY c11020.test:1", PacRunner.findProxy("dns", script, "https://x.test/", "x.test", 2_000))
            assertEquals(PAC_MAX_DNS_LOOKUPS, host.resolveCalls.value - before)
            // the count is per run
            assertEquals("PROXY c11020.test:1", PacRunner.findProxy("dns", script, "https://x.test/", "x.test", 2_000))
            assertEquals(2 * PAC_MAX_DNS_LOOKUPS, host.resolveCalls.value - before)
        }

    /** An answer longer than [PAC_MAX_ANSWER_CHARS] is refused before it is copied out of the script's context. */
    @Test fun negative_hugeAnswerIsRefused() =
        runBlocking {
            fun padded(n: Int) = "function FindProxyForURL(url, host) { return 'DIRECT' + ' '.repeat($n - 6); }"
            assertEquals(
                PAC_MAX_ANSWER_CHARS,
                PacRunner.findProxy("fits", padded(PAC_MAX_ANSWER_CHARS), "https://x.test/", "x.test", 2_000)?.length,
            )
            assertNull(PacRunner.findProxy("over", padded(PAC_MAX_ANSWER_CHARS + 1), "https://x.test/", "x.test", 2_000))
            val huge = "function FindProxyForURL(url, host) { return 'PROXY a.test:1;'.repeat(1000000); }"
            assertNull(PacRunner.findProxy("huge", huge, "https://x.test/", "x.test", 2_000))
            assertEquals("PROXY ok.test:1", PacRunner.findProxy("ok", ok, "https://x.test/", "x.test", 2_000))
        }

    /**
     * Answers that are no PAC string fail the run, as in Chromium (no string; a string that is not ASCII), so the next
     * setting counts; a string whose `toString` throws is no string either.
     */
    @Test fun negative_malformedAnswersFail() =
        runBlocking {
            for (value in listOf(
                "42",
                "null",
                "undefined",
                "{ toString: function() { throw 1; } }",
                "['DIRECT']",
                "'PROXY пример.test:1'",
            )) {
                val script = "function FindProxyForURL(url, host) { return $value; }"
                assertNull(PacRunner.findProxy("bad-$value", script, "https://x.test/", "x.test", 2_000), value)
            }
            val warnings = ArrayList<String>()
            val entry =
                CfProxy(
                    CfProxy.Type.AutoConfiguration,
                    null,
                    null,
                    pacScript = "function FindProxyForURL(url, host) { return 'PROXY a b:1; PROXY ev/il.test:80'; }",
                )
            assertEquals(
                ResolvedProxy.http("next.test", 3128),
                pickCfProxyWithPac(
                    listOf(entry, CfProxy(CfProxy.Type.Http, "next.test", 3128)),
                    { evaluatePac(it, "https://x.test/", "x.test") },
                ) {
                    warnings += it
                },
            )
            assertEquals(listOf(PAC_FAILED), warnings)
        }

    /** Entries of an answer that break the grammar are skipped, the valid ones kept in order (Chromium's ProxyList). */
    @Test fun negative_malformedEntriesAreSkipped() {
        val list =
            parsePacResult(
                "PROXY a b:1; PROXY ev/il.test:80; PROXY us@er.test:1; PROXY :80; PROXY a.test:; DIRECT x; BOGUS b.test:1; " +
                    "PROXY ${"a".repeat(254)}:1; SOCKS [::1:1; PROXY good.test:8080; ; PROXY 2001:db8::1; DIRECT",
            )
        assertEquals(listOf("good.test", "2001:db8::1", null), list.map { it.host })
        assertEquals(listOf(CfProxy.Type.Http, CfProxy.Type.Http, CfProxy.Type.None), list.map { it.type })
    }

    /** Deep recursion ends in JavaScriptCore's stack check: the run fails, nothing is abandoned, and PAC runs on. */
    @Test fun negative_deepRecursionFailsAndPacRecovers() =
        runBlocking {
            val script = "function f(n) { return f(n + 1) + 1; } function FindProxyForURL(url, host) { return 'PROXY a' + f(0) + ':1'; }"
            assertNull(PacRunner.findProxy("deep", script, "https://x.test/", "x.test", 2_000))
            assertEquals(0, PacRunner.abandonedThreads.value)
            assertEquals("PROXY ok.test:1", PacRunner.findProxy("ok", ok, "https://x.test/", "x.test", 2_000))
        }

    /**
     * A string that doubles without end hits JavaScriptCore's string length limit (an out-of-memory error, before the
     * memory is taken: concatenations are ropes): the run fails and PAC runs on. A bomb that really allocates (a
     * growing array) is not bounded by JavaScriptCore's public API: only the run's time limit and the abandoned thread
     * bound it (threat model 3.20.3); it is not run here, as it would take the test host's memory.
     */
    @Test fun negative_stringBombFailsAndPacRecovers() =
        runBlocking {
            val script = "function FindProxyForURL(url, host) { var s = 'x'; while (true) s = s + s; }"
            assertNull(PacRunner.findProxy("bomb", script, "https://x.test/", "x.test", 2_000))
            assertEquals(0, PacRunner.abandonedThreads.value)
            assertEquals("PROXY ok.test:1", PacRunner.findProxy("ok", ok, "https://x.test/", "x.test", 2_000))
        }

    /**
     * A script that loops in JavaScript (no native call blocking it) overruns: no answer, its thread is abandoned, and once
     * the loop ends (here when the host lets it) the thread and its contexts go and PAC runs again.
     */
    @Test fun negative_busyLoopIsAbandonedAndPacRecovers() =
        runBlocking {
            val spin = "function FindProxyForURL(url, host) { while (myIpAddressEx() === '') {} return 'DIRECT'; }"
            assertNull(PacRunner.findProxy("spin", spin, "https://x.test/", "x.test", 200))
            assertEquals(1, PacRunner.abandonedThreads.value)
            assertEquals("PROXY ok.test:1", PacRunner.findProxy("ok", ok, "https://x.test/", "x.test", 2_000))
            host.release.complete(Unit)
            withTimeout(10.seconds) { PacRunner.awaitNoneAbandoned() }
        }

    /** A script given inline in the settings is held to the same size cap as a downloaded one. */
    @Test fun negative_oversizedInlineScriptIsRefused() =
        runBlocking {
            val body = "function FindProxyForURL(url, host) { return 'PROXY big.test:1'; }\n"

            fun script(bytes: Int) = "//" + "x".repeat(bytes - 3 - body.length) + "\n" + body
            val big = CfProxy(CfProxy.Type.AutoConfiguration, null, null, pacScript = script(PAC_MAX_SCRIPT_BYTES + 1))
            assertEquals(PacOutcome.Failed, evaluatePac(big, "https://x.test/", "x.test"))
            val fits = CfProxy(CfProxy.Type.AutoConfiguration, null, null, pacScript = script(PAC_MAX_SCRIPT_BYTES))
            assertEquals(PAC_MAX_SCRIPT_BYTES, fits.pacScript!!.encodeToByteArray().size)
            assertEquals(CfProxy.Type.Http, assertIs<PacOutcome.Answer>(evaluatePac(fits, "https://x.test/", "x.test")).proxies[0].type)
        }

    /** What a script throws is reported in a bounded message: a huge thrown string is not copied out whole. */
    @Test fun negative_hugeThrownValueIsNotCopied() {
        val ctx = PacContext("function FindProxyForURL(url, host) { throw 'e'.repeat(10000000); }")
        try {
            val e = assertFailsWith<PacScriptException> { ctx.findProxy("https://x.test/", "x.test") }
            assertTrue((e.message?.length ?: 0) < 1_000, "${e.message?.length} characters")
        } finally {
            ctx.close()
        }
    }

    @Test fun answersAreParsed() {
        val list =
            parsePacResult(
                "PROXY a.test:8080; SOCKS b.test:1081;SOCKS5 [2001:db8::1]:1082; HTTPS c.test:443; SOCKS4 d:1; DIRECT; HTTP e.test",
            )
        assertEquals(
            listOf(
                CfProxy.Type.Http,
                CfProxy.Type.Socks,
                CfProxy.Type.Socks,
                CfProxy.Type.Unsupported,
                CfProxy.Type.Unsupported,
                CfProxy.Type.None,
                CfProxy.Type.Http,
            ),
            list.map { it.type },
        )
        assertEquals(listOf("a.test", "b.test", "2001:db8::1", "c.test", "d", null, "e.test"), list.map { it.host })
        assertEquals(listOf(8080, 1081, 1082, 443, 1, null, 80), list.map { it.port })
        assertEquals(emptyList(), parsePacResult("PROXY a.test:99999"))
    }

    @Test fun wpadCandidatesAreTheSearchDomainsExactly() {
        assertEquals(
            listOf(
                "http://cfg.test/proxy.pac",
                "http://wpad.a.corp.example.com/wpad.dat",
                "http://wpad.example.com/wpad.dat",
                "http://wpad/wpad.dat",
            ),
            wpadCandidates("http://cfg.test/proxy.pac\u0000", listOf("a.corp.example.com.", "example.com", "mac.local", "com")),
        )
    }

    /** No parent of a search domain is tried: `x.corp.example.co.uk` never leads to `wpad.co.uk` or `wpad.example.co.uk`. */
    @Test fun negative_wpadNeverTriesAPublicSuffix() {
        val candidates = wpadCandidates(null, listOf("x.corp.example.co.uk"))
        assertEquals(listOf("http://wpad.x.corp.example.co.uk/wpad.dat", "http://wpad/wpad.dat"), candidates)
        for (parent in listOf("corp.example.co.uk", "example.co.uk", "co.uk", "uk")) {
            assertTrue(candidates.none { it.contains("//wpad.$parent/") }, parent)
        }
    }

    /** A discovered PAC URL (DHCP option 252) is `http` or `https` only: never a local file or another scheme. */
    @Test fun negative_discoveredUrlIsHttpOnly() =
        runBlocking {
            assertEquals(listOf("http://wpad/wpad.dat"), wpadCandidates("file:///etc/evil.pac", emptyList()))
            assertEquals(listOf("http://wpad/wpad.dat"), wpadCandidates("ftp://x.test/p.pac", emptyList()))
            assertEquals(listOf("https://cfg.test/p.pac", "http://wpad/wpad.dat"), wpadCandidates("https://cfg.test/p.pac", emptyList()))
            assertNull(PacScripts.script("file:///etc/hosts", 1_000, allowFile = false))
            assertEquals(0, PacScripts.downloads)
        }

    @Test fun scriptsAreKeptUntilTheyExpire() =
        runBlocking {
            var now = 0L
            PacScripts.nowForTest = { now }
            servePac(
                ArrayList(),
                "200 OK",
                "function FindProxyForURL() { return 'DIRECT'; }".encodeToByteArray(),
                connections = 2,
            ) { port ->
                val url = "http://127.0.0.1:$port/p.pac"
                PacScripts.script(url, 5_000)
                PacScripts.script(url, 5_000)
                assertEquals(1, PacScripts.downloads)
                now += PacScripts.SCRIPT_TTL_MILLIS
                PacScripts.script(url, 5_000)
                assertEquals(2, PacScripts.downloads)
            }
        }

    /** Serves [body] with [status] to [connections] connections, one request each, recording the request lines. */
    private suspend fun servePac(
        requests: MutableList<String>,
        status: String,
        body: ByteArray,
        connections: Int = 1,
        block: suspend (Int) -> Unit,
    ) {
        val selector = SelectorManager(Dispatchers.IO)
        val listener = bindTcp(selector, "127.0.0.1", 0)
        try {
            coroutineScope {
                val server =
                    launch {
                        repeat(connections) {
                            listener.accept().use { s ->
                                val input = s.openReadChannel()
                                val first = input.readLine(LineEnding.Lenient) ?: return@use
                                requests += first
                                while (input.readLine(LineEnding.Lenient)?.isNotEmpty() == true) continue
                                val output = s.openWriteChannel(autoFlush = true)
                                output.writeStringUtf8("HTTP/1.1 $status\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n")
                                runCatching { output.writeFully(body) }
                                output.flushAndClose()
                            }
                        }
                    }
                block((listener.localAddress as InetSocketAddress).port)
                server.cancel()
            }
        } finally {
            listener.close()
            selector.close()
        }
    }
}
