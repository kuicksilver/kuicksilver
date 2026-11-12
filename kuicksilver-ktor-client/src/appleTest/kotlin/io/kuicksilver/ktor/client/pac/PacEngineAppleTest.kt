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
import io.kuicksilver.ktor.client.ResolvedProxy
import io.kuicksilver.ktor.client.pacTarget
import io.kuicksilver.ktor.client.pickCfProxyWithPac
import io.kuicksilver.ktor.network.bindTcp
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import platform.Foundation.NSTemporaryDirectory
import platform.posix.fclose
import platform.posix.fopen
import platform.posix.fputs
import platform.posix.remove
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** The engine's own PAC engine on Apple platforms: scripts from files and plain-http URLs, the URI the script gets, limits. */
@OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)
class PacEngineAppleTest {
    @BeforeTest fun load() =
        runBlocking {
            KslLoader.ensureLoaded()
            PacScripts.clearForTest()
            PacRunner.resetForTest()
        }

    @AfterTest fun reset() =
        runBlocking {
            PacScripts.nowForTest = null
            PacRunner.resetForTest()
        }

    /** Echoes what the script gets: the URL and host, made a host name. */
    private val echo =
        "function FindProxyForURL(url, host) { return 'PROXY ' + url.replace(/[^a-z0-9]/g, '-') + '.' + host + ':3128; DIRECT'; }"

    /**
     * RFC 6455 section 4.1: "the URI to pass the function MUST be constructed from /host/, /port/, /resource name/, and
     * the /secure/ flag using the definition of a WebSocket URI": the script gets the whole `wss://` URI, its resource
     * name and query included (CFNetwork's own engine dropped them).
     */
    @Test fun theScriptGetsTheWholeWebSocketUri() =
        runBlocking {
            val target = pacTarget(Url("wss://h.test:8443/chat?room=1"))
            assertEquals("wss://h.test:8443/chat?room=1", target)
            val answer = evaluatePac(CfProxy(CfProxy.Type.AutoConfiguration, null, null, pacScript = echo), target, "h.test")!!
            assertEquals("wss---h-test-8443-chat-room-1.h.test", answer[0].host)
            assertEquals(3128, answer[0].port)
            assertEquals(CfProxy.Type.None, answer[1].type)
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

    /** A script that cannot be had (404) or runs into an error: no answer, the next entry counts, one warning. */
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

    /** A script larger than the cap is refused. */
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
     * The sandbox: ECMAScript and the PAC functions only; nothing to reach the network, files, timers or modules, and
     * the natives cannot be replaced.
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
        } finally {
            ctx.close()
        }
    }

    /**
     * A script that never returns: no answer once its time is up, its thread is given up to it, and the next script runs
     * on a new thread; after [PacRunner.MAX_ABANDONED] such scripts no script runs any more.
     */
    @Test fun negative_runawayScriptIsAbandoned() =
        runBlocking {
            val loop = "function FindProxyForURL(url, host) { while (true) {} }"
            val ok = "function FindProxyForURL(url, host) { return 'PROXY ok.test:1'; }"
            assertNull(PacRunner.findProxy("loop1", loop, "https://x.test:443/", "x.test", 200))
            assertEquals(1, PacRunner.abandonedThreads)
            assertEquals("PROXY ok.test:1", PacRunner.findProxy("ok", ok, "https://x.test:443/", "x.test", 2_000))
            assertNull(PacRunner.findProxy("loop2", loop, "https://x.test:443/", "x.test", 200))
            assertEquals(PacRunner.MAX_ABANDONED, PacRunner.abandonedThreads)
            assertNull(PacRunner.findProxy("ok", ok, "https://x.test:443/", "x.test", 2_000), "no script runs any more")
        }

    @Test fun answersAreParsed() {
        val list =
            parsePacResult(
                "PROXY a.test:8080; SOCKS b.test:1081;SOCKS5 [2001:db8::1]:1082; HTTPS c.test:443; SOCKS4 d:1; DIRECT; HTTP e.test",
            )
        assertEquals(
            listOf(CfProxy.Type.Http, CfProxy.Type.Socks, CfProxy.Type.Socks, CfProxy.Type.None, CfProxy.Type.Http),
            list.map { it.type },
        )
        assertEquals(listOf("a.test", "b.test", "2001:db8::1", null, "e.test"), list.map { it.host })
        assertEquals(listOf(8080, 1081, 1082, null, 80), list.map { it.port })
        assertEquals(emptyList(), parsePacResult("PROXY a.test:99999"))
    }

    @Test fun wpadCandidatesWalkToTwoLabels() {
        assertEquals(
            listOf(
                "http://cfg.test/proxy.pac",
                "http://wpad.a.corp.example.com/wpad.dat",
                "http://wpad.corp.example.com/wpad.dat",
                "http://wpad.example.com/wpad.dat",
            ),
            wpadCandidates("http://cfg.test/proxy.pac\u0000", listOf("a.corp.example.com.", "example.com", "mac.local", "com")),
        )
        assertEquals(emptyList(), wpadCandidates(null, listOf("com", "local")))
    }

    @Test fun scriptsAreKeptUntilTheyExpire() =
        runBlocking {
            var now = 0L
            PacScripts.nowForTest = { now }
            val requests = ArrayList<String>()
            servePac(requests, "200 OK", "function FindProxyForURL() { return 'DIRECT'; }".encodeToByteArray(), connections = 2) { port ->
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
                                output.writeFully(body)
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
