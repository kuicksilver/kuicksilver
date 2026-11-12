// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.ktor.network.bindTcp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** The CFNetwork answer as the Apple `System` resolver reads it; the host's own settings are not involved. */
class SystemProxyAppleTest {
    @Test fun parsesCfProxyDictionary() {
        val k = CfProxyKeys
        val answer =
            listOf(
                mapOf(k.type to k.https, k.host to "proxy.test", k.port to 3128),
                mapOf(k.type to k.none),
            )
        val entries = cfProxiesFrom(answer)
        assertEquals(listOf(CfProxy.Type.Https, CfProxy.Type.None), entries.map { it.type })
        assertEquals(ResolvedProxy.http("proxy.test", 3128), pickCfProxy(entries) {})
        assertEquals(
            ResolvedProxy.socks5("s.test", 1080),
            pickCfProxy(
                cfProxiesFrom(
                    listOf(
                        mapOf(
                            k.type to k.socks,
                            k.host to "s.test",
                            k.port to 1080,
                        ),
                    ),
                ),
            ) {},
        )
        var warned = 0
        assertNull(pickCfProxy(cfProxiesFrom(listOf(mapOf(k.type to k.pac)))) { warned++ })
        assertEquals(1, warned)
    }

    private val script =
        """
        function FindProxyForURL(url, host) {
          if (url.substring(0, 18) == "wss://h.test:8443/" && host == "h.test") return "PROXY p.test:3128; DIRECT";
          if (host == "socks.test") return "SOCKS s.test:1080";
          return "DIRECT";
        }
        """.trimIndent()

    /** CFNetwork's PAC engine runs a script on this thread's run loop; its answer is read as the fixed entries are. */
    @Test fun pacScriptRuns() {
        val answer = runPac(null, script, "wss://h.test:8443/chat?room=1", 5_000)!!
        assertEquals(listOf(CfProxy.Type.Https, CfProxy.Type.None), answer.map { it.type }) // PROXY for a secure target
        assertEquals("p.test", answer[0].host)
        assertEquals(3128, answer[0].port)
        assertEquals(ResolvedProxy.http("p.test", 3128), pickCfProxy(answer) {})
        assertEquals(listOf(CfProxy.Type.None), runPac(null, script, "wss://other.test:8443/chat", 5_000)!!.map { it.type })
        assertEquals(listOf(CfProxy.Type.Socks), runPac(null, script, "https://socks.test:443/", 5_000)!!.map { it.type })
    }

    /**
     * What the script gets: the WebSocket URI we pass (RFC 6455 section 4.1) keeps its scheme, host and port, but
     * CFNetwork drops the resource name (and any path and query) before the script runs, for every scheme. Pinned here so
     * a change of the platform shows (docs/spec/rfc/6455.md, "connecting, through a proxy").
     */
    @Test fun cfNetworkGivesTheScriptNoResourceName() {
        val echo = "function FindProxyForURL(url, host) { return \"PROXY \" + url.replace(/[^a-z0-9]/g, \"-\") + \".x:1\"; }"
        assertEquals("wss---h-test-8443-.x", runPac(null, echo, "wss://h.test:8443/chat?room=1", 5_000)?.single()?.host)
        assertEquals("http---h-test-8080-.x", runPac(null, echo, "http://h.test:8080/a?b=1", 5_000)?.single()?.host)
    }

    /** A PAC URL that cannot be fetched: no answer, so the next setting or a direct connection is used. */
    @Test fun negative_pacUrlThatFailsGivesNoAnswer() {
        assertNull(runPac("data:application/x-ns-proxy-autoconfig,x", null, "https://x.test:443/", 5_000))
    }

    /** A PAC URL that never answers: no answer within the bound. */
    @Test fun negative_pacUrlThatHangsTimesOut() =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            val listener = bindTcp(selector, "127.0.0.1", 0)
            val accepted = launch { listener.accept() } // accepts, never answers
            try {
                val port = (listener.localAddress as InetSocketAddress).port
                val answer = withContext(Dispatchers.IO) { runPac("http://127.0.0.1:$port/proxy.pac", null, "https://x.test:443/", 300) }
                assertNull(answer)
            } finally {
                accepted.cancel()
                listener.close()
                selector.close()
            }
        }

    /** The real system call runs (whatever this host's settings) and gives a list. */
    @Test fun systemProxiesCallRuns() {
        systemProxies("https://example.com/")
    }
}
