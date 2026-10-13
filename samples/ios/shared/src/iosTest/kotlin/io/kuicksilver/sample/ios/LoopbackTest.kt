// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.ios

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals

/** The sample's operations against its own server over loopback, in the simulator (no UI, no main-thread callbacks). */
class LoopbackTest {
    @Test fun echoAndHttp3AgainstTheInAppServer() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val server = SampleServer.start(0, scope) { println(it) }
        try {
            val echo = quicEcho("::1", server.port, "ping", rounds = 3, intervalMs = 0, mode = TrustMode.SAMPLE_CA, tofu = MemoryTofuStore(), log = { println(it) })
            assertEquals(3, echo.rounds)
            val page = http3Get("https://127.0.0.1:${server.port}/hello", TrustMode.SAMPLE_CA, MemoryTofuStore())
            assertEquals(200, page.status)
            assertContains(page.bodyPreview, "Hello over HTTP/3")
            val tofu = http3Get("https://localhost:${server.port}/", TrustMode.TOFU, MemoryTofuStore())
            assertEquals(200, tofu.status)
        } finally {
            server.close(); scope.cancel()
        }
    }

    @Test fun parsesUrls() {
        assertEquals(ParsedUrl("example.com", 443, "/"), parseHttpsUrl("https://example.com"))
        assertEquals(ParsedUrl("::1", 4433, "/x?y"), parseHttpsUrl("https://[::1]:4433/x?y"))
        assertEquals("[::1]:4433", parseHttpsUrl("https://[::1]:4433/").authority)
    }
}
