// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

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

    /** The real system call runs (whatever this host's settings) and gives a list. */
    @Test fun systemProxiesCallRuns() {
        systemProxies("https://example.com/")
    }
}
