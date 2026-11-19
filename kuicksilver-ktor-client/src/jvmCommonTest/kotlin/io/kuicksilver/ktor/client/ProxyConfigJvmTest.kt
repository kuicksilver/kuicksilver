// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.engine.ProxyBuilder
import io.ktor.client.request.get
import io.ktor.http.Url
import java.net.InetSocketAddress
import java.net.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ProxyConfigJvmTest {
    /** `Proxy.NO_PROXY` as the engine's `proxy` means a direct connection, not an unsupported proxy type. */
    @Test fun noProxyIsDirect() = assertNull(Proxy.NO_PROXY.toResolvedProxy(null))

    /**
     * A `java.net.Proxy` has no scheme: Ktor's `ProxyBuilder.http(Url("https://proxy"))` makes `Proxy(HTTP, proxy:443)`, and
     * speaking plain HTTP to it would send the CONNECT, the origin's name and `proxyCredentials` in clear to what was meant
     * as an `https://` proxy (CWE-319). An HTTP proxy on port 443 is refused, with or without credentials, saying what to
     * use instead; the request fails before any connection. Other ports and SOCKS stay as they were.
     */
    @Test fun negative_schemelessHttpProxyOn443IsRefused() =
        clientTest {
            val credentials = ProxyCredentials("alice", "S3cRtQ")
            for (proxy in listOf(
                ProxyBuilder.http(Url("https://127.0.0.1")),
                Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", 443)),
            )) {
                val e = assertFailsWith<UnsupportedOperationException> { proxy.toResolvedProxy(null) }
                assertTrue("ResolvedProxy.https" in e.message!! && "ResolvedProxy.http(" in e.message!!, e.message)
                assertFailsWith<UnsupportedOperationException> { proxy.toResolvedProxy(credentials) }
                testClient(engine = {
                    this.proxy = proxy
                    proxyCredentials = credentials
                }).use { c ->
                    val f = assertFailsWith<UnsupportedOperationException> { c.get("https://server.test:1/") }
                    assertFalse("S3cRtQ" in f.message!!)
                }
            }
            assertEquals(ResolvedProxy.http("127.0.0.1", 3128), ProxyBuilder.http(Url("http://127.0.0.1:3128")).toResolvedProxy(null))
            assertEquals(
                ResolvedProxy.socks5("127.0.0.1", 443),
                Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", 443)).toResolvedProxy(null),
            )
        }
}
