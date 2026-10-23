// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.engine.ProxyConfig
import io.ktor.client.request.get
import io.ktor.http.Url
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Off the JVM a `ProxyConfig` is a URL: its scheme and user info. */
class ProxyConfigNativeTest {
    /** TLS to the proxy itself is not supported: refused, never a CONNECT in clear to what expects TLS. */
    @Test fun negative_httpsProxyUrlRefused() =
        clientTest {
            testClient(engine = { proxy = ProxyConfig(Url("https://127.0.0.1:1")) }).use { c ->
                val e = assertFailsWith<UnsupportedOperationException> { c.get("https://127.0.0.1:2/") }
                assertTrue("https://" in e.message!!, e.message)
            }
        }

    @Test fun userInfoBecomesCredentials() {
        val p = ProxyConfig(Url("http://al%40ice:p%3Ass@proxy.test:3128")).toResolvedProxy(ProxyCredentials("other", "x"))!!
        assertEquals(ProxyCredentials("al@ice", "p:ss"), p.credentials)
        assertEquals("proxy.test", p.host)
        assertEquals(3128, p.port)
        assertEquals("http://proxy.test:3128", p.toString(), "the credentials stay out of its text")
        val none = ProxyConfig(Url("http://proxy.test:3128")).toResolvedProxy(ProxyCredentials("other", "x"))!!
        assertEquals(ProxyCredentials("other", "x"), none.credentials)
    }
}
