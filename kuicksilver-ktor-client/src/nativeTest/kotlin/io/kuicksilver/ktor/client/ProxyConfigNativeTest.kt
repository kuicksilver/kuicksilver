// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.engine.ProxyConfig
import io.ktor.client.request.get
import io.ktor.http.Url
import io.ktor.network.sockets.openReadChannel
import io.ktor.utils.io.readAvailable
import kotlinx.coroutines.async
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Off the JVM a `ProxyConfig` is a URL: its scheme and user info. */
class ProxyConfigNativeTest {
    /**
     * An `https://` proxy URL is TLS to the proxy (0.3.0; before, refused): never a CONNECT in clear to what expects TLS.
     * Its user info becomes the credentials and its port defaults to 443.
     */
    @Test fun httpsProxyUrlIsTlsToTheProxy() {
        val p = ProxyConfig(Url("https://u:pw@proxy.test")).toResolvedProxy(null)!!
        assertEquals(ResolvedProxy.https("proxy.test", 443, ProxyCredentials("u", "pw")), p)
        assertTrue(p.tls)
        assertEquals("https://proxy.test:443", p.toString())
        assertEquals(false, ProxyConfig(Url("http://proxy.test:3128")).toResolvedProxy(null)!!.tls)
    }

    /**
     * The explicit `https://` proxy through the engine: the first byte it gets is a TLS handshake record (22), never a
     * CONNECT in clear, and a proxy that then closes fails the request with [ProxyTlsException].
     */
    @Test fun negative_httpsProxyUrlNeverSpeaksPlainToTheProxy() =
        clientTest {
            val selector =
                io.ktor.network.selector
                    .SelectorManager(kotlinx.coroutines.Dispatchers.Default)
            val listener =
                io.kuicksilver.ktor.network
                    .bindTcp(selector, "127.0.0.1", 0)
            try {
                kotlinx.coroutines.coroutineScope {
                    val first =
                        async {
                            listener.accept().use { s ->
                                val input = s.openReadChannel()
                                val buf = ByteArray(1)
                                input.readAvailable(buf, 0, 1)
                                buf[0].toInt()
                            }
                        }
                    val proxyPort = (listener.localAddress as io.ktor.network.sockets.InetSocketAddress).port
                    testClient(engine = { proxy = ProxyConfig(Url("https://127.0.0.1:$proxyPort")) }).use { c ->
                        assertFailsWith<ProxyTlsException> { c.get("https://127.0.0.1:2/") }
                    }
                    assertEquals(22, first.await(), "the proxy's first byte is not a TLS handshake record")
                }
            } finally {
                listener.close()
                selector.close()
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
