// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.ProxyBuilder
import io.ktor.http.Url
import io.kuicksilver.http3.UdpProxyTemplate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Credentials sent as HTTP `Basic` (RFC 7617) to an HTTP, HTTPS or CONNECT-UDP proxy. RFC 7617 section 2 binds the
 * sender: "a user-id containing a colon character is invalid" (the proxy splits `user-pass` at the first colon, so
 * `a:b` / `c` would reach it as `a` / `b:c`), and "The user-id and password MUST NOT contain any control characters"
 * (CTL, RFC 5234 appendix B.1: 0x00-0x1F and 0x7F). Such credentials fail at once with IllegalArgumentException where the
 * proxy is configured, before anything is sent. SOCKS5 (RFC 1929) has no such rule: a colon stays valid there.
 */
class ProxyBasicCredentialsTest {
    private val invalid =
        listOf(
            ProxyCredentials("a:b", "s3cr3t"),
            ProxyCredentials(":", "s3cr3t"),
            ProxyCredentials("u\u0000", "s3cr3t"),
            ProxyCredentials("u", "s3cr3t\r\nX-Injected: 1"),
            ProxyCredentials("u\u007f", "s3cr3t"),
            ProxyCredentials("u", "s3cr3t\u0001"),
            ProxyCredentials("u\tv", "s3cr3t"),
        )

    @Test fun negative_colonInUserIdOrControlCharactersAreRefusedForBasic() {
        for (c in invalid) {
            val http = assertFailsWith<IllegalArgumentException>("http $c") { ResolvedProxy.http("proxy.test", 3128, c) }
            assertTrue("RFC 7617" in http.message!!, http.message)
            assertFalse("s3cr3t" in http.message!!, "the password is in the message: ${http.message}")
            assertFailsWith<IllegalArgumentException>("https $c") { ResolvedProxy.https("proxy.test", 3128, c) }
            assertFailsWith<IllegalArgumentException>("connect-udp $c") {
                ConnectUdpProxy(UdpProxyTemplate.wellKnown("proxy.test:443"), c)
            }
        }
    }

    /** The engine's own `proxy` with `proxyCredentials`: the engine's creation fails, as for a SOCKS5 empty password. */
    @Test fun negative_engineWithAnInvalidBasicUserIdFailsAtCreation() {
        val e =
            assertFailsWith<IllegalArgumentException> {
                HttpClient(Kuicksilver) {
                    engine {
                        proxy = ProxyBuilder.http(Url("http://127.0.0.1:3128"))
                        proxies { credentials = ProxyCredentials("a:b", "p") }
                    }
                }.close()
            }
        assertTrue("RFC 7617" in e.message!!, e.message)
    }

    /** Valid credentials stay valid: any other character (non-ASCII, SP, `@`, a colon in the password), and an empty password. */
    @Test fun validBasicCredentialsAreAccepted() {
        for (c in listOf(
            ProxyCredentials("u", "p:q"),
            ProxyCredentials("us er@x", ""),
            ProxyCredentials("üser", "päss w:rd"),
        )) {
            val proxy = ResolvedProxy.http("proxy.test", 3128, c)
            val expected =
                "Basic " +
                    kotlin.io.encoding.Base64
                        .encode("${c.user}:${c.password}".encodeToByteArray())
            assertEquals(expected, proxy.basicAuthorization)
            ResolvedProxy.https("proxy.test", 3128, c)
            ConnectUdpProxy(UdpProxyTemplate.wellKnown("proxy.test:443"), c)
        }
    }

    /** RFC 1929 has no colon rule: a SOCKS5 user name with a colon is still sent as is. */
    @Test fun colonInASocks5UserNameIsAccepted() {
        ResolvedProxy.socks5("proxy.test", 1080, ProxyCredentials("a:b", "p"))
    }
}
