// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

import io.ktor.http.HttpMethod
import io.kuicksilver.ktor.server.uriHost
import kotlin.test.Test
import kotlin.test.assertEquals

/** `serverHost` and `serverPort` from the Host field (RFC 9110 section 7.2: `uri-host [ ":" port ]`). */
class H1ConnectionPointTest {
    private fun point(
        host: String?,
        scheme: String = "https",
    ) = H1ConnectionPoint(null, null, "HTTP/1.1", "/", host, HttpMethod.Get, scheme)

    @Test fun nameAndPort() {
        assertEquals("example.com", point("example.com:8443").serverHost)
        assertEquals(8443, point("example.com:8443").serverPort)
        assertEquals("example.com", point("example.com").serverHost)
        assertEquals(443, point("example.com").serverPort)
        assertEquals(80, point("example.com", scheme = "http").serverPort)
        assertEquals("127.0.0.1", point("127.0.0.1:8080").serverHost)
    }

    /**
     * An IPv6 literal keeps its brackets, as `serverHost` over HTTP/3 does (`H3Call`). Before, `Host: [::1]:8443` gave
     * `"[:"` (everything before the last colon), and `Host: [::1]` gave `"[:"` with the local port.
     */
    @Test fun ipv6Literal() {
        assertEquals("[::1]", point("[::1]:8443").serverHost)
        assertEquals(8443, point("[::1]:8443").serverPort)
        assertEquals("[::1]", point("[::1]").serverHost)
        assertEquals(443, point("[::1]").serverPort)
        assertEquals("[2001:db8::1]", point("[2001:db8::1]:80").serverHost)
        assertEquals(80, point("[2001:db8::1]:80").serverPort)
    }

    @Test fun deprecatedHostAndPortWithoutLocalAddress() {
        @Suppress("DEPRECATION")
        assertEquals("[::1]", point("[::1]:8443").host)
        @Suppress("DEPRECATION")
        assertEquals(8443, point("[::1]:8443").port)
        @Suppress("DEPRECATION")
        assertEquals(443, point("[::1]").port)
    }

    /**
     * The local and remote hosts are the connection's literals as the listener hands them over (`ipLiteral()`, never a
     * name lookup); the deprecated `host` and `port` are `serverHost` and `serverPort`, as over HTTP/2 and HTTP/3.
     */
    @Test fun hostsAreTheAddressLiterals() {
        val p =
            H1ConnectionPoint(
                H1Address("127.0.0.2", 50000),
                H1Address("127.0.0.1", 8443),
                "HTTP/1.1",
                "/",
                "example.com:8080",
                HttpMethod.Get,
                "https",
            )
        assertEquals("127.0.0.1", p.localHost)
        assertEquals("127.0.0.1", p.localAddress)
        assertEquals(8443, p.localPort)
        assertEquals("127.0.0.2", p.remoteHost)
        assertEquals("127.0.0.2", p.remoteAddress)
        assertEquals(50000, p.remotePort)
        assertEquals("example.com", p.serverHost)
        @Suppress("DEPRECATION")
        assertEquals("example.com", p.host)
        @Suppress("DEPRECATION")
        assertEquals(8080, p.port)
    }

    /**
     * Without a Host field `serverHost` is the local address as a Host field writes it: an IPv6 literal in brackets (RFC
     * 9110 section 7.2 `uri-host`, RFC 3986 section 3.2.2 `IP-literal`), without a zone ID, which stays in `localHost`.
     */
    @Test fun ipv6LiteralsWithoutHostField() {
        val p = H1ConnectionPoint(H1Address("::1", 50000), H1Address("::1", 8443), "HTTP/1.0", "/", null, HttpMethod.Get, "http")
        assertEquals("::1", p.localHost)
        assertEquals("::1", p.localAddress)
        assertEquals("::1", p.remoteHost)
        assertEquals("[::1]", p.serverHost)
        assertEquals(8443, p.serverPort)
        @Suppress("DEPRECATION")
        assertEquals("[::1]", p.host)
        @Suppress("DEPRECATION")
        assertEquals(8443, p.port)
        val scoped = H1ConnectionPoint(H1Address("fe80::2", 1), H1Address("fe80::1%en0", 80), "HTTP/1.0", "/", null, HttpMethod.Get, "http")
        assertEquals("fe80::1%en0", scoped.localHost)
        assertEquals("fe80::1%en0", scoped.localAddress)
        assertEquals("[fe80::1]", scoped.serverHost)
        val v4 = H1ConnectionPoint(H1Address("10.0.0.2", 1), H1Address("10.0.0.1", 80), "HTTP/1.0", "/", null, HttpMethod.Get, "http")
        assertEquals("10.0.0.1", v4.serverHost)
    }

    @Test fun uriHostBracketsIpv6Only() {
        assertEquals("[::1]", uriHost("::1"))
        assertEquals("[fe80::1]", uriHost("fe80::1%en0")) // no zone in a URI host (RFC 3986, RFC 9844)
        assertEquals("[::1]", uriHost("[::1]"))
        assertEquals("10.0.0.1", uriHost("10.0.0.1"))
        assertEquals("example.com", uriHost("example.com"))
    }
}
