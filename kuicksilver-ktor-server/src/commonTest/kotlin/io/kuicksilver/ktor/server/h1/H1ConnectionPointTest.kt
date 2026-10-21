// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

import io.ktor.http.HttpMethod
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
}
