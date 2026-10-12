// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.http.Url
import kotlin.test.Test
import kotlin.test.assertEquals

class SocketHostTest {
    /** Ktor keeps the brackets of an IPv6 literal in `Url.host`; a socket address needs the bare literal (Kotlin/Native's `getaddrinfo` rejects "[::1]"). */
    @Test fun ipv6LiteralLosesItsBrackets() {
        assertEquals("[::1]", Url("https://[::1]:8443/").host)
        assertEquals("::1", socketHost(Url("https://[::1]:8443/").host))
        assertEquals("fe80::1", socketHost("[fe80::1]"))
    }

    @Test fun namesAndIpv4StayAsTheyAre() {
        assertEquals("127.0.0.1", socketHost("127.0.0.1"))
        assertEquals("example.com", socketHost("example.com"))
        assertEquals("::1", socketHost("::1"))
    }

    @Test fun altUsedHostIsBracketedForIpv6() {
        // RFC 7838 section 5: Alt-Used carries uri-host [":" port]; an IPv6 literal needs its brackets
        assertEquals("[::1]", uriHost("::1"))
        assertEquals("[2001:db8::1]", uriHost("2001:db8::1"))
        assertEquals("[::1]", uriHost("[::1]"))
        assertEquals("alt.example", uriHost("alt.example"))
        assertEquals("127.0.0.1", uriHost("127.0.0.1"))
    }
}
