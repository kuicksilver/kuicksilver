// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h3

import kotlin.test.Test
import kotlin.test.assertEquals

/** `serverHost` / `serverPort` of an HTTP/3 call from the `:authority` kuicksilver-http3 admits (RFC 3986 section 3.2). */
class H3AuthorityTest {
    @Test fun hostAndPort() {
        val cases =
            listOf(
                "example.com" to ("example.com" to null),
                "example.com:8443" to ("example.com" to 8443),
                "example.com:" to ("example.com" to null),
                "[::1]" to ("[::1]" to null),
                "[::1]:443" to ("[::1]" to 443),
                "127.0.0.1:80" to ("127.0.0.1" to 80),
                // userinfo is not the host (schemes other than http and https may carry it)
                "u:p@h.example:8080" to ("h.example" to 8080),
                "u@[::1]:9" to ("[::1]" to 9),
            )
        for ((authority, expected) in cases) {
            assertEquals(expected, authorityHost(authority) to authorityPort(authority), authority)
        }
    }

    /** Without a port in `:authority`, `serverPort` is the default port of the request's `:scheme` (RFC 9110 sections 4.2.1, 4.2.2). */
    @Test fun defaultPortFollowsTheScheme() {
        assertEquals(80, defaultPort("http"))
        assertEquals(443, defaultPort("https"))
        assertEquals(443, defaultPort(null))
    }
}
