// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.message

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** RFC 9113 section 8 beyond the shared vectors (HttpFieldVectorsTest): what the engines read back from a valid message. */
class H2MessagesTest {
    @Test fun requestControlDataComesFirstWithAuthority() {
        val f = H2Messages.buildRequest("GET", "https", "example.com:8443", "/a?b", listOf("accept" to "*/*"))
        // section 8.3.1: clients generating HTTP/2 requests directly use :authority, not host
        assertEquals(listOf(":method", ":scheme", ":authority", ":path", "accept"), f.map { it.first })
        H2Messages.requireValidRequest(f)
    }

    @Test fun negative_invalidOwnRequestIsIllegalArgument() {
        assertFailsWith<IllegalArgumentException> {
            H2Messages.requireValidRequest(H2Messages.buildRequest("GET", "https", "example.com", "/", listOf("connection" to "close")))
        }
        assertFailsWith<IllegalArgumentException> {
            H2Messages.requireValidRequest(H2Messages.buildRequest("GET", "https", "example.com", "/", listOf("x" to "a\r\nb")))
        }
    }

    @Test fun responseStatusAndContentLength() {
        val r = H2Messages.parseResponse(listOf(":status" to "200", "content-length" to "5", "content-length" to "5", "x" to "y"))
        assertEquals(200, r.status)
        assertEquals(5L, r.contentLength)
        assertEquals(listOf("content-length" to "5", "x" to "y"), r.fields) // identical values collapse to one (RFC 9110 section 8.6)
        assertEquals(-1L, H2Messages.parseResponse(listOf(":status" to "204")).contentLength)
    }

    @Test fun negative_teIsRequestOnly() {
        assertFailsWith<MalformedMessage> { H2Messages.parseResponse(listOf(":status" to "200", "te" to "trailers")) }
        H2Messages.parseRequest(
            listOf(":method" to "GET", ":scheme" to "https", ":authority" to "a.example", ":path" to "/", "te" to "trailers"),
            connectProtocolEnabled = false,
        )
    }

    @Test fun negative_extendedConnectNeedsTheSetting() {
        val f =
            listOf(":method" to "CONNECT", ":protocol" to "websocket", ":scheme" to "https", ":authority" to "a.example", ":path" to "/")
        assertFailsWith<MalformedMessage> { H2Messages.parseRequest(f, connectProtocolEnabled = false) } // RFC 8441 section 4
        assertEquals("websocket", H2Messages.parseRequest(f, connectProtocolEnabled = true).protocol)
    }

    /**
     * RFC 9113 section 8.3.1: `host` that identifies another entity than `:authority` is malformed. RFC 9110 section 4.2.3:
     * the host is case-insensitive and an empty or default port is the scheme's default, so these name the same entity.
     */
    @Test fun hostAndAuthorityCompareAsTheSameOrigin() {
        fun req(
            authority: String,
            host: String,
            scheme: String = "https",
        ) = H2Messages.parseRequest(
            listOf(":method" to "GET", ":scheme" to scheme, ":authority" to authority, ":path" to "/", "host" to host),
            connectProtocolEnabled = false,
        )
        req("Example.COM", "example.com")
        req("example.com:443", "example.com")
        req("example.com", "EXAMPLE.com:443")
        req("example.com:80", "example.com", scheme = "http")
        req("[::1]:443", "[::1]")
        assertFailsWith<MalformedMessage> { req("example.com", "example.net") }
        assertFailsWith<MalformedMessage> { req("example.com:8443", "example.com") }
        assertFailsWith<MalformedMessage> { req("example.com:80", "example.com") } // https: 80 is not the default
    }
}
