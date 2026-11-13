// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.engineinterop

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * Our client against a plain Netty 4.2 server, for what Ktor's server API cannot produce: interim responses, trailer
 * fields and a GOAWAY with a stream in flight, over HTTP/1.1 and HTTP/2 (both over TLS 1.3 with ALPN). The HTTP/2 GET,
 * POST, cancellation, large-field, gzip and TLS 1.2 cases against plain Netty are `H2InteropTest` in kuicksilver-ktor-client.
 */
internal class ClientToPlainNettyTest {
    private fun pair(
        h2: Boolean,
        block: suspend (PlainNettyServer, io.ktor.client.HttpClient) -> Unit,
    ) = interopTest {
        PlainNettyServer(h2).use { s -> ktorClient(ClientEngine.Kuicksilver, http2 = h2).use { c -> block(s, c) } }
    }

    /**
     * RFC 9110 section 15.2: "A client MUST be able to parse one or more 1xx responses received prior to a final response,
     * even if the client does not expect one." A 103 (RFC 8297) before the 200 over HTTP/1.1.
     */
    @Test fun earlyHintsBeforeTheFinalResponseH1() =
        pair(h2 = false) { s, c ->
            val r = c.get(s.url("/early-hints"))
            assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
            assertEquals(HttpStatusCode.OK, r.status)
            assertEquals("hinted", r.bodyAsText())
            assertEquals("/next", c.get(s.url("/next")).bodyAsText())
        }

    /** The same over HTTP/2 (RFC 9113 section 8.1: a response may begin with HEADERS frames of 1xx responses). */
    @Test fun earlyHintsBeforeTheFinalResponseH2() =
        pair(h2 = true) { s, c ->
            val r = c.get(s.url("/early-hints"))
            assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
            assertEquals(HttpStatusCode.OK, r.status)
            assertEquals("hinted", r.bodyAsText())
        }

    /**
     * A chunked response with a trailer section (RFC 9112 section 7.1.2): the content is complete and the connection
     * carries the next request. RFC 9110 section 6.5.1 lets a recipient discard trailer fields it does not use, as the
     * engine does (Ktor's client API has no trailers).
     */
    @Test fun trailersH1() =
        pair(h2 = false) { s, c ->
            assertEquals("with trailers", c.get(s.url("/trailers")).bodyAsText())
            assertEquals("/next", c.get(s.url("/next")).bodyAsText())
            assertEquals(1, s.connections.get(), "the trailer section ended the message, not the connection")
        }

    /** Trailers over HTTP/2: a HEADERS frame with END_STREAM after the DATA (RFC 9113 section 8.1). */
    @Test fun trailersH2() =
        pair(h2 = true) { s, c ->
            assertEquals("with trailers", c.get(s.url("/trailers")).bodyAsText())
            assertEquals("/next", c.get(s.url("/next")).bodyAsText())
        }

    /**
     * RFC 9113 section 6.8: the server sends GOAWAY (NO_ERROR) naming the stream in flight as its last; that stream
     * completes, and "Receivers of a GOAWAY frame MUST NOT open additional streams on the connection": the next request
     * goes over a new connection.
     */
    @Test fun goAwayLetsTheStreamInFlightCompleteAndMovesOn() =
        pair(h2 = true) { s, c ->
            assertEquals("/first", c.get(s.url("/first")).bodyAsText())
            val r = c.get(s.url("/goaway"))
            assertEquals("before goaway;after goaway", r.bodyAsText())
            assertEquals(3, withTimeout(10.seconds) { s.goAwaySent.await() }, "the stream the GOAWAY named")
            assertEquals("/after", c.get(s.url("/after")).bodyAsText())
            assertEquals(2, s.connections.get(), "a request after the GOAWAY on a new connection")
        }
}
