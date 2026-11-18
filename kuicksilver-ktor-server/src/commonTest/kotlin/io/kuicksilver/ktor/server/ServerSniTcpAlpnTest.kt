// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.application.call
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.ServerTlsOverride
import io.kuicksilver.tls.TlsException
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * An `sniSelector` answer's `alpn` on the TCP side of a connector that serves HTTP/2 and HTTP/3: `h3` identifies HTTP/3 over
 * QUIC only (RFC 9114 section 3.1), so TLS over TCP never negotiates it, and a name whose answer lists `h3` alone has its TCP
 * handshake refused with `no_application_protocol` (RFC 7301 section 3.2). A name whose answer leaves `h3` out gets no
 * ALTSVC frame on HTTP/2 either (RFC 7838 section 2.1: an alternative must serve the origin).
 */
class ServerSniTcpAlpnTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private suspend fun server(alpn: List<String>?): Pair<Server, Int> {
        val id = ServerFixtures.identity()
        return tlsServer(
            configure = {
                http2 = true
                http3 = true
            },
            connector = { sniSelector = { ServerTlsOverride(id, alpn = alpn) } },
        ) { routing { get("/") { call.respondText("ok") } } }
    }

    /** The ALTSVC frames (RFC 7838 section 4) the server sends on an HTTP/2 connection before its response to one request. */
    private suspend fun altSvcFrames(
        answer: List<String>?,
        offer: List<String> = listOf("h2"),
    ): List<RawFrame> {
        val (server, port) = server(answer)
        try {
            RawH2Client.connect(port, alpn = offer).use { raw ->
                assertEquals("h2", raw.alpn)
                raw.preface()
                raw.headers(1, RawH2Client.get())
                val seen = ArrayList<RawFrame>()
                raw.await {
                    seen += it
                    it.type == RawFrame.HEADERS && it.stream == 1
                }
                return seen.filter { it.type == ALTSVC }
            }
        } finally {
            server.stop(100, 500)
        }
    }

    /** The protocol a TCP client offering [offer] negotiates with a server whose answer is [answer]. */
    private suspend fun negotiated(
        answer: List<String>,
        offer: List<String>,
    ): String? {
        val (server, port) = server(answer)
        try {
            return RawH2Client.connect(port, alpn = offer).use { it.alpn }
        } finally {
            server.stop(100, 500)
        }
    }

    /** The alert a TCP client offering [offer] receives from a server whose answer is [answer], null when it connected. */
    private suspend fun alertFor(
        answer: List<String>?,
        offer: List<String>,
    ): Int? {
        val (server, port) = server(answer)
        try {
            val failure = runCatching { RawH2Client.connect(port, alpn = offer).use { it.alpn } }.exceptionOrNull() ?: return null
            var cause: Throwable? = failure
            while (cause != null && cause !is TlsException.AlertReceived) cause = cause.cause
            return cause?.code ?: throw AssertionError("no alert received", failure)
        } finally {
            server.stop(100, 500)
        }
    }

    @Test fun negative_anH2NameWithoutH3GetsNoAltSvcFrame() =
        h3ServerTest {
            assertTrue(altSvcFrames(listOf("h2", "http/1.1")).isEmpty(), "no ALTSVC for a name restricted to TCP")
            assertEquals(1, altSvcFrames(listOf("h3", "h2", "http/1.1")).size, "control: h3 listed")
            assertEquals(1, altSvcFrames(null).size, "control: no alpn in the answer")
            assertEquals(1, altSvcFrames(listOf("h3", "h2"), offer = listOf("h3", "h2")).size, "h3 kept off TCP, still advertised")
        }

    /** The server prefers its own order (RFC 7301 section 3.2): `h3` first in the answer, or alone in the offer, is never chosen. */
    @Test fun negative_h3IsNeverSelectedOverTcp() =
        h3ServerTest {
            assertEquals("h2", negotiated(listOf("h3", "h2", "http/1.1"), offer = listOf("h3", "h2")))
            assertEquals("h2", negotiated(listOf("h2", "h3"), offer = listOf("h3", "h2")))
            assertEquals("h2", negotiated(listOf("h3", "h3", "h2"), offer = listOf("h3", "h2")))
            assertEquals("http/1.1", negotiated(listOf("h3", "h2", "http/1.1"), offer = listOf("h3", "http/1.1")))
            assertEquals(120, alertFor(listOf("h3", "h2"), offer = listOf("h3")), "a client offering h3 alone shares nothing over TCP")
        }

    /** An answer of `h3` alone serves its name over QUIC only: its TCP handshake ends with `no_application_protocol` (120). */
    @Test fun negative_anH3OnlyNameIsRefusedOverTcpWithNoApplicationProtocol() =
        h3ServerTest {
            assertEquals(120, alertFor(listOf("h3"), offer = listOf("h2")))
            assertEquals(120, alertFor(listOf("h3"), offer = listOf("h3", "h2")))
            assertEquals(120, alertFor(listOf("h3"), offer = listOf("h3")))
            assertEquals(120, alertFor(listOf("h3", "h3"), offer = listOf("h2", "http/1.1")))
            assertEquals(120, alertFor(listOf("h3"), offer = emptyList()), "a client without ALPN is refused too")
            assertEquals(null, alertFor(listOf("h3", "http/1.1"), offer = listOf("http/1.1")), "control: a TCP protocol listed")
        }

    /**
     * A TCP client without ALPN speaks HTTP/1.1: RFC 9113 section 3.3, "HTTP/2 connections over TLS MUST use protocol
     * negotiation in TLS". A name whose answer leaves `http/1.1` out refuses it with `no_application_protocol` (120).
     */
    @Test fun negative_aClientWithoutAlpnIsRefusedForANameWithoutHttp11() =
        h3ServerTest {
            assertEquals(120, alertFor(listOf("h2"), offer = emptyList()))
            assertEquals(120, alertFor(listOf("h3", "h2"), offer = emptyList()))
            assertEquals(120, alertFor(listOf("h3"), offer = emptyList()), "h3 alone: still 120")
            assertEquals(null, alertFor(listOf("h2", "http/1.1"), offer = emptyList()), "control: http/1.1 listed")
            assertEquals(null, alertFor(listOf("h3", "http/1.1"), offer = emptyList()), "control: http/1.1 listed after h3")
            assertEquals(null, alertFor(emptyList(), offer = emptyList()), "control: an empty answer, no ALPN")
            assertEquals(null, alertFor(null, offer = emptyList()), "control: no alpn in the answer, the connector's protocols")
            assertEquals(null, alertFor(listOf("h2"), offer = listOf("h2")), "control: a client with ALPN")
        }

    /**
     * The connector's TCP configurations carry the same rule for their own list (a `tlsConfig(listOf("h2"))` refuses a client
     * without ALPN); the QUIC one has none, QUIC needing ALPN anyway (RFC 9001 section 8.1).
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun theConnectorsTcpConfigurationsTakeHttp11ForAClientWithoutAlpn() {
        val connector = KuicksilverTlsConnector.Builder(ServerFixtures.identity()).build()
        assertEquals("http/1.1", connector.tlsConfig(listOf("h2")).alpnFallback)
        assertEquals("http/1.1", connector.tlsConfig(listOf("h2", "http/1.1")).alpnFallback)
        assertEquals(null, connector.tlsConfig(listOf("h3")).alpnFallback)
    }

    private companion object {
        const val ALTSVC = 0xa
    }
}
