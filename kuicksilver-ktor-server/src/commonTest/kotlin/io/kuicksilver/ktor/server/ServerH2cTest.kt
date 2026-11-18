// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * h2c, HTTP/2 over cleartext TCP with prior knowledge (RFC 9113 sections 3.3 and 3.4; ADR-0018), on a plain connector:
 * [H2cMode.Only] serves HTTP/2 alone, [H2cMode.WithHttp11] tells HTTP/2 from HTTP/1.1 by the client connection preface,
 * without holding back an HTTP/1.1 request and within the request-head deadline. Requests written by hand ([RawH2Client]).
 */
class ServerH2cTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val protocolError = 0x1L

    /** A started server with one plain connector of [mode] on a free loopback port (HTTP/3 off); returns it and the port. */
    private suspend fun h2cServer(
        mode: H2cMode,
        gateway: Boolean = false,
        configure: KuicksilverApplicationEngine.Configuration.() -> Unit = {},
        module: io.ktor.server.application.Application.() -> Unit = {
            routing { get("/") { call.respondText("${call.request.httpVersion} ${call.request.local.scheme}") } }
        },
    ): Pair<Server, Int> {
        val server =
            kuicksilverServer(null, configure = {
                plainConnector {
                    host = "127.0.0.1"
                    port = 0
                    h2c = mode
                    trustedGateway = gateway
                }
                http3 = false
                configure()
            }, module)
        server.startSuspend(wait = false)
        return server to
            server.engine
                .resolvedConnectors()
                .first()
                .port
    }

    /** The control data of an h2c GET (section 8.3.1): `:scheme` `http`. */
    private fun get(
        path: String = "/",
        scheme: String = "http",
    ) = listOf(":method" to "GET", ":scheme" to scheme, ":authority" to "server.test", ":path" to path)

    /** Sends a GET on stream 1 and returns the response's DATA as text once the stream ended. */
    private suspend fun RawH2Client.fetch(fields: List<Pair<String, String>> = get()): String {
        headers(1, fields)
        val body = StringBuilder()
        withTimeout(10.seconds) {
            while (true) {
                val f = assertNotNull(readFrame(), "the connection ended before the response")
                if (f.stream != 1) continue
                if (f.type == RawFrame.DATA) body.append(f.payload.decodeToString())
                if (f.endStream) break
            }
        }
        return body.toString()
    }

    @Test fun priorKnowledgeOnAnH2cOnlyConnector() =
        serverTest {
            val (server, port) = h2cServer(H2cMode.Only)
            try {
                RawH2Client.connectPlain(port).use { raw ->
                    raw.preface()
                    // section 3.4: the server's preface is a SETTINGS frame, its first frame, with what TLS connections send:
                    // SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441) and SETTINGS_NO_RFC7540_PRIORITIES (RFC 9218 section 2.1)
                    val first = assertNotNull(raw.readFrame())
                    assertEquals(RawFrame.SETTINGS, first.type, "$first")
                    assertEquals(1L, first.settings[0x8], "${first.settings}")
                    assertEquals(1L, first.settings[0x9], "${first.settings}")
                    assertEquals("HTTP/2 http", raw.fetch())
                    // an HTTP/2 connection of the engine's, counted as the TLS ones are (the probe's server.h2Connections)
                    assertEquals(
                        1,
                        withTimeout(10.seconds) {
                            server.engine.h2Live.count
                                .first { it == 1 }
                        },
                    )
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun http11AndH2cOnOnePort() =
        serverTest {
            val (server, port) = h2cServer(H2cMode.WithHttp11)
            try {
                RawH2Client.connectPlain(port).use { raw ->
                    raw.preface()
                    assertEquals("HTTP/2 http", raw.fetch())
                }
                val h1 = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n", tls = null)
                assertTrue(h1.startsWith("HTTP/1.1 200 ") && h1.endsWith("HTTP/1.1 http"), h1)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A request shorter than the 24-octet preface (an HTTP/1.0 request line and the empty line: 18 octets) is answered at
     * once: the check hands the connection to HTTP/1.1 at the first octet that differs, never waiting for 24.
     */
    @Test fun negative_shortHttp11RequestIsNotHeldForThePreface() =
        serverTest {
            val (server, port) = h2cServer(H2cMode.WithHttp11, configure = { requestHeaderTimeoutSeconds = 60 })
            try {
                val r = withTimeout(10.seconds) { rawHttp(port, "GET / HTTP/1.0\r\n\r\n", tls = null) }
                assertTrue(r.startsWith("HTTP/1.1 200 "), r)
            } finally {
                server.stop(100, 500)
            }
        }

    /** An HTTP/1.1 request whose first octets are the preface's (`PRI `) but not all of them is HTTP/1.1. */
    @Test fun negative_aPrefixOfThePrefaceIsHttp11() =
        serverTest {
            val (server, port) = h2cServer(H2cMode.WithHttp11)
            try {
                val r = rawHttp(port, "PRI * HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n", tls = null)
                assertTrue(r.startsWith("HTTP/1.1 "), r)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * Section 3.4: the preface is exactly 24 octets. One whose request line is the preface's but whose `SM` line is not is
     * no HTTP/2 connection: on a connector with HTTP/1.1 its `PRI * HTTP/2.0` line gets the 505 of a plain connector.
     */
    @Test fun negative_brokenPrefaceWithHttp11Gets505() =
        serverTest {
            val (server, port) = h2cServer(H2cMode.WithHttp11)
            try {
                val r = rawHttp(port, "PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n", tls = null)
                assertTrue(r.startsWith("HTTP/1.1 505 "), r)
            } finally {
                server.stop(100, 500)
            }
        }

    /** Section 3.4: "Clients and servers MUST treat an invalid connection preface as a connection error ... PROTOCOL_ERROR". */
    @Test fun negative_invalidPrefaceOnAnH2cOnlyConnectorIsAProtocolError() =
        serverTest {
            val (server, port) = h2cServer(H2cMode.Only)
            try {
                RawH2Client.connectPlain(port).use { raw ->
                    raw.write("PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n".encodeToByteArray() + RawH2Client.frame(RawFrame.SETTINGS, 0, 0))
                    val frames = raw.readToEnd(within = 15.seconds)
                    val goAway = assertNotNull(frames.lastOrNull { it.type == RawFrame.GOAWAY }, "$frames")
                    assertEquals(protocolError, goAway.errorCode)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** An HTTP/1.1 client on an h2c-only port gets no HTTP/1.1 answer: the connection error of an invalid preface. */
    @Test fun negative_http11OnAnH2cOnlyConnectorIsRefused() =
        serverTest {
            var calls = 0
            val (server, port) = h2cServer(H2cMode.Only, module = { routing { get("/") { calls++ } } })
            try {
                RawH2Client.connectPlain(port).use { raw ->
                    raw.write("GET / HTTP/1.1\r\nHost: server.test\r\n\r\n".encodeToByteArray())
                    val frames = raw.readToEnd(within = 15.seconds)
                    val goAway = assertNotNull(frames.lastOrNull { it.type == RawFrame.GOAWAY }, "$frames")
                    assertEquals(protocolError, goAway.errorCode)
                }
                val text = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n", tls = null)
                assertFalse(text.startsWith("HTTP/"), text)
                assertEquals(0, calls)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A slowloris on the preface: part of it, then nothing. The connection is closed at the request-head deadline on both
     * kinds of connector (on [H2cMode.WithHttp11] the octets seen still match the preface, so the check is what waits).
     */
    @Test fun negative_slowPrefaceIsCutAtTheHeaderDeadline() =
        serverTest {
            for (mode in listOf(H2cMode.Only, H2cMode.WithHttp11)) {
                val (server, port) = h2cServer(mode, configure = { requestHeaderTimeoutSeconds = 1 })
                try {
                    RawH2Client.connectPlain(port).use { raw ->
                        raw.write("PRI * HTTP/2.0\r\n".encodeToByteArray())
                        // ends (the server closed) well before the 15 s: readToEnd throws on a timeout
                        raw.readToEnd(within = 15.seconds)
                    }
                } finally {
                    server.stop(100, 500)
                }
            }
        }

    /**
     * RFC 9113 section 3.1 deprecates `Upgrade: h2c`, and the server never takes it: such a request is served as HTTP/1.1
     * (RFC 9110 section 7.8 lets a server ignore an upgrade), with no 101.
     */
    @Test fun upgradeH2cIsServedAsHttp11() =
        serverTest {
            val (server, port) = h2cServer(H2cMode.WithHttp11)
            try {
                val r =
                    rawHttp(
                        port,
                        "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: Upgrade, HTTP2-Settings, close\r\nUpgrade: h2c\r\n" +
                            "HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\r\n",
                        tls = null,
                    )
                assertTrue(r.startsWith("HTTP/1.1 200 ") && r.endsWith("HTTP/1.1 http"), r)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 9110 section 7.4: an `https` request over a plain connection is misdirected (no certificate secures it), on h2c
     * as in absolute form on HTTP/1.1: 421 (HEADERS with END_STREAM, no content) and never the application, unless the
     * connector's clients are trusted gateways (a TLS-terminating proxy that forwards `:scheme https`).
     */
    @Test fun negative_httpsSchemeOverH2cIsMisdirected() =
        serverTest {
            val calls = MutableStateFlow(0)
            val module: io.ktor.server.application.Application.() -> Unit = {
                routing {
                    get("/") {
                        calls.update { it + 1 }
                        call.respondText("${call.request.local.scheme}")
                    }
                }
            }
            val (server, port) = h2cServer(H2cMode.Only, module = module)
            try {
                RawH2Client.connectPlain(port).use { raw ->
                    raw.preface()
                    assertEquals("", raw.fetch(get(scheme = "https")))
                }
                assertEquals(0, calls.value)
            } finally {
                server.stop(100, 500)
            }
            val (gw, gwPort) = h2cServer(H2cMode.Only, gateway = true, module = module)
            try {
                RawH2Client.connectPlain(gwPort).use { raw ->
                    raw.preface()
                    assertEquals("http", raw.fetch(get(scheme = "https")))
                }
                assertEquals(1, calls.value)
            } finally {
                gw.stop(100, 500)
            }
        }

    /**
     * Request smuggling between an HTTP/1.1 front and an h2c back end (ADR-0018, threat model): the message checks of HTTP/2
     * hold on h2c as on TLS. A connection-specific field (`transfer-encoding`, RFC 9113 section 8.2.2) or a
     * `content-length` that the DATA does not match (section 8.1.1) makes the request malformed: RST_STREAM with
     * PROTOCOL_ERROR, never the application, and the connection serves the next request.
     */
    @Test fun negative_smugglingFieldsOverH2cAreMalformed() =
        serverTest {
            val calls = MutableStateFlow(0)
            val (server, port) =
                h2cServer(H2cMode.Only, module = {
                    routing {
                        get("/") {
                            calls.update { it + 1 }
                            call.respondText("ok")
                        }
                        post("/") {
                            calls.update { it + 1 }
                            call.respondText("ok")
                        }
                    }
                })
            try {
                RawH2Client.connectPlain(port).use { raw ->
                    raw.preface()
                    raw.headers(1, get() + ("transfer-encoding" to "chunked"))
                    val reset = assertNotNull(raw.await { it.stream == 1 && it.type == RawFrame.RST_STREAM })
                    assertEquals(protocolError, reset.errorCode)
                    val post = listOf(":method" to "POST", ":scheme" to "http", ":authority" to "server.test", ":path" to "/")
                    raw.headers(3, post + ("content-length" to "5"), endStream = false)
                    raw.data(3, "0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n".encodeToByteArray(), endStream = true)
                    val reset3 = assertNotNull(raw.await { it.stream == 3 && it.type == RawFrame.RST_STREAM })
                    assertEquals(protocolError, reset3.errorCode)
                    raw.headers(5, get())
                    assertNotNull(raw.await { it.stream == 5 && it.endStream })
                }
                assertEquals(1, calls.value)
            } finally {
                server.stop(100, 500)
            }
        }

    /** Section 6.8: a stopping server sends the two-step GOAWAY on its h2c connections as on TLS ones. */
    @Test fun stopSendsTwoStepGoAwayOnH2c() =
        serverTest {
            val (server, port) = h2cServer(H2cMode.Only)
            RawH2Client.connectPlain(port).use { raw ->
                coroutineScope {
                    raw.preface()
                    assertEquals("HTTP/2 http", raw.fetch())
                    val stop = async { server.stopSuspend(10_000, 15_000) }
                    val first = assertNotNull(raw.await { it.type == RawFrame.GOAWAY })
                    assertEquals(Int.MAX_VALUE, first.lastStreamId)
                    assertEquals(0L, first.errorCode)
                    val ping = assertNotNull(raw.await { it.type == RawFrame.PING && it.flags and 1 == 0 })
                    raw.write(RawH2Client.frame(RawFrame.PING, 1, 0, ping.payload))
                    val second = assertNotNull(raw.await { it.type == RawFrame.GOAWAY })
                    assertEquals(1, second.lastStreamId)
                    raw.close()
                    withTimeout(15.seconds) { stop.await() }
                }
            }
        }

    /**
     * Rapid Reset (CVE-2023-44487) over h2c: the reset budget ends the connection with ENHANCE_YOUR_CALM, as over TLS
     * (ADR-0018: every HTTP/2 limit applies to h2c unchanged).
     */
    @Test fun negative_rapidResetOverH2cEndsCalm() =
        serverTest {
            val (server, port) =
                h2cServer(H2cMode.Only, module = { routing { get("/") { kotlinx.coroutines.awaitCancellation() } } })
            try {
                RawH2Client.connectPlain(port).use { raw ->
                    raw.preface()
                    val all = ArrayList<Byte>()
                    for (i in 0 until 2_000) {
                        val id = 1 + 2 * i
                        all += RawH2Client.frame(RawFrame.HEADERS, 0x5, id, RawH2Client.block(get())).toList()
                        all += RawH2Client.frame(RawFrame.RST_STREAM, 0, id, byteArrayOf(0, 0, 0, 8)).toList()
                    }
                    runCatching { raw.write(all.toByteArray()) }
                    val frames = runCatching { raw.readToEnd(within = 30.seconds) }.getOrDefault(emptyList())
                    frames.lastOrNull { it.type == RawFrame.GOAWAY }?.let { assertEquals(0xbL, it.errorCode) }
                }
                withTimeout(10.seconds) { server.engine.h2FloodEnds.first { it == 1L } }
            } finally {
                server.stop(100, 500)
            }
        }

    /** h2c needs a plain connector: one the configuration's identity turns into TLS refuses the start (section 3.3). */
    @Test fun negative_h2cOnAConnectorTheIdentityMakesTlsIsRefused() =
        serverTest {
            val server =
                kuicksilverServer(null, configure = {
                    identity = ServerFixtures.identity()
                    plainConnector {
                        host = "127.0.0.1"
                        port = 0
                        h2c = H2cMode.Only
                    }
                    http3 = false
                }) {}
            try {
                assertFailsWith<IllegalArgumentException> { server.startSuspend(wait = false) }
            } finally {
                server.stop(100, 500)
            }
        }
}
