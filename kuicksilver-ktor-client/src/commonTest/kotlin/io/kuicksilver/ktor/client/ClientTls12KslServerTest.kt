// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.ktor.server.H2cMode
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsVersion
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyReason
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import io.ktor.server.websocket.WebSockets as ServerWebSockets
import io.ktor.server.websocket.webSocket as serverWebSocket
import io.kuicksilver.ktor.server.Kuicksilver as KuicksilverServer

/**
 * The default client (TLS 1.3, or 1.2 with a server without 1.3) against a server that has TLS 1.2 alone, on every platform:
 * [Tls12KslServer], a raw `ksl` server capped at TLS 1.2 in front of a plain h2c connector. HTTP/1.1 and HTTP/2 over TLS 1.2
 * (RFC 9113 section 9.2), the version in the call diagnostics, pins, a TLS 1.2 resumption on the engine's second connection,
 * and a server without Extended Master Secret refused (RFC 7627 section 5.2, RFC 9325 section 3.5).
 */
class ClientTls12KslServerTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val loopback: suspend (String, Int) -> List<TcpAddress> = { _, p -> listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), p)) }

    private val anchored = TrustConfig.AnchoredCa(listOf(Certificate(RsaTestCert.root)))

    /** Runs [block] with a plain h2c backend answering "ok", and its port. */
    private suspend fun <T> backend(block: suspend (Int) -> T): T {
        val server =
            embeddedServer(KuicksilverServer, configure = {
                webSockets { overHttp2 = true }
                plainConnector {
                    host = "127.0.0.1"
                    port = 0
                    h2c = H2cMode.WithHttp11
                    // the TLS 1.2 server in front is the trusted gateway RFC 9110 section 7.4 names: its h2 requests say https
                    @OptIn(io.kuicksilver.annotations.DelicateKuicksilverApi::class)
                    allowMisdirectedHosts = true
                }
            }) {
                install(ServerWebSockets)
                routing {
                    get("/") { call.respondText("ok") }
                    serverWebSocket("/ws") {
                        val f = incoming.receive() as Frame.Text
                        send(Frame.Text("echo:" + f.readText() + " " + call.request.httpVersion))
                    }
                }
            }
        server.startSuspend(false)
        try {
            return block(
                server.engine
                    .resolvedConnectors()
                    .first()
                    .port,
            )
        } finally {
            server.stopSuspend(0, 0)
        }
    }

    private fun client(
        trust: TrustConfig = anchored,
        block: io.ktor.client.HttpClientConfig<KuicksilverEngineConfig>.() -> Unit = {},
        more: KuicksilverEngineConfig.() -> Unit = {},
    ) = testClient(engine = {
        resolverForTest = loopback
        connectTimeout = 20.seconds
        tls { this.trust = trust }
        more()
    }, block = block)

    private fun tcpOf(r: HttpResponse) = assertIs<TcpConnectionSnapshot>(assertNotNull(r.kuicksilverDiagnostics).connection)

    @Test fun defaultClientSpeaksHttp11OverTls12() =
        clientTest {
            backend { b ->
                Tls12KslServer.with(b, alpn = listOf("http/1.1")) { s ->
                    client().use { c ->
                        val r = c.get("https://server.test:${s.port}/")
                        assertEquals("ok", r.bodyAsText())
                        assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                        assertEquals(TlsVersion.Tls12, tcpOf(r).tlsVersion)
                    }
                    val o = s.next()
                    assertNull(o.failure)
                    assertEquals(0x0303, o.version)
                    assertTrue(o.ems, "Extended Master Secret")
                    // the opt-in TLS 1.3 only refuses this server
                    client(more = { tls { versions = io.kuicksilver.tls.TlsVersions.Tls13 } }).use { c ->
                        val e = assertFailsWith<Throwable> { c.get("https://server.test:${s.port}/") }
                        val alert = generateSequence(e) { it.cause }.filterIsInstance<TlsException.AlertReceived>().firstOrNull()
                        assertEquals("protocol_version", alert?.description, "the TLS 1.2 server's answer to a TLS 1.3-only client: $e")
                    }
                    assertNotNull(s.next().failure)
                }
            }
        }

    /** RFC 9113 section 9.2: HTTP/2 over TLS 1.2, with the RSA certificate section 9.2.2's mandatory suite needs. */
    @Test fun defaultClientSpeaksH2OverTls12() =
        clientTest {
            backend { b ->
                Tls12KslServer.with(b) { s ->
                    client().use { c ->
                        val r = c.get("https://server.test:${s.port}/")
                        assertEquals("ok", r.bodyAsText())
                        assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                        val t = tcpOf(r)
                        assertEquals(TlsVersion.Tls12, t.tlsVersion)
                        assertEquals("h2", t.alpn)
                    }
                    assertEquals("h2", s.next().alpn)
                }
            }
        }

    /**
     * WebSockets over HTTP/2 (RFC 8441, Extended CONNECT) on a TLS 1.2 connection: a `wss://` WebSocket goes as a stream of
     * the origin's h2 connection over TLS 1.2 (no second handshake), once the server allowed it in its SETTINGS
     * (SETTINGS_ENABLE_CONNECT_PROTOCOL), and echoes a message; RFC 9113 section 9.2's rules hold as for any stream.
     */
    @Test fun webSocketOverH2OnATls12Connection() =
        clientTest {
            backend { b ->
                Tls12KslServer.with(b) { s ->
                    client(block = { install(WebSockets) }).use { c ->
                        val r = c.get("https://server.test:${s.port}/")
                        assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                        assertEquals(TlsVersion.Tls12, tcpOf(r).tlsVersion)
                        var version: HttpProtocolVersion? = null
                        var echo = ""
                        withTimeout(20.seconds) {
                            c.webSocket("wss://server.test:${s.port}/ws") {
                                version = call.response.version
                                send(Frame.Text("tls12"))
                                echo = (incoming.receive() as Frame.Text).readText()
                            }
                        }
                        assertEquals(HttpProtocolVersion.HTTP_2_0, version, "Extended CONNECT on the h2 connection")
                        assertEquals("echo:tls12 HTTP/2", echo)
                    }
                    val first = s.next()
                    assertEquals("h2", first.alpn)
                    assertEquals(0x0303, first.version)
                    assertNull(s.outcomes.tryReceive().getOrNull(), "one TLS 1.2 handshake: the WebSocket took a stream of it")
                }
            }
        }

    /** Pins hold over TLS 1.2: a key not pinned fails with PinMismatch, the leaf's own passes. */
    @Test fun negative_pinsHoldOverTls12() =
        clientTest {
            backend { b ->
                Tls12KslServer.with(b, alpn = listOf("http/1.1")) { s ->
                    client(TrustConfig.Pinned(setOf(SpkiSha256(ByteArray(32) { 7 })), base = anchored)).use { c ->
                        val e = assertFailsWith<Throwable> { c.get("https://server.test:${s.port}/") }
                        val v = generateSequence(e) { it.cause }.filterIsInstance<TlsException.Verify>().firstOrNull()
                        assertIs<VerifyReason.PinMismatch>(v?.reason, "$e")
                    }
                    client(TrustConfig.Pinned(setOf(Certificate(RsaTestCert.leaf).spkiSha256), base = anchored)).use { c ->
                        val r = c.get("https://server.test:${s.port}/")
                        assertEquals("ok", r.bodyAsText())
                        assertEquals(TlsVersion.Tls12, tcpOf(r).tlsVersion)
                    }
                }
            }
        }

    /** The engine's second connection to a TLS 1.2 server resumes the first one's session (its ticket, RFC 5077). */
    @Test fun tls12SessionIsResumedOnTheEnginesNextConnection() =
        clientTest {
            backend { b ->
                Tls12KslServer.with(b, alpn = listOf("http/1.1")) { s ->
                    client().use { c ->
                        // Connection: close (RFC 9112 section 9.6) ends the first connection, so the second request needs a new one
                        val first = c.get("https://server.test:${s.port}/") { header("Connection", "close") }
                        assertEquals("ok", first.bodyAsText())
                        assertEquals("ok", c.get("https://server.test:${s.port}/").bodyAsText())
                    }
                    assertFalse(s.next().reused, "the first handshake is a full one")
                    assertTrue(s.next().reused, "the second resumes the first one's session")
                }
            }
        }

    /**
     * RFC 7627 section 5.2, RFC 9325 section 3.5: a TLS 1.2 server without Extended Master Secret (its ServerHello without
     * the extension) is refused through the engine before the client's Finished; the same server with it is served
     * ([defaultClientSpeaksHttp11OverTls12]).
     */
    @Test fun negative_tls12ServerWithoutEmsIsRefused() =
        clientTest {
            backend { b ->
                Tls12KslServer.with(b, alpn = listOf("http/1.1"), stripFromServerHello = EXTENDED_MASTER_SECRET) { s ->
                    client().use { c ->
                        val e = assertFailsWith<Throwable> { c.get("https://server.test:${s.port}/") }
                        assertTrue(
                            generateSequence(e) { it.cause }.any { "extended master secret" in it.message.orEmpty() },
                            "refused for EMS: $e",
                        )
                    }
                    assertNotNull(s.next().failure, "the server's handshake failed too")
                }
            }
        }

    private companion object {
        /** extended_master_secret (RFC 7627; extended_main_secret since RFC 9846 appendix D). */
        const val EXTENDED_MASTER_SECRET = 0x0017
    }
}
