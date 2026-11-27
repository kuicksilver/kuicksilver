// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicException
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.TlsException
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A server that requires a client certificate the client did not configure ends the handshake with certificate_required
 * (116; TLS 1.3, RFC 9846 section 4.4.2.4). Over TLS 1.3 the client's handshake completes on its side before the server
 * checks the certificate, so the client may have its connection, and its request under way, when the alert comes: the
 * call must name the alert whatever the timing, on every protocol, not "the connection is going away" (the GOAWAY the
 * HTTP/2 client sends as the transport fails) or another vague end. Each case runs several times to cover both orders.
 */
@OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
class ClientMissingCertificateTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val alert = "TLS alert received from the peer: certificate_required (116)"

    @Test fun negative_overHttp11TheCallNamesTheAlert() =
        clientTest {
            withServer(http2 = false) { port ->
                repeat(ROUNDS) { round ->
                    val e = assertFails { testClient().use { it.get("https://127.0.0.1:$port/") } }
                    val received = generateSequence(e) { it.cause }.filterIsInstance<TlsException.AlertReceived>().firstOrNull()
                    assertNotNull(received, "round $round: $e")
                    assertEquals(alert, received.message, "round $round: $e")
                    assertTrue(e.message.orEmpty().contains("certificate_required (116)"), "round $round: $e")
                }
            }
        }

    /**
     * Over HTTP/2 the call fails with the lost connection, the alert as its cause, and is not repeated: the request was
     * not processed (RFC 9113 section 8.7), but a new connection would only meet the same alert after a full handshake.
     */
    @Test fun negative_overHttp2TheCallNamesTheAlert() =
        clientTest {
            withServer(http2 = true) { port ->
                repeat(ROUNDS) { round ->
                    val retries = kotlin.concurrent.atomics.AtomicInt(0)
                    val e =
                        assertFails {
                            testClient(engine = {
                                observability {
                                    eventListener =
                                        object : KuicksilverEventListener() {
                                            override fun retry(
                                                request: io.ktor.client.request.HttpRequestData,
                                                attempt: Int,
                                                cause: Throwable,
                                            ) {
                                                retries.addAndFetch(1)
                                            }
                                        }
                                }
                            }).use { it.get("https://127.0.0.1:$port/") }
                        }
                    assertIs<Http2Exception.ConnectionClosed>(e, "round $round: $e")
                    assertEquals("the connection was lost: $alert", e.message, "round $round")
                    assertIs<TlsException.AlertReceived>(generateSequence<Throwable>(e) { it.cause }.last(), "round $round: $e")
                    assertEquals(0, retries.load(), "round $round: a call lost to a TLS alert is not repeated")
                }
            }
        }

    @Test fun negative_overHttp3TheCallNamesTheAlert() =
        h3Test {
            withServer(http2 = true) { port ->
                repeat(ROUNDS) { round ->
                    val e = assertFails { testClient(Http3Discovery.H3Only).use { it.get("https://127.0.0.1:$port/") } }
                    assertIs<QuicException.ConnectionLost.TransportClosed>(e, "round $round: $e")
                    assertEquals(0x0174L, e.code, "round $round: CRYPTO_ERROR 0x0100 + 116")
                    val received = assertIs<TlsException.AlertReceived>(e.cause, "round $round: $e")
                    assertEquals(alert, received.message, "round $round")
                }
            }
        }

    private suspend fun withServer(
        http2: Boolean,
        block: suspend (port: Int) -> Unit,
    ) {
        val (server, port) =
            testServer(configure = { http2 { enabled = http2 } }, tls = {
                tls {
                    clientAuth = ClientAuth.Required
                    clientTrust = ClientFixtures.trust
                }
            }) {
                routing { get("/") { call.respondText("unreachable") } }
            }
        try {
            block(port)
        } finally {
            server.stopSuspend(100, 1000)
        }
    }

    private companion object {
        const val ROUNDS = 8
    }
}
