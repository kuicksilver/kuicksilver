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

    /**
     * Preferred mode (docs/guide/engine-tls.md, mutual TLS): HTTP/3 fails with the alert, the call goes on over TCP and fails
     * there as over TCP, with no suppressed exceptions (the TCP setup did not fail) and a `raceEnded` that names HTTP/2,
     * whatever the order: the alert ends the new HTTP/2 connection after the request got its stream, or before
     * ([io.kuicksilver.ktor.client.h1.H1Pool.afterH2StartForTest] waits for the connection's end, as a slow host does).
     */
    @Test fun negative_preferredFailsAsOverTcpWhicheverOrder() =
        h3Test {
            withServer(http2 = true) { port ->
                for (lostBeforeStream in listOf(false, true)) {
                    repeat(ROUNDS / 2) { round ->
                        val at = "lostBeforeStream=$lostBeforeStream, round $round"
                        val races =
                            kotlin.concurrent.atomics.AtomicReference(
                                emptyList<Pair<io.ktor.http.HttpProtocolVersion, Throwable?>>(),
                            )
                        val e =
                            assertFails {
                                testClient(Http3Discovery.Preferred, engine = {
                                    observability {
                                        eventListener =
                                            object : KuicksilverEventListener() {
                                                override fun raceEnded(
                                                    request: io.ktor.client.request.HttpRequestData,
                                                    winner: io.ktor.http.HttpProtocolVersion,
                                                    headStart: kotlin.time.Duration,
                                                    h3Failure: Throwable?,
                                                ) {
                                                    while (true) {
                                                        val l = races.load()
                                                        if (races.compareAndSet(l, l + (winner to h3Failure))) break
                                                    }
                                                }
                                            }
                                    }
                                }).use { c ->
                                    if (lostBeforeStream) {
                                        (c.engine as KuicksilverEngine).h1.afterH2StartForTest = { client, _ -> client.awaitClosed() }
                                    }
                                    c.get("https://127.0.0.1:$port/")
                                }
                            }
                        assertIs<Http2Exception.ConnectionClosed>(e, "$at: $e")
                        assertEquals("the connection was lost: $alert", e.message, at)
                        assertIs<TlsException.AlertReceived>(generateSequence<Throwable>(e) { it.cause }.last(), "$at: $e")
                        assertEquals(emptyList(), e.suppressedExceptions.filter { it !is FailureDiagnostics }, "$at: $e")
                        val (winner, h3Failure) = races.load().singleOrNull() ?: kotlin.test.fail("$at: one raceEnded, got ${races.load()}")
                        assertEquals(io.ktor.http.HttpProtocolVersion.HTTP_2_0, winner, at)
                        // HTTP/3 had failed with the alert (CRYPTO_ERROR 0x0100 + 116), or had not answered yet
                        assertTrue(
                            h3Failure == null || (h3Failure is QuicException.ConnectionLost.TransportClosed && h3Failure.code == 0x0174L),
                            "$at: $h3Failure",
                        )
                    }
                }
            }
        }

    /** What a failed call said through the event listener, in order. */
    private class Said : KuicksilverEventListener() {
        val events = kotlin.concurrent.atomics.AtomicReference(emptyList<String>())

        private fun add(e: String) {
            while (true) {
                val l = events.load()
                if (events.compareAndSet(l, l + e)) break
            }
        }

        override fun protocolSelected(
            request: io.ktor.client.request.HttpRequestData,
            protocol: io.ktor.http.HttpProtocolVersion,
            reason: ProtocolReason,
        ) = add("protocolSelected $protocol $reason")

        override fun connectionAcquired(
            request: io.ktor.client.request.HttpRequestData,
            protocol: io.ktor.http.HttpProtocolVersion,
            reused: Boolean,
        ) = add("connectionAcquired $protocol reused=$reused")

        override fun connectionReleased(
            request: io.ktor.client.request.HttpRequestData,
            protocol: io.ktor.http.HttpProtocolVersion,
            kept: Boolean,
        ) = add("connectionReleased $protocol kept=$kept")
    }

    /**
     * The call's events and diagnostics do not hang on the order either, over TCP alone and in Preferred mode: whether the
     * alert ends the new HTTP/2 connection after the request got its stream or before, the call says protocolSelected
     * HTTP/2, connectionAcquired and connectionReleased once each, and its diagnostics name the same reason and an HTTP/2
     * connection.
     */
    @Test fun negative_theCallSaysTheSameWhicheverOrder() =
        h3Test {
            withServer(http2 = true) { port ->
                for (discovery in listOf<Http3Discovery?>(null, Http3Discovery.Preferred)) {
                    val seen =
                        listOf(false, true).map { lostBeforeStream ->
                            val at = "discovery=$discovery, lostBeforeStream=$lostBeforeStream"
                            val said = Said()
                            val e =
                                assertFails {
                                    testClient(discovery, engine = { observability { eventListener = said } }).use { c ->
                                        if (lostBeforeStream) {
                                            (c.engine as KuicksilverEngine).h1.afterH2StartForTest = { client, _ -> client.awaitClosed() }
                                        }
                                        c.get("https://127.0.0.1:$port/")
                                    }
                                }
                            assertEquals("the connection was lost: $alert", e.message, "$at: $e")
                            val d =
                                e.suppressedExceptions
                                    .filterIsInstance<FailureDiagnostics>()
                                    .single()
                                    .diagnostics
                            val connection = assertIs<TcpConnectionSnapshot>(d.connection, "$at: $d")
                            assertEquals(io.ktor.http.HttpProtocolVersion.HTTP_2_0, connection.protocol, at)
                            assertEquals("h2", connection.alpn, at)
                            val events = said.events.load()
                            assertEquals(1, events.count { it.startsWith("protocolSelected HTTP/2.0") }, "$at: $events")
                            assertEquals(1, events.count { it.startsWith("connectionAcquired HTTP/2.0") }, "$at: $events")
                            assertEquals(1, events.count { it.startsWith("connectionReleased HTTP/2.0") }, "$at: $events")
                            Triple(events.filter { it.startsWith("protocolSelected") }, d.reason, d.transport)
                        }
                    assertEquals(seen[0], seen[1], "discovery=$discovery: after the stream, then before it")
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
