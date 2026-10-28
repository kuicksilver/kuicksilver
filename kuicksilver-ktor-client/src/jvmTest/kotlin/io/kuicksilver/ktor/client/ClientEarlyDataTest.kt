// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.ktor.server.receivedEarly
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.async
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/** 0-RTT between the Kuicksilver engines when both opt in (ADR-0015). */
@OptIn(ExperimentalKuicksilverApi::class)
class ClientEarlyDataTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun reconnectResumesWith0Rtt() =
        clientTest {
            val (server, port) =
                testServer(configure = { quicEarlyData = true }) {
                    routing {
                        get("/") { call.respondText("get early=${call.request.receivedEarly}") }
                        post("/") { call.respondText("post early=${call.request.receivedEarly}") }
                    }
                }
            try {
                testClient(Http3DiscoveryMode.H3Only, engine = { http3 { earlyData = true } }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    val first = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_3_0, first.version)
                    assertEquals("get early=false", first.bodyAsText())
                    assertEquals("get early=false", c.get("https://127.0.0.1:$port/").bodyAsText()) // the ticket arrived meanwhile
                    assertEquals(
                        null,
                        engine.h3
                            .connectionsForTest()
                            .single()
                            .quic.earlyDataAccepted,
                        "a full handshake",
                    )
                    engine.h3.dropConnectionsForTest().forEach { it.close() }
                    val again = c.get("https://127.0.0.1:$port/").bodyAsText()
                    assertTrue(again == "get early=true" || again == "get early=false", again) // early only when it beat the handshake
                    val conn = engine.h3.connectionsForTest().single()
                    conn.quic.awaitHandshake()
                    assertEquals(true, conn.quic.earlyDataAccepted, "the reconnect resumed with 0-RTT")
                    assertEquals("post early=false", c.post("https://127.0.0.1:$port/").bodyAsText(), "a POST never runs early")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * The server rejects the 0-RTT (a restarted server whose new ticket keys cannot open the client's ticket): RFC 9001
     * section 4.6.2, the client "MUST reset the state of all streams". The rejection closes the connection, the server
     * processed nothing of its 0-RTT, and the GET is sent again once, on a new connection without 0-RTT, over HTTP/3: no
     * fallback to HTTP/1.1, no alternative marked broken. Before 0.2.1 the transport sent the 0-RTT streams again in 1-RTT.
     */
    @Test fun rejected0RttIsRetriedOnANewConnectionWithout0Rtt() =
        h3Test {
            rejected0RttRetry(waitsForHandshake = false) { c, url -> c.get(url) }
        }

    /**
     * A POST with a streamed body as the first request on the 0-RTT connection waits for the handshake the rejection ends,
     * so its body was never touched: it is sent again on the new connection too, not failed as a consumed body.
     */
    @Test fun aStreamedUploadWaitingForTheHandshakeIsRetriedAfterARejected0Rtt() =
        h3Test {
            rejected0RttRetry(waitsForHandshake = true) { c, url ->
                c.post(url) {
                    setBody(
                        io.ktor.utils.io
                            .ByteReadChannel("payload"),
                    )
                }
            }
        }

    /** A rejected 0-RTT does not mark the alternative broken: it says nothing against the server's HTTP/3. */
    @Test fun aRejected0RttDoesNotMarkTheAlternativeBroken() {
        @OptIn(ExperimentalKuicksilverApi::class)
        val rejected =
            io.kuicksilver.quic.QuicException.ConnectionLost
                .ZeroRttRejected()
        assertFalse(
            marksAlternativeBroken(
                io.kuicksilver.ktor.client.h3
                    .H3NotSent(rejected),
            ),
        )
        assertTrue(
            marksAlternativeBroken(
                io.kuicksilver.ktor.client.h3
                    .H3NotSent(
                        io.kuicksilver.quic.QuicException.ConnectionLost
                            .StatelessReset(),
                    ),
            ),
        )
    }

    /**
     * A ticket from one server, then the same port served with other ticket keys, so the client's 0-RTT is rejected there;
     * [send] makes the first request on that new connection and must be answered "h3" over HTTP/3 after exactly one retry
     * for the rejection, with no fallback to HTTP/1.1.
     */
    private suspend fun rejected0RttRetry(
        waitsForHandshake: Boolean,
        send: suspend (io.ktor.client.HttpClient, String) -> io.ktor.client.statement.HttpResponse,
    ) = kotlinx.coroutines.coroutineScope {
        run {
            val retries = java.util.concurrent.CopyOnWriteArrayList<Throwable>()
            val fallbacks = java.util.concurrent.CopyOnWriteArrayList<Throwable>()
            val events =
                object : KuicksilverEventListener() {
                    override fun retry(
                        request: io.ktor.client.request.HttpRequestData,
                        attempt: Int,
                        cause: Throwable,
                    ) {
                        retries += cause
                    }

                    override fun fallback(
                        request: io.ktor.client.request.HttpRequestData,
                        cause: Throwable,
                    ) {
                        fallbacks += cause
                    }
                }
            var ep = h3Origin(earlyData = true, ticketKeys = io.kuicksilver.tls.SessionTicketConfig(keys = listOf(ByteArray(80) { 1 })))
            val port = ep.localAddress.port
            try {
                udpRelay(port) { front, relay ->
                    testClient(Http3DiscoveryMode.H3Only, engine = {
                        eventListener = events
                        http3 { earlyData = true }
                    }).use { c ->
                        val engine = c.engine as KuicksilverEngine
                        val url = "https://127.0.0.1:$front/"
                        assertEquals("h3", c.get(url).bodyAsText())
                        assertEquals("h3", c.get(url).bodyAsText()) // the ticket arrived meanwhile
                        engine.h3.dropConnectionsForTest().forEach { it.close() }
                        ep.close()
                        // the same port, other ticket keys: the client's ticket opens nothing there, so its 0-RTT is rejected
                        var next: io.kuicksilver.http3.Http3Endpoint? = null
                        for (i in 0 until 100) {
                            next =
                                runCatching {
                                    h3Origin(
                                        earlyData = true,
                                        port = port,
                                        ticketKeys = io.kuicksilver.tls.SessionTicketConfig(keys = listOf(ByteArray(80) { 2 })),
                                    )
                                }.getOrNull()
                            if (next != null) break
                            kotlinx.coroutines.delay(50)
                        }
                        ep = next ?: kotlin.test.fail("UDP $port could not be bound again")
                        // the server's answers are held: connectEarly returns on its 0-RTT keys, and the request starts on
                        // that connection (in 0-RTT, or waiting for the handshake) before any answer, the rejection
                        // included, reaches the client
                        relay.holdDown = true
                        val waiting = kotlinx.coroutines.CompletableDeferred<Unit>()
                        engine.h3.beforeHandshakeWaitForTest = { waiting.complete(Unit) }
                        val pending = async { send(c, url) }
                        withTimeout(20.seconds) {
                            while (engine.h3.connectionsForTest().isEmpty()) kotlinx.coroutines.delay(5) // acquire returned
                            if (waitsForHandshake) waiting.await()
                        }
                        relay.release()
                        val r = pending.await()
                        engine.h3.beforeHandshakeWaitForTest = null
                        assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                        assertEquals("h3", r.bodyAsText())
                        assertEquals(1, retries.size, "one retry: $retries")
                        // the GET rode 0-RTT and failed in its exchange; the POST waited for the handshake, unsent
                        if (waitsForHandshake) assertIs<io.kuicksilver.ktor.client.h3.H3NotSent>(retries.single())
                        assertTrue(
                            generateSequence(
                                retries.single(),
                            ) { it.cause }.any { it is io.kuicksilver.quic.QuicException.ConnectionLost.ZeroRttRejected },
                            "the retry was for the rejected 0-RTT: ${retries.single()}",
                        )
                        assertTrue(fallbacks.isEmpty(), "no fallback to HTTP/1.1: $fallbacks")
                        val conn = engine.h3.connectionsForTest().single()
                        assertTrue(conn.quic.isHandshakeComplete && !conn.closed.isCompleted, "the retry's connection stays")
                    }
                }
            } finally {
                ep.close()
            }
        }
    }

    /**
     * HTTP/3 works and a ticket is kept (TCP accepts nothing yet: a connection waits in the backlog, and HTTP/3 wins the
     * race), then QUIC is blocked on the path and HTTP/1.1 is served on TCP; it accepts connections only once the client's
     * first QUIC datagram was dropped, so the HTTP/3 setup has been under way first. Runs [phase2] with the URL, the client
     * and its engine. The TCP port is bound with the relay's UDP port, before the ticket names it: binding it only for
     * phase 2 failed with "Address already in use" whenever another process held that TCP port.
     */
    private suspend fun ticketThenUdpBlocked(
        connectTimeout: kotlin.time.Duration,
        networkId: () -> String?,
        onBlocked: () -> Unit = {},
        phase2: suspend (String, io.ktor.client.HttpClient, KuicksilverEngine) -> Unit,
    ) = kotlinx.coroutines.coroutineScope {
        val ep = h3Origin(earlyData = true)
        try {
            udpRelay(ep.localAddress.port, tcpTwin = true) { port, relay ->
                val url = "https://127.0.0.1:$port/"
                testClient(Http3DiscoveryMode.Preferred, engine = {
                    this.connectTimeout = connectTimeout
                    quic = io.kuicksilver.quic.quicConfig { handshakeTimeout = 30.seconds }
                    http3 {
                        earlyData = true
                        this.networkId = networkId
                    }
                }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    assertEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version)
                    assertEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version) // the ticket arrived meanwhile
                    engine.h3.dropConnectionsForTest().forEach { it.close() }
                    relay.blocked = true
                    onBlocked()
                    tlsH1WithSilentUdp(silentUdp = false, listener = relay.tcp, acceptAfter = relay.dropped, handler = { _, input, output ->
                        while (readRequest(input).isNotEmpty()) {
                            output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nh1")
                        }
                    }) { phase2(url, c, engine) }
                }
            }
        } finally {
            ep.close()
        }
    }

    /**
     * QUIC blocked on a network where it worked: the 0-RTT GET goes out at once (QUIC is known to work here), but the
     * connect timeout bounds the setup, and the request falls back to HTTP/1.1 then, not after the 30 s handshake timeout.
     */
    @Test fun udpBlockedWith0RttFallsBackWithinConnectTimeout() =
        h3Test {
            ticketThenUdpBlocked(3.seconds, { null }) { url, c, _ ->
                val t0 = TimeSource.Monotonic.markNow()
                val r = c.get(url)
                assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                assertEquals("h1", r.bodyAsText())
                assertTrue(t0.elapsedNow() < 15.seconds, "fell back after ${t0.elapsedNow()}")
            }
        }

    /**
     * A POST cannot go in 0-RTT: it waits for the handshake before any stream is opened, so a handshake that fails leaves it
     * provably unsent and it goes over HTTP/1.1 (as when the connection could not be set up at all).
     */
    @Test fun postWaitingForAFailedHandshakeFallsBack() =
        h3Test {
            ticketThenUdpBlocked(3.seconds, { null }) { url, c, _ ->
                val t0 = TimeSource.Monotonic.markNow()
                val r = c.post(url) { setBody("x") }
                assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                assertEquals("h1", r.bodyAsText())
                assertTrue(t0.elapsedNow() < 15.seconds, "fell back after ${t0.elapsedNow()}")
            }
        }

    /**
     * On a network where QUIC was never seen working, a 0-RTT connection does not win the race before the handshake
     * completes (as Chromium requires confirmation there): HTTP/1.1 wins at once, and QUIC is not recorded as working on
     * that network.
     */
    @Test fun earlyConnectionDoesNotWinTheRaceOnAnUnconfirmedNetwork() =
        h3Test {
            var network = "A"
            ticketThenUdpBlocked(20.seconds, { network }, onBlocked = { network = "B" }) { url, c, engine ->
                val t0 = TimeSource.Monotonic.markNow()
                val r = c.get(url)
                assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                assertEquals("h1", r.bodyAsText())
                assertTrue(t0.elapsedNow() < 10.seconds, "HTTP/1.1 waited ${t0.elapsedNow()}")
                assertFalse(engine.brokenAltSvc.quicConfirmedOn("B"), "QUIC confirmed on B without a handshake")
            }
        }
}
