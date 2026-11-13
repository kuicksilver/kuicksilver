// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.get
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import io.ktor.websocket.Frame
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.io.readByteArray
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** How an HTTP/3 WebSocket session ends (RFC 9220), the same with Ktor's JVM and common (Native) WebSocket readers. */
class ClientH3WebSocketTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * The server's FIN can trail its Close frame (the core sends a flushed frame at once, the FIN with the close): a client
     * whose closing handshake ends before that FIN arrives still delivers its Close reply and FIN, and abandons only the
     * read side (STOP_SENDING), never its own finished send side (RESET_STREAM). Ordered here by holding the FIN back.
     * On every platform: Ktor's JVM WebSocket reader stops at the Close frame, and the engine ends the stream it hands to the
     * common (Native) reader after the peer's Close frame too, so a session never waits for a FIN that does not come.
     */
    @Test fun webSocketClosedBeforeThePeersFinKeepsItsCloseReply() =
        h3Test {
            val serverTls =
                tlsConfig(TlsRole.Server) {
                    alpn = listOf("h3")
                    identity =
                        TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
                }
            val ep =
                Http3Endpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig.Builder(serverTls).build()
                        }.build(),
                    io.kuicksilver.http3.http3Settings { enableConnectProtocol = true },
                )
            val clientDone = CompletableDeferred<Unit>()
            coroutineScope {
                val served =
                    async {
                        val conn = ep.accept()
                        val s = conn.acceptRequest().acceptConnect()
                        s.output.writeFully(byteArrayOf(0x88.toByte(), 0x02, 0x03, 0xE8.toByte()))
                        s.output.flush() // Close(1000) without FIN: the FIN follows only after the client's call is over
                        clientDone.await()
                        val read =
                            runCatching {
                                s.input
                                    .readBuffer()
                                    .readByteArray()
                                    .size
                            }
                        runCatching { s.output.flushAndClose() }
                        read
                    }
                try {
                    testClient(Http3DiscoveryMode.H3Only, block = { install(WebSockets) }).use { c ->
                        // the session ends on the Close exchange, not on the FIN
                        withTimeout(
                            10.seconds,
                        ) { c.webSocket("wss://127.0.0.1:${ep.localAddress.port}/ws") { for (f in incoming) continue } }
                        clientDone.complete(Unit)
                        val got = withTimeout(5.seconds) { served.await() }
                        assertTrue(got.isSuccess && got.getOrThrow() >= 6, "the server reads the client's Close reply and FIN, got $got")
                    }
                } finally {
                    served.cancel()
                    ep.close()
                }
            }
        }

    /**
     * RFC 6455 section 5.3 over HTTP/3: the engine gives Ktor's session `masking = false` and masks every frame itself,
     * each with a new key from the CSPRNG.
     */
    @Test fun negative_clientEngineMasksEveryFrameWithANewKeyH3() =
        h3Test {
            val serverTls =
                tlsConfig(TlsRole.Server) {
                    alpn = listOf("h3")
                    identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
                }
            val ep =
                Http3Endpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig
                        .Builder()
                        .apply { this.server = QuicServerConfig.Builder(serverTls).build() }
                        .build(),
                    io.kuicksilver.http3.http3Settings { enableConnectProtocol = true },
                )
            var sessionMasking: Boolean? = null
            coroutineScope {
                val served =
                    async {
                        val s = ep.accept().acceptRequest().acceptConnect()
                        List(3) {
                            val b1 = s.input.readByteArray(2)[1].toInt() and 0xff
                            val mask = s.input.readByteArray(4)
                            val payload = s.input.readByteArray(b1 and 0x7f)
                            assertTrue(b1 and 0x80 != 0, "masked")
                            val text =
                                payload
                                    .mapIndexed {
                                        i,
                                        b,
                                        ->
                                        (b.toInt() xor mask[i % 4].toInt()).toByte()
                                    }.toByteArray()
                                    .decodeToString()
                            assertEquals("m$it", text)
                            mask.toList()
                        }.also {
                            runCatching {
                                s.output.writeFully(byteArrayOf(0x88.toByte(), 0x02, 0x03, 0xE8.toByte()))
                                s.output.flush()
                            }
                        }
                    }
                try {
                    testClient(Http3DiscoveryMode.H3Only, block = { install(WebSockets) }).use { c ->
                        withTimeout(10.seconds) {
                            c.webSocket("wss://127.0.0.1:${ep.localAddress.port}/ws") {
                                sessionMasking = masking
                                repeat(3) { send(Frame.Text("m$it")) }
                                for (f in incoming) continue
                            }
                        }
                    }
                    val keys = withTimeout(5.seconds) { served.await() }
                    assertEquals(3, keys.toSet().size, "a new key for every frame: $keys")
                    assertEquals(false, sessionMasking, "Ktor's session does not mask")
                } finally {
                    served.cancel()
                    ep.close()
                }
            }
        }

    /**
     * RFC 6455 section 4.1 step 2 over HTTP/3: "There MUST be no more than one connection in a CONNECTING state." While
     * the server holds back its answer to a first WebSocket's Extended CONNECT, a second WebSocket to the same host waits
     * (the engine's per-host lock, shared with HTTP/1.1) and its CONNECT reaches the server only after the first was
     * answered. Before, both handshakes were in flight at once over HTTP/3.
     */
    @Test fun negative_secondHandshakeToTheSameHostWaitsForTheFirstH3() =
        h3Test {
            val serverTls =
                tlsConfig(TlsRole.Server) {
                    alpn = listOf("h3")
                    identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
                }
            val ep =
                Http3Endpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig
                        .Builder()
                        .apply { this.server = QuicServerConfig.Builder(serverTls).build() }
                        .build(),
                    io.kuicksilver.http3.http3Settings { enableConnectProtocol = true },
                )
            val firstArrived = CompletableDeferred<Unit>()
            val answerFirst = CompletableDeferred<Unit>()
            var firstAnswered = false
            var secondArrivedAfterFirstAnswer: Boolean? = null
            val close = byteArrayOf(0x88.toByte(), 0x02, 0x03, 0xE8.toByte())
            coroutineScope {
                val served =
                    async {
                        val conn = ep.accept()
                        val first = conn.acceptRequest()
                        firstArrived.complete(Unit)
                        answerFirst.await()
                        val s1 = first.acceptConnect()
                        firstAnswered = true
                        val second = conn.acceptRequest()
                        secondArrivedAfterFirstAnswer = firstAnswered
                        val s2 = second.acceptConnect()
                        for (s in listOf(s1, s2)) {
                            s.output.writeFully(close)
                            s.output.flush()
                        }
                    }
                try {
                    testClient(Http3DiscoveryMode.H3Only, block = { install(WebSockets) }).use { c ->
                        val engine = c.engine as KuicksilverEngine
                        val url = "wss://127.0.0.1:${ep.localAddress.port}/ws"
                        coroutineScope {
                            launch { withTimeout(10.seconds) { c.webSocket(url) { for (f in incoming) continue } } }
                            firstArrived.await()
                            launch { withTimeout(10.seconds) { c.webSocket(url) { for (f in incoming) continue } } }
                            // the second WebSocket waits for the host: an event, not a window of real time
                            withTimeout(10.seconds) {
                                engine.h1.webSocketConnecting.waitsForTest
                                    .first { it >= 1 }
                            }
                            answerFirst.complete(Unit)
                        }
                    }
                    withTimeout(5.seconds) { served.await() }
                    assertEquals(
                        true,
                        secondArrivedAfterFirstAnswer,
                        "the second CONNECT reached the server only after the first was answered",
                    )
                } finally {
                    served.cancel()
                    ep.close()
                }
            }
        }

    /**
     * A server that never answers the Extended CONNECT holds the host's lock for at most the connect timeout, as over
     * HTTP/1.1: the first WebSocket fails with `ConnectTimeoutException`, and the second one, which waited for the
     * host, then connects. Before, the CONNECT waited without a bound while holding the lock, so every later WebSocket
     * to the address, over HTTP/1.1 too, waited forever.
     */
    @Test fun negative_stalledHandshakeTimesOutAndFreesTheHostH3() =
        h3Test {
            val serverTls =
                tlsConfig(TlsRole.Server) {
                    alpn = listOf("h3")
                    identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
                }
            val ep =
                Http3Endpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig
                        .Builder()
                        .apply { this.server = QuicServerConfig.Builder(serverTls).build() }
                        .build(),
                    io.kuicksilver.http3.http3Settings { enableConnectProtocol = true },
                )
            val firstArrived = CompletableDeferred<Unit>()
            coroutineScope {
                val served =
                    async {
                        val conn = ep.accept()
                        conn.acceptRequest() // never answered
                        firstArrived.complete(Unit)
                        val s = conn.acceptRequest().acceptConnect()
                        s.output.writeFully(byteArrayOf(0x88.toByte(), 0x02, 0x03, 0xE8.toByte()))
                        s.output.flush()
                    }
                try {
                    testClient(
                        Http3DiscoveryMode.H3Only,
                        engine = { connectTimeout = 500.milliseconds },
                        block = { install(WebSockets) },
                    ).use { c ->
                        val engine = c.engine as KuicksilverEngine
                        val url = "wss://127.0.0.1:${ep.localAddress.port}/ws"
                        coroutineScope {
                            val first = async { runCatching { c.webSocket(url) { for (f in incoming) continue } } }
                            firstArrived.await()
                            val second = async { withTimeout(10.seconds) { c.webSocket(url) { for (f in incoming) continue } } }
                            val failure = withTimeout(10.seconds) { first.await() }.exceptionOrNull()
                            assertTrue(failure is io.ktor.client.network.sockets.ConnectTimeoutException, "the first: $failure")
                            second.await()
                        }
                        assertEquals(0, engine.h1.webSocketConnecting.size(), "the host is free again")
                    }
                    withTimeout(5.seconds) { served.await() }
                } finally {
                    served.cancel()
                    ep.close()
                }
            }
        }

    /**
     * RFC 9114 section 5.2 with RFC 9220: after the server's GOAWAY a connection takes no new request, so it does not count
     * as one that can carry a WebSocket's Extended CONNECT, even while it is still open (a request in flight) and its
     * SETTINGS allow Extended CONNECT. Before, it counted, and the WebSocket was sent to HTTP/3 on its strength.
     */
    @Test fun negative_goAwayConnectionDoesNotCountForExtendedConnect() =
        h3Test {
            val serverTls =
                tlsConfig(TlsRole.Server) {
                    alpn = listOf("h3")
                    identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
                }
            val ep =
                Http3Endpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig
                        .Builder()
                        .apply { this.server = QuicServerConfig.Builder(serverTls).build() }
                        .build(),
                    io.kuicksilver.http3.http3Settings { enableConnectProtocol = true },
                )
            val release = CompletableDeferred<Unit>()
            val requested = CompletableDeferred<Unit>()
            coroutineScope {
                val served =
                    launch {
                        val conn = ep.accept()
                        val held = conn.acceptRequest() // in flight: the connection stays open after the GOAWAY
                        requested.complete(Unit)
                        conn.goAway()
                        release.await()
                        held.respond(200).finish()
                    }
                try {
                    testClient(Http3DiscoveryMode.H3Only).use { c ->
                        val engine = c.engine as KuicksilverEngine
                        val port = ep.localAddress.port
                        val target =
                            io.kuicksilver.ktor.client.h3
                                .H3Target("127.0.0.1", "127.0.0.1", port)
                        val held = async { c.get("https://127.0.0.1:$port/hold") }
                        withTimeout(10.seconds) { requested.await() } // the request went out on the pooled connection
                        val conn = engine.h3.connectionsForTest().single()
                        withTimeout(10.seconds) { conn.goAwayReceived.first { it != null } }
                        assertEquals(true, conn.peerSettings.value?.enableConnectProtocol, "the server allows Extended CONNECT")
                        assertTrue(!conn.closed.isCompleted, "still open: a request is in flight")
                        assertTrue(!engine.h3.canConnectProtocol(target), "a connection after GOAWAY carries no new Extended CONNECT")
                        release.complete(Unit)
                        assertEquals(200, withTimeout(10.seconds) { held.await() }.status.value)
                    }
                } finally {
                    release.complete(Unit)
                    served.cancel()
                    ep.close()
                }
            }
        }
}
