// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.timeout
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.client.request.get
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
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
     * whose closing handshake ends before that FIN arrives delivers its Close reply at once and its FIN after the server's
     * (RFC 9220 section 3, RFC 6455 section 7.1.1), never a RESET_STREAM over the Close reply. Ordered here by holding the
     * server's FIN back until the client's call is over.
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
                        runCatching { s.output.flushAndClose() } // the server's FIN, then the client's
                        runCatching {
                            s.input
                                .readBuffer()
                                .readByteArray()
                                .size
                        }
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
     * Ktor's `webSocketSession()` cancels its call as soon as the session queued its Close (its builder takes the cancelled
     * outgoing channel for a failure). Here the writer is held at the server's flow control behind a large frame when that
     * happens: the stream is not reset, and once the server reads it gets the frame and then the Close with the
     * application's code and reason (RFC 6455 section 7.1.2). Before, the call's cancellation reset the stream and the
     * Close never left.
     */
    @Test fun closeQueuedBeforeTheCallIsCancelledIsWritten() =
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
            val reading = CompletableDeferred<Unit>()
            coroutineScope {
                val served =
                    async {
                        val conn = ep.accept()
                        val s = conn.acceptRequest().acceptConnect()
                        reading.await() // nothing is read before the client's call is over: its writer waits for credit
                        readClientFrames(s.input)
                    }
                try {
                    testClient(Http3DiscoveryMode.H3Only, block = { install(WebSockets) }).use { c ->
                        (c.engine as KuicksilverEngine).h3.webSocketCloseWaitMillis = 60_000
                        val session = c.webSocketSession("wss://127.0.0.1:${ep.localAddress.port}/ws")
                        session.outgoing.send(Frame.Binary(true, ByteArray(BIG)))
                        launch { session.close(CloseReason(4002, "client bye")) } // close() also waits for the writer
                        session.call.coroutineContext[Job]!!.join()
                        reading.complete(Unit)
                        assertEquals(listOf("binary $BIG", "close 4002 client bye"), withTimeout(BIG_TRANSFER_WAIT) { served.await() })
                    }
                } finally {
                    served.cancel()
                    ep.close()
                }
            }
        }

    /**
     * A server that reads nothing until the session was released: the session gets the close wait (200 ms here) to write
     * its Close, then the stream is reset (RESET_STREAM H3_REQUEST_CANCELLED, RFC 9220 section 3), so what its writer had
     * not written never leaves; the server finds the stream reset and no Close. As over HTTP/1.1
     * (`ClientWebSocketCloseTest.negative_anUnwrittenCloseIsBoundedByTheCloseWait`).
     */
    @Test fun negative_anUnwrittenCloseIsBoundedByTheCloseWaitH3() =
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
            // every attempt's decision in order, with what it was made from: the server reads nothing, so no session ends
            // in order
            val ends = kotlinx.coroutines.channels.Channel<String>(kotlinx.coroutines.channels.Channel.UNLIMITED)
            try {
                val read =
                    unwrittenCloseAttempts { data, frames ->
                        val released = CompletableDeferred<Unit>()
                        val listener =
                            object : KuicksilverEventListener() {
                                override fun connectionReleased(
                                    request: io.ktor.client.request.HttpRequestData,
                                    protocol: io.ktor.http.HttpProtocolVersion,
                                    kept: Boolean,
                                ) {
                                    released.complete(Unit)
                                }
                            }
                        coroutineScope {
                            val served =
                                async {
                                    val conn = ep.accept()
                                    val s = conn.acceptRequest().acceptConnect()
                                    released.await() // reads nothing before the client gave the stream up
                                    readClientFrames(s.input)
                                }
                            try {
                                testClient(Http3DiscoveryMode.H3Only, engine = { eventListener = listener }, block = {
                                    install(WebSockets)
                                }).use { c ->
                                    (c.engine as KuicksilverEngine).h3.webSocketCloseWaitMillis = 200
                                    (c.engine as KuicksilverEngine).h3.webSocketEndForTest = { end, writerDone, boundary ->
                                        ends.trySend("$end writerDone=$writerDone boundary=$boundary")
                                    }
                                    val session = c.webSocketSession("wss://127.0.0.1:${ep.localAddress.port}/ws")
                                    repeat(frames) { session.outgoing.send(Frame.Binary(true, data)) }
                                    launch { session.close(CloseReason(4002, "client bye")) }
                                    session.call.coroutineContext[Job]!!.join()
                                    withTimeout(10.seconds) { released.await() }
                                    withTimeout(20.seconds) { served.await() }
                                }
                            } finally {
                                served.cancel()
                            }
                        }
                    }
                assertEquals("reset", read.last(), "the stream was reset, not ended with a FIN: $read")
                // the attempt whose Close stayed unwritten (the last one) was reset, also when its writer ended its channel
                // inside a frame (Ktor's writer does so when cancelled): never a FIN after a cut frame. An earlier attempt
                // whose writing the transport took whole, its Close in flight, rightly got a FIN; it is not checked here
                val decided = generateSequence { ends.tryReceive().getOrNull() }.toList()
                assertTrue(decided.lastOrNull()?.startsWith("Reset") == true, "the last attempt's stream reset: $decided")
            } finally {
                ep.close()
            }
        }

    /**
     * The pool counts a WebSocket's connection as in use until the session ended, not until its call did: a connection
     * retired while a session lingers after its call (its Close still held at the server's flow control) is not closed
     * under it. Before, the pool's count fell to 0 at the call's end and the retired connection closed at once, with the
     * Close unsent.
     */
    @Test fun aRetiredConnectionKeepsALingeringSession() =
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
            val reading = CompletableDeferred<Unit>()
            coroutineScope {
                val served =
                    async {
                        val conn = ep.accept()
                        val s = conn.acceptRequest().acceptConnect()
                        reading.await() // nothing is read before the client's call is over: its writer waits for credit
                        readClientFrames(s.input)
                    }
                try {
                    testClient(Http3DiscoveryMode.H3Only, block = { install(WebSockets) }).use { c ->
                        (c.engine as KuicksilverEngine).h3.webSocketCloseWaitMillis = 60_000
                        val session = c.webSocketSession("wss://127.0.0.1:${ep.localAddress.port}/ws")
                        session.outgoing.send(Frame.Binary(true, ByteArray(BIG)))
                        launch { session.close(CloseReason(4002, "client bye")) } // close() also waits for the writer
                        session.call.coroutineContext[Job]!!.join()
                        // the connection is retired (this client's GOAWAY) while the session still holds it: it closes only
                        // once the session ended, not at once because the call is over
                        (c.engine as KuicksilverEngine).closeHttp3Connections()
                        reading.complete(Unit)
                        assertEquals(listOf("binary $BIG", "close 4002 client bye"), withTimeout(BIG_TRANSFER_WAIT) { served.await() })
                    }
                } finally {
                    served.cancel()
                    ep.close()
                }
            }
        }

    /**
     * `close(reason)` and then `client.close()` at once, the writer held at the server's flow control, which the server
     * opens right after: the engine's cleanup (the HTTP/3 connections, the endpoint) waits for the session to write its
     * Close and end. Before, the cleanup closed the connection under it and the server never saw the Close.
     */
    @Test fun clientCloseWaitsForTheSessionsClose() = clientCloseWithAHeldWriter(serverReads = true)

    /**
     * The same against a server that takes nothing (it gives no flow-control credit): the session
     * has not written its Close, so the engine's close does not cut it short; it keeps its close wait (T1, 1 s here), and
     * only then is it cut and the stream reset. The cleanup waits for that, not longer. Its Close never left: the
     * server took none of the stream.
     */
    @Test fun negative_clientCloseLeavesAWriterTheServerTakesNothingFromItsCloseWait() =
        clientCloseWithAHeldWriter(serverReads = false, closeWait = 1_000)

    /**
     * The same with `client.close()` late in T1 (1.5 s into a 2 s close wait): the session still ends at its T1, counted
     * from its own Close, and the stream reset; the engine's close starts no close wait of its own.
     */
    @Test fun negative_aLateClientCloseEndsAWriterTheServerTakesNothingFromAtItsT1() =
        clientCloseWithAHeldWriter(serverReads = false, closeWait = 2_000, closeAt = 1_500.milliseconds)

    /**
     * A server that reads slowly but steadily as the client is closed (256 KiB every 30 ms with a 16 MiB frame; 64 KiB
     * every 200 or 50 ms with 1 MiB, where the stream's credit comes in coarse steps): the writer is not cut (the
     * engine's close cuts no writer that has not written its Close; the close wait bounds it), so the frame arrives whole
     * and the Close after it, with no reset.
     */
    @Test fun clientCloseLetsAServerReading256KiBPer30msTakeTheFrameAndTheClose() =
        clientCloseWithAHeldWriter(serverReads = true, throttle = 256 * 1024 to 30.milliseconds)

    @Test fun clientCloseLetsAServerReading64KiBPer200msTakeTheFrameAndTheClose() =
        clientCloseWithAHeldWriter(serverReads = true, size = 1 shl 20, throttle = 64 * 1024 to 200.milliseconds)

    @Test fun clientCloseLetsAServerReading64KiBPer50msTakeTheFrameAndTheClose() =
        clientCloseWithAHeldWriter(serverReads = true, size = 1 shl 20, throttle = 64 * 1024 to 50.milliseconds)

    private fun clientCloseWithAHeldWriter(
        serverReads: Boolean,
        size: Int = BIG,
        throttle: Pair<Int, kotlin.time.Duration>? = null,
        closeWait: Long = 60_000,
        closeAt: kotlin.time.Duration? = null,
    ) = h3Test {
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
        val reading = CompletableDeferred<Unit>()
        coroutineScope {
            val served =
                async {
                    val conn = ep.accept()
                    val s = conn.acceptRequest().acceptConnect()
                    reading.await() // nothing is read before the client's call is over: its writer waits for credit
                    val frames = readClientFrames(throttle?.let { (n, p) -> throttled(s.input, n, p) } ?: s.input)
                    // the server's Close and FIN end the session (and with it the engine's wait); a stream the client reset
                    // takes neither
                    runCatching {
                        s.output.writeFully(byteArrayOf(0x88.toByte(), 0x02, 0x03, 0xE8.toByte()))
                        s.output.flushAndClose()
                    }
                    frames
                }
            try {
                testClient(Http3DiscoveryMode.H3Only, block = { install(WebSockets) }).let { c ->
                    (c.engine as KuicksilverEngine).h3.webSocketCloseWaitMillis = closeWait
                    val session = c.webSocketSession("wss://127.0.0.1:${ep.localAddress.port}/ws")
                    session.outgoing.send(Frame.Binary(true, ByteArray(size)))
                    val started =
                        kotlin.time.TimeSource.Monotonic
                            .markNow()
                    launch { session.close(CloseReason(4002, "client bye")) } // close() also waits for the writer
                    session.call.coroutineContext[Job]!!.join()
                    closeAt?.let { kotlinx.coroutines.delay(it) } // a close late in T1
                    c.close()
                    if (serverReads) {
                        reading.complete(Unit)
                        assertEquals(listOf("binary $size", "close 4002 client bye"), withTimeout(BIG_TRANSFER_WAIT) { served.await() })
                        withTimeout(20.seconds) { (c.engine as KuicksilverEngine).cleanup.join() }
                    } else {
                        // not cut short by the engine's close: the session keeps its close wait
                        kotlin.test.assertNull(
                            kotlinx.coroutines.withTimeoutOrNull((if (closeAt == null) closeWait / 2 else 0L).milliseconds) {
                                (c.engine as KuicksilverEngine).cleanup.join()
                            },
                        )
                        withTimeout((closeWait + 10_000).milliseconds) { (c.engine as KuicksilverEngine).cleanup.join() }
                        // a close late in T1 ends the session at its T1 all the same, not a close wait after the engine's close
                        if (closeAt != null) {
                            val took = started.elapsedNow()
                            assertTrue(
                                took < (closeWait + 1_000).milliseconds,
                                "the cleanup ended $took after the own Close; T1 is $closeWait ms",
                            )
                        }
                        reading.complete(Unit)
                        val frames = runCatching { withTimeout(BIG_TRANSFER_WAIT) { served.await() } }
                        assertTrue(
                            frames.getOrNull()?.none { it.startsWith("close") } ?: true,
                            "the Close of a cut writer left: $frames",
                        )
                    }
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
     *
     * The connect timeout also bounds the QUIC handshake, so a request answered first sets the connection up outside it:
     * on a loaded host (a Windows VM) the handshake took longer than the 500 ms, the first WebSocket failed before its
     * CONNECT was sent, and the test waited for that CONNECT until its own 60 s ran out. The second WebSocket's answer
     * has its own, longer connect timeout for the same reason; only the first one's wait is under test. Nothing waits for
     * the first's CONNECT to reach the server either (the server tells the two apart by path): the second starts once the
     * first holds the host, so a slow host changes when things happen, never the outcome.
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
            coroutineScope {
                val served =
                    async {
                        val conn = ep.accept()
                        // the set-up: a 204 has no content, so the client's call is over with its HEADERS and it may abandon
                        // the stream (STOP_SENDING with H3_REQUEST_CANCELLED, RFC 9114 section 4.1.1) before the FIN goes
                        // out, which fails the finish (a slow host); the client checks the 204 itself
                        val setUp = conn.acceptRequest()
                        val answer = setUp.respond(204, io.kuicksilver.http3.Http3Headers(emptyList()))
                        runCatching { answer.finish() }
                        // the first's CONNECT is never answered, whenever it arrives (or if it never does: its client can
                        // give up before it is sent); the second's is
                        while (true) {
                            val r = conn.acceptRequest()
                            if (r.path != "/second") continue
                            val s = r.acceptConnect()
                            s.output.writeFully(byteArrayOf(0x88.toByte(), 0x02, 0x03, 0xE8.toByte()))
                            s.output.flush()
                            break
                        }
                    }
                try {
                    testClient(
                        Http3DiscoveryMode.H3Only,
                        engine = { connectTimeout = 500.milliseconds },
                        block = {
                            install(WebSockets)
                            install(HttpTimeout)
                        },
                    ).use { c ->
                        val engine = c.engine as KuicksilverEngine
                        val url = "wss://127.0.0.1:${ep.localAddress.port}"
                        // the connection is set up (and SETTINGS seen) with a longer connect timeout than the one under test
                        val setUp =
                            c.get("https://127.0.0.1:${ep.localAddress.port}/") {
                                timeout { connectTimeoutMillis = 10_000 }
                            }
                        assertEquals(204, setUp.status.value)
                        coroutineScope {
                            val connecting = engine.h1.webSocketConnecting
                            val before = connecting.acquiredForTest.value
                            val first = async { runCatching { c.webSocket("$url/first") { for (f in incoming) continue } } }
                            // the second starts once the first holds the host: what is under test is how long the first
                            // holds it (its connect timeout), not how fast its CONNECT reaches the server
                            withTimeout(10.seconds) { connecting.acquiredForTest.first { it > before } }
                            val second =
                                async {
                                    withTimeout(10.seconds) {
                                        c.webSocket("$url/second", request = {
                                            timeout { connectTimeoutMillis = 10_000 }
                                        }) { for (f in incoming) continue }
                                    }
                                }
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

    private companion object {
        /** Far more than the server's stream window and the client's send buffer take before the writer waits. */
        const val BIG = 16 shl 20

        /**
         * How long the server may take to read [BIG] and the Close: a guard against a hang, under the test's own 60 s. About
         * a second on a laptop; on a loaded Windows VM (the JVM suites beside a busy host) it passed 20 s.
         */
        val BIG_TRANSFER_WAIT = 45.seconds
    }
}
