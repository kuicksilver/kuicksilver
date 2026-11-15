// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.client.request.get
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.discard
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.CloseReason
import io.ktor.websocket.close
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.ktor.network.bindTcp
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.TlsConnection
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The order in which a client WebSocket ends its transport (RFC 6455 sections 5.5.1 and 7.1.1; RFC 8441 section 5 and RFC
 * 9220 section 3 for HTTP/2 and HTTP/3): the property under test is that the client never closes its side of the
 * transport (TCP FIN, close_notify, END_STREAM, FIN) before the server closed its own, closes it after the server did,
 * within T2, and, against a server that never closes, closes it cleanly at T2 (a FIN, never a reset; a stream reset or
 * STOP_SENDING only one close wait after that). Every case runs with the client's Close first and with the server's.
 *
 * The servers record what reaches them as events in order; the engine's test hooks say when the client waits for the
 * server's close ("waiting"), and whether that close came ("server closed" / "server ended") or T2 passed ("T2").
 */
class ClientWebSocketCloseOrderTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** What reached one side, in order. */
    private class Events {
        val all = MutableStateFlow(emptyList<String>())

        private val start =
            kotlin.time.TimeSource.Monotonic
                .markNow()
        val timed = MutableStateFlow(emptyList<String>())

        operator fun plusAssign(e: String) {
            timed.update { it + "$e@${start.elapsedNow().inWholeMilliseconds}" }
            all.update { it + e }
        }

        suspend fun await(e: String) = withTimeout(20.seconds) { all.first { e in it } }

        fun has(e: String) = e in all.value

        /**
         * A slow server: it holds its close for [SLOW_SERVER] after the client said it waits; nothing of the client's close
         * (an event starting with "client") may come meanwhile. Fails with what came.
         */
        suspend fun assertClientQuietWhileServerHolds() {
            val early = kotlinx.coroutines.withTimeoutOrNull(SLOW_SERVER) { all.first { l -> l.any { it.startsWith("client") } } }
            kotlin.test.assertNull(early, "the client closed its side before the server: ${timed.value}")
        }

        fun before(
            a: String,
            b: String,
        ): Boolean = all.value.indexOf(a).let { it >= 0 && it < all.value.indexOf(b) }
    }

    /** An HTTP/1.1 WebSocket connection as the raw server sees it: plaintext channels, its own close, its events. */
    private class RawConnection(
        val input: ByteReadChannel,
        val output: ByteWriteChannel,
        val events: Events,
        val watchEnd: () -> Unit,
        val close: suspend () -> Unit,
        /** Over TLS: the server's FIN without close_notify (a truncation); without TLS the same as [close]. */
        val closeTruncated: suspend () -> Unit = close,
    )

    /**
     * A raw HTTP/1.1 WebSocket server (over TLS with [tls]): answers one handshake per connection with a 101 and hands the
     * connection to [serve]. Events: "client FIN" (the TCP stream ended), "client RST" (it failed), over TLS also "client
     * close_notify" (the TLS stream ended in order); "server close_notify" and "server FIN" when [RawConnection.close] runs.
     * Without TLS the client's FIN is only looked for once [RawConnection.watchEnd] was called (it reads to the end).
     */
    private suspend fun rawServer(
        tls: Boolean,
        serve: suspend CoroutineScope.(RawConnection) -> Unit,
        block: suspend (port: Int) -> Unit,
    ) {
        val selector = SelectorManager(Dispatchers.IO)
        val listener = bindTcp(selector, "127.0.0.1", 0)
        try {
            coroutineScope {
                val server =
                    launch {
                        while (true) {
                            val socket = listener.accept()
                            launch {
                                val events = Events()
                                val socketIn = socket.openReadChannel()
                                val socketOut = socket.openWriteChannel(autoFlush = true)
                                val conn =
                                    if (!tls) {
                                        RawConnection(socketIn, socketOut, events, watchEnd = {
                                            launch {
                                                try {
                                                    socketIn.discard()
                                                    events += if (socketIn.closedCause == null) "client FIN" else "client RST"
                                                } catch (e: Throwable) {
                                                    events += "client RST"
                                                }
                                            }
                                        }, close = {
                                            events += "server FIN"
                                            socketOut.flushAndClose()
                                        })
                                    } else {
                                        // the TLS session reads a copy of the socket's input, so that its end is seen
                                        val fed = ByteChannel()
                                        launch {
                                            val buf = ByteArray(16_384)
                                            try {
                                                while (true) {
                                                    val n = socketIn.readAvailable(buf, 0, buf.size)
                                                    if (n < 0) break
                                                    fed.writeFully(buf, 0, n)
                                                    fed.flush()
                                                }
                                                events += if (socketIn.closedCause == null) "client FIN" else "client RST"
                                                fed.flushAndClose()
                                            } catch (e: Throwable) {
                                                events += "client RST"
                                                fed.cancel(e)
                                            }
                                        }
                                        val session =
                                            TlsConnection.server(
                                                fed,
                                                socketOut,
                                                tlsConfig(TlsRole.Server) { identity = ClientFixtures.identity() },
                                                coroutineContext,
                                            )
                                        RawConnection(session.input, session.output, events, watchEnd = {
                                            launch {
                                                try {
                                                    session.input.discard()
                                                    if (session.input.closedCause == null) events += "client close_notify"
                                                } catch (_: Throwable) {
                                                    // the end without close_notify: "client FIN" or "client RST" says how
                                                }
                                            }
                                        }, close = {
                                            events += "server close_notify"
                                            launch {
                                                session.shutdown(drainTimeout = null, afterSent = {
                                                    events += "server FIN"
                                                    socketOut.flushAndClose()
                                                })
                                            }
                                        }, closeTruncated = {
                                            events += "server FIN"
                                            socketOut.flushAndClose()
                                        })
                                    }
                                conn.output.writeStringUtf8(switchingProtocols(conn.input.readWebSocketKey()))
                                conn.output.flush()
                                serve(conn)
                            }
                        }
                    }
                try {
                    block((listener.localAddress as InetSocketAddress).port)
                } finally {
                    server.cancel()
                }
            }
        } finally {
            listener.close()
            selector.close()
        }
    }

    private suspend fun ok(r: io.kuicksilver.http2.runtime.H2ServerStream) {
        r.respond(200, listOf("content-type" to "text/plain"))
        r.sendBody(ByteReadChannel("h2".encodeToByteArray()))
    }

    private fun scheme(tls: Boolean) = if (tls) "wss" else "ws"

    private fun engine(c: HttpClient) = c.engine as KuicksilverEngine

    /** The client's side ends only after the server's: "client X" comes after "server X" in [events]. */
    private fun assertServerFirst(
        events: Events,
        tls: Boolean,
    ) {
        val e = events.all.value
        assertFalse(events.has("client RST"), "no reset: $e")
        assertTrue(events.before("server FIN", "client FIN"), "the server's FIN first: $e")
        if (tls) {
            assertTrue(events.before("server close_notify", "client close_notify"), "the server's close_notify first: $e")
        }
    }

    /**
     * The client closes (its Close first): the server answers with its Close and closes only once the client waits for
     * it ("waiting"); nothing of the client's close came before, and all of it comes after, long before T2 (60 s here).
     */
    private fun clientClosesH1(tls: Boolean) =
        clientTest {
            val conns = CompletableDeferred<RawConnection>()
            val hook = Events()
            rawServer(tls, serve = { conn ->
                conns.complete(conn)
                assertEquals("close 4000 client bye", readClientFrames(conn.input).last())
                conn.watchEnd()
                conn.output.writeFully(byteArrayOf(0x88.toByte(), 2, 0x0F, 0xA0.toByte())) // Close 4000
                conn.output.flush()
            }) { port ->
                testClient(block = { install(WebSockets) }).use { c ->
                    engine(c).h1.webSocketClosingForTest = { hook += it }
                    engine(c).h1.webSocketCloseWaitMillis = 60_000
                    val session = c.webSocketSession("${scheme(tls)}://127.0.0.1:$port/ws")
                    session.close(CloseReason(4000, "client bye"))
                    val conn = conns.await()
                    hook.await("waiting")
                    conn.events.assertClientQuietWhileServerHolds()
                    conn.close()
                    conn.events.await("client FIN")
                    if (tls) conn.events.await("client close_notify")
                    hook.await("server closed")
                    assertFalse(hook.has("T2"))
                    assertServerFirst(conn.events, tls)
                }
            }
        }

    /** The server closes (its Close first), the client's `webSocket { }` answers it: the same order, on the orderly path. */
    private fun serverClosesH1(
        tls: Boolean,
        trailing: Boolean = false,
        truncated: Boolean = false,
    ) = clientTest {
            val conns = CompletableDeferred<RawConnection>()
            val hook = Events()
            rawServer(tls, serve = { conn ->
                conns.complete(conn)
                conn.output.writeFully(byteArrayOf(0x88.toByte(), 2, 0x0F, 0xA1.toByte())) // Close 4001
                // a server that sends more after its Close (RFC 6455 section 5.5.1 forbids data frames): the client
                // reads and drops it (section 7.1.1: "discarding any trailing bytes")
                if (trailing) conn.output.writeFully(TRAILING)
                conn.output.flush()
                assertEquals("close 4001 ", readClientFrames(conn.input).last())
                conn.watchEnd()
            }) { port ->
                testClient(block = { install(WebSockets) }).use { c ->
                    engine(c).h1.webSocketClosingForTest = { hook += it }
                    engine(c).h1.webSocketCloseWaitMillis = 60_000
                    withTimeout(20.seconds) { c.webSocket("${scheme(tls)}://127.0.0.1:$port/ws") { for (f in incoming) continue } }
                    val conn = conns.await()
                    hook.await("waiting")
                    conn.events.assertClientQuietWhileServerHolds()
                    if (truncated) conn.closeTruncated() else conn.close()
                    conn.events.await("client FIN")
                    // over TLS the client answers even a truncated end with close_notify: it closes its write side
                    if (tls) conn.events.await("client close_notify")
                    hook.await("server closed")
                    if (!truncated) assertServerFirst(conn.events, tls)
                    assertFalse(conn.events.has("client RST"), "${conn.events.all.value}")
                }
            }
        }

    /**
     * A server that answers the Close and then never closes: the client closes at T2 (200 ms here), cleanly (close_notify
     * over TLS, then a FIN, no reset), whichever side closed first.
     */
    private fun silentServerH1(
        tls: Boolean,
        clientFirst: Boolean,
    ) = clientTest {
        val conns = CompletableDeferred<RawConnection>()
        val hook = Events()
        rawServer(tls, serve = { conn ->
            conns.complete(conn)
            if (clientFirst) {
                readClientFrames(conn.input)
                conn.output.writeFully(byteArrayOf(0x88.toByte(), 2, 0x03, 0xE8.toByte()))
                conn.output.flush()
            } else {
                conn.output.writeFully(byteArrayOf(0x88.toByte(), 2, 0x03, 0xE8.toByte()))
                conn.output.flush()
                readClientFrames(conn.input)
            }
            conn.watchEnd()
        }) { port ->
            testClient(block = { install(WebSockets) }).use { c ->
                engine(c).h1.webSocketClosingForTest = { hook += it }
                engine(c).h1.webSocketCloseWaitMillis = 200
                val url = "${scheme(tls)}://127.0.0.1:$port/ws"
                if (clientFirst) {
                    c.webSocketSession(url).close(CloseReason(4000, "client bye"))
                } else {
                    withTimeout(20.seconds) { c.webSocket(url) { for (f in incoming) continue } }
                }
                val conn = conns.await()
                conn.events.await("client FIN")
                hook.await("T2")
                val e = conn.events.all.value
                assertFalse(conn.events.has("client RST"), "a clean close at T2, not a reset: $e")
                // over TLS close_notify first (TCP delivers it before the FIN; the server's TLS reads it after its socket did)
                if (tls) conn.events.await("client close_notify")
                conn.close()
            }
        }
    }

    @Test fun clientClosesPlainServerClosesTcpFirst() = clientClosesH1(tls = false)

    @Test fun clientClosesTlsServerClosesFirst() = clientClosesH1(tls = true)

    @Test fun serverClosesPlainServerClosesTcpFirst() = serverClosesH1(tls = false)

    @Test fun serverClosesTlsServerClosesFirst() = serverClosesH1(tls = true)

    @Test fun negative_bytesAfterThePlainServersCloseAreDropped() = serverClosesH1(tls = false, trailing = true)

    @Test fun negative_bytesAfterTheTlsServersCloseAreDropped() = serverClosesH1(tls = true, trailing = true)

    /** A TLS server that ends with a FIN and no close_notify: the client still follows at once, cleanly, not at T2. */
    @Test fun negative_tlsServerFinWithoutCloseNotifyIsFollowedAtOnce() = serverClosesH1(tls = true, truncated = true)

    @Test fun negative_silentPlainServerClientClosesCleanlyAtT2() = silentServerH1(tls = false, clientFirst = true)

    @Test fun negative_silentTlsServerClientClosesCleanlyAtT2() = silentServerH1(tls = true, clientFirst = true)

    @Test fun negative_silentPlainServerAfterItsCloseClientClosesCleanlyAtT2() = silentServerH1(tls = false, clientFirst = false)

    @Test fun negative_silentTlsServerAfterItsCloseClientClosesCleanlyAtT2() = silentServerH1(tls = true, clientFirst = false)

    // ---- HTTP/2 (RFC 8441 section 5: END_STREAM is the TCP FIN, RST_STREAM CANCEL the reset) ----

    /**
     * An HTTP/2 WebSocket: the server sends its Close first or answers the client's, and ends its side ([serverEnds]) only
     * once the client waits for it. Events: "client END_STREAM", "client RST <code>", "server END_STREAM".
     */
    private fun h2Close(
        clientFirst: Boolean,
        serverEnds: Boolean,
        trailing: Boolean = false,
    ) = clientTest {
        val events = Events()
        val hook = Events()
        val endServer = CompletableDeferred<Unit>()
        tlsH2WithSilentUdp(
            enableConnectProtocol = true,
            onRequest = { _, r ->
                if (r.method != "CONNECT") return@tlsH2WithSilentUdp ok(r)
                r.invokeOnFailure { events += "client RST ${(it as? Http2Exception.StreamReset)?.code}" }
                r.respond(200)
                val out = ByteChannel()
                val sender = launch { runCatching { r.sendBody(out, end = true) } }
                val close = byteArrayOf(0x88.toByte(), 2, 0x03, 0xE8.toByte())
                if (clientFirst) {
                    readClientFrames(r.body)
                    out.writeFully(close)
                    if (trailing) out.writeFully(TRAILING)
                    out.flush()
                } else {
                    out.writeFully(close)
                    if (trailing) out.writeFully(TRAILING)
                    out.flush()
                    readClientFrames(r.body)
                }
                launch {
                    runCatching { r.body.discard() }
                    if (r.body.closedCause == null) events += "client END_STREAM"
                }
                endServer.await()
                events += "server END_STREAM"
                out.flushAndClose()
                sender.join()
                kotlinx.coroutines.awaitCancellation()
            },
        ) { port, _ ->
            testClient(block = { install(WebSockets) }).use { c ->
                engine(c).h1.h2WebSocketClosingForTest = { hook += it }
                engine(c).h1.webSocketCloseWaitMillis = if (serverEnds) 60_000 else 200
                c.get("https://127.0.0.1:$port/")
                val url = "wss://127.0.0.1:$port/ws"
                if (clientFirst) {
                    c.webSocketSession(url).close(CloseReason(4000, "client bye"))
                } else {
                    withTimeout(20.seconds) { c.webSocket(url) { for (f in incoming) continue } }
                }
                hook.await("waiting")
                if (serverEnds) {
                    events.assertClientQuietWhileServerHolds()
                    endServer.complete(Unit)
                    events.await("client END_STREAM")
                    hook.await("server ended")
                    assertTrue(events.before("server END_STREAM", "client END_STREAM"), "${events.all.value}")
                    // the stream is over both ways: released without RST_STREAM. A request after the release goes on
                    // the same connection, behind any RST_STREAM the release would have sent
                    awaitH2StreamsReleased(engine(c))
                    c.get("https://127.0.0.1:$port/")
                    assertFalse(events.all.value.any { it.startsWith("client RST") }, "${events.all.value}")
                } else {
                    // T2 (200 ms): END_STREAM first, the reset (CANCEL) only one close wait later
                    events.await("client END_STREAM")
                    hook.await("T2")
                    events.await("client RST ${Http2ErrorCode.CANCEL}")
                    assertTrue(events.before("client END_STREAM", "client RST ${Http2ErrorCode.CANCEL}"), "${events.all.value}")
                    endServer.complete(Unit)
                }
            }
        }
    }

    private suspend fun awaitH2StreamsReleased(e: KuicksilverEngine) {
        withTimeout(10.seconds) { while (e.h1.h2.streamCount != 0) kotlinx.coroutines.yield() }
    }

    @Test fun h2ClientClosesServerEndsStreamFirst() = h2Close(clientFirst = true, serverEnds = true)

    @Test fun h2ServerClosesServerEndsStreamFirst() = h2Close(clientFirst = false, serverEnds = true)

    @Test fun negative_h2BytesAfterTheServersCloseAreDropped() = h2Close(clientFirst = false, serverEnds = true, trailing = true)

    @Test fun negative_h2SilentServerGetsEndStreamAtT2AndCancelLater() = h2Close(clientFirst = true, serverEnds = false)

    @Test fun negative_h2SilentServerAfterItsCloseGetsEndStreamAtT2AndCancelLater() = h2Close(clientFirst = false, serverEnds = false)

    // ---- HTTP/3 (RFC 9220 section 3: the FIN is the TCP FIN, H3_REQUEST_CANCELLED the reset) ----

    /** The client's qlog: "client STOP_SENDING" and "client RESET_STREAM" for every such frame it sends. */
    private class FramesSent(
        val events: Events,
    ) : QlogSink {
        override fun open(
            odcidHex: String,
            role: TlsRole,
        ): QlogTrace =
            object : QlogTrace {
                override fun write(record: String) {
                    if ("packet_sent" !in record) return
                    if ("\"stop_sending\"" in record) events += "client STOP_SENDING"
                    if ("\"reset_stream\"" in record) events += "client RESET_STREAM"
                }

                override fun close() {}
            }
    }

    /**
     * An HTTP/3 WebSocket: the same as [h2Close] with FIN. With [serverStops] the server sends STOP_SENDING while the
     * client holds its FIN: the client answers with RESET_STREAM (RFC 9000 section 3.5) and never stops the server.
     */
    private fun h3Close(
        clientFirst: Boolean,
        serverEnds: Boolean,
        serverStops: Boolean = false,
        trailing: Boolean = false,
    ) = h3Test {
        val events = Events()
        val hook = Events()
        val endServer = CompletableDeferred<Unit>()
        val ep =
            Http3Endpoint.bind(
                InetSocketAddress("127.0.0.1", 0),
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        server =
                            QuicServerConfig
                                .Builder(
                                    tlsConfig(TlsRole.Server) {
                                        alpn = listOf("h3")
                                        identity = ClientFixtures.identity()
                                    },
                                ).build()
                    }.build(),
                // no GREASE stream, which the client stops (STOP_SENDING, RFC 9114 section 6.2.3): the client's qlog then
                // shows only the WebSocket stream's frames
                io.kuicksilver.http3.http3Settings {
                    enableConnectProtocol = true
                    grease = false
                },
            )
        coroutineScope {
            val served =
                launch {
                    val conn = ep.accept()
                    val s = conn.acceptRequest().acceptConnect()
                    val close = byteArrayOf(0x88.toByte(), 2, 0x03, 0xE8.toByte())
                    if (clientFirst) {
                        readClientFrames(s.input)
                        s.output.writeFully(close)
                        if (trailing) s.output.writeFully(TRAILING)
                        s.output.flush()
                    } else {
                        s.output.writeFully(close)
                        if (trailing) s.output.writeFully(TRAILING)
                        s.output.flush()
                        readClientFrames(s.input)
                    }
                    launch {
                        runCatching { s.input.discard() }
                        events += if (s.input.closedCause == null) "client FIN" else "client reset"
                    }
                    endServer.await()
                    if (serverStops) {
                        events += "server STOP_SENDING"
                        s.stopSending(io.kuicksilver.http3.Http3ErrorCode.NO_ERROR)
                    }
                    events += "server FIN"
                    runCatching { s.output.flushAndClose() }
                    kotlinx.coroutines.awaitCancellation()
                }
            try {
                testClient(
                    Http3DiscoveryMode.H3Only,
                    engine = { http3 { qlog = FramesSent(events) } },
                    block = { install(WebSockets) },
                ).use { c ->
                    engine(c).h3.webSocketClosingForTest = { hook += it }
                    engine(c).h3.webSocketCloseWaitMillis = if (serverEnds) 60_000 else 200
                    val url = "wss://127.0.0.1:${ep.localAddress.port}/ws"
                    if (clientFirst) {
                        c.webSocketSession(url).close(CloseReason(4000, "client bye"))
                    } else {
                        withTimeout(20.seconds) { c.webSocket(url) { for (f in incoming) continue } }
                    }
                    hook.await("waiting")
                    when {
                        serverStops -> {
                            events.assertClientQuietWhileServerHolds()
                            endServer.complete(Unit)
                            events.await("client RESET_STREAM")
                            events.await("client reset")
                            hook.await("server ended")
                            assertFalse(events.has("client STOP_SENDING"), "${events.all.value}")
                        }

                        serverEnds -> {
                            events.assertClientQuietWhileServerHolds()
                            endServer.complete(Unit)
                            events.await("client FIN")
                            hook.await("server ended")
                            assertTrue(events.before("server FIN", "client FIN"), "${events.all.value}")
                            // the stream's end is over before the pool lets the connection go: no frame of an abort
                            assertFalse(events.has("client STOP_SENDING") || events.has("client RESET_STREAM"), "${events.all.value}")
                        }

                        else -> {
                            events.await("client FIN")
                            hook.await("T2")
                            events.await("client STOP_SENDING")
                            assertTrue(events.before("client FIN", "client STOP_SENDING"), "${events.timed.value} ${hook.timed.value}")
                            assertFalse(events.has("client RESET_STREAM"), "${events.all.value}")
                            endServer.complete(Unit)
                        }
                    }
                }
            } finally {
                served.cancel()
                ep.close()
            }
        }
    }

    @Test fun h3ClientClosesServerFinFirst() = h3Close(clientFirst = true, serverEnds = true)

    @Test fun h3ServerClosesServerFinFirst() = h3Close(clientFirst = false, serverEnds = true)

    @Test fun negative_h3BytesAfterTheServersCloseAreDropped() = h3Close(clientFirst = false, serverEnds = true, trailing = true)

    @Test fun negative_h3SilentServerGetsFinAtT2AndStopSendingLater() = h3Close(clientFirst = true, serverEnds = false)

    @Test fun negative_h3SilentServerAfterItsCloseGetsFinAtT2AndStopSendingLater() = h3Close(clientFirst = false, serverEnds = false)

    @Test fun negative_h3ServerStopSendingWhileTheFinIsHeldIsAnsweredWithReset() =
        h3Close(clientFirst = true, serverEnds = true, serverStops = true)
}

/** How long the slow servers above hold their close once the client waits for it: a behaviour under test, not a wait. */
private val SLOW_SERVER = 300.milliseconds

/** A text frame "late" of a server's (unmasked), sent after its Close: what a client must read and drop. */
private val TRAILING = byteArrayOf(0x81.toByte(), 4) + "late".encodeToByteArray()
