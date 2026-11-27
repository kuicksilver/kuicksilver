// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.application.install
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.discard
import io.ktor.utils.io.exhausted
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.CloseReason
import io.ktor.websocket.close
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.ktor.network.connectTcp
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.awaitSendStopped
import io.kuicksilver.tls.TlsConnection
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * How the server engine ends a WebSocket's transport (RFC 6455 section 5.5.1: "After both sending and receiving a Close
 * message ... The server MUST close the underlying TCP connection immediately"; RFC 9220 section 3: the FIN bit is the TCP
 * close). The properties: over TLS the server's FIN follows its close_notify at once, whether the client ever answers it;
 * over HTTP/3 the server sends no STOP_SENDING while a client holds its FIN back within the close wait, nor after that
 * FIN, and stops a client that never sends one with H3_NO_ERROR once the close wait is over. Each with the client's Close
 * first and with the server's.
 */
class ServerWebSocketCloseOrderTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun io.ktor.server.application.Application.routes() {
        install(WebSockets)
        routing {
            webSocket("/ws") { for (f in incoming) continue } // answers the client's Close
            webSocket("/bye") { close(CloseReason(CloseReason.Codes.NORMAL, "bye")) } // the server's Close first
        }
    }

    /** A Close frame of the client's: masked (RFC 6455 section 5.3), key 0, code 1000. */
    private val clientClose = byteArrayOf(0x88.toByte(), 0x82.toByte(), 0, 0, 0, 0, 0x03, 0xE8.toByte())

    /** Reads one frame of the server's (unmasked) from [input]; returns its opcode. */
    private suspend fun readServerFrame(input: ByteReadChannel): Int {
        val b0 = input.readByte().toInt() and 0xff
        val len =
            when (val l = input.readByte().toInt() and 0x7f) {
                126 -> input.readByteArray(2).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xff) }
                127 -> input.readByteArray(8).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xff) }
                else -> l.toLong()
            }
        input.discard(len)
        return b0 and 0x0f
    }

    /**
     * A raw TLS client that never sends close_notify (nor a FIN) after the closing handshake: the server's close_notify
     * comes, and its TCP FIN right after it, within [FIN_WITHIN], not after the server's wait for the client's
     * close_notify, stretched here to [PEER_WAIT] (3 s otherwise) so the two are three times apart. Before, the FIN waited
     * for that close_notify, or for that wait.
     */
    private fun tlsFinComesAtOnce(path: String) =
        serverTest {
            val (server, port) = tlsServer(configure = { tlsCloseTimeoutForTest = PEER_WAIT }) { routes() }
            val selector = SelectorManager(Dispatchers.IO)
            try {
                coroutineScope {
                    val socket = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                    val socketIn = socket.openReadChannel()
                    val socketOut = socket.openWriteChannel(autoFlush = true)
                    // the TLS session reads a copy of the socket's input, so the TCP FIN is seen apart from close_notify
                    val fed = ByteChannel()
                    val fin = CompletableDeferred<TimeSource.Monotonic.ValueTimeMark>()
                    launch {
                        val buf = ByteArray(16_384)
                        while (true) {
                            val n = runCatching { socketIn.readAvailable(buf, 0, buf.size) }.getOrDefault(-1)
                            if (n < 0) break
                            fed.writeFully(buf, 0, n)
                            fed.flush()
                        }
                        fin.complete(TimeSource.Monotonic.markNow())
                        fed.flushAndClose()
                    }
                    val tls = TlsConnection.client(fed, socketOut, ServerFixtures.clientTls(), coroutineContext)
                    tls.output.writeStringUtf8(
                        "GET $path HTTP/1.1\r\nHost: server.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
                    )
                    tls.output.flush()
                    assertTrue(tls.input.readLine(LineEnding.Lenient)!!.startsWith("HTTP/1.1 101"))
                    while (tls.input.readLine(LineEnding.Lenient)!!.isNotEmpty()) continue
                    if (path == "/bye") assertEquals(8, readServerFrame(tls.input))
                    tls.output.writeFully(clientClose)
                    tls.output.flush()
                    val closeSent = TimeSource.Monotonic.markNow()
                    if (path == "/ws") assertEquals(8, readServerFrame(tls.input))
                    // the server's close_notify: its plaintext ends in order
                    tls.input.discard()
                    assertNull(tls.input.closedCause, "the server's close_notify")
                    val finAt = withTimeout(PEER_WAIT * 2) { fin.await() }
                    val took = finAt - closeSent
                    assertTrue(took < FIN_WITHIN, "the server's FIN came $took after the closing handshake")
                    tls.close()
                    socket.close()
                }
            } finally {
                selector.close()
                server.stop(100, 500)
            }
        }

    @Test fun negative_tlsFinIsNotHeldForTheClientsCloseNotifyClientCloses() = tlsFinComesAtOnce("/ws")

    @Test fun negative_tlsFinIsNotHeldForTheClientsCloseNotifyServerCloses() = tlsFinComesAtOnce("/bye")

    // ---- HTTP/3 ----

    /** Reads one HTTP/3 frame from [input]: its type and payload. */
    private suspend fun readH3Frame(input: ByteReadChannel): Pair<Long, ByteArray> {
        val type = readVarint(input)
        val len = readVarint(input)
        return type to input.readByteArray(len.toInt())
    }

    /** Reads one QUIC variable-length integer (RFC 9000 section 16) from [input]. */
    private suspend fun readVarint(input: ByteReadChannel): Long {
        val first = input.readByte().toInt() and 0xff
        val len = 1 shl (first ushr 6)
        var v = (first and 0x3f).toLong()
        repeat(len - 1) { v = (v shl 8) or (input.readByte().toLong() and 0xff) }
        return v
    }

    /** The settings in a SETTINGS frame's [payload]: identifier and value varint pairs (RFC 9114 section 7.2.4). */
    private suspend fun settingsOf(payload: ByteArray): Map<Long, Long> {
        val input = ByteReadChannel(payload)
        val out = HashMap<Long, Long>()
        while (!input.exhausted()) out[readVarint(input)] = readVarint(input)
        return out
    }

    /**
     * The client side of the server's unidirectional streams on a bare QUIC connection [c] (no HTTP/3 session of ours):
     * the server's SETTINGS go to [settings] and the id of its first GOAWAY to [goAway] (RFC 9114 section 7.2.6); its QPACK
     * streams are read and dropped (a client whose SETTINGS are empty allows the server no dynamic table: RFC 9204 section
     * 3.2.3, SETTINGS_QPACK_MAX_TABLE_CAPACITY defaults to 0).
     * Runs until the connection ends or the caller cancels it.
     */
    private suspend fun readServerStreams(
        c: QuicConnection,
        settings: CompletableDeferred<Map<Long, Long>>,
        goAway: CompletableDeferred<Long>,
    ): Unit =
        coroutineScope {
            while (true) {
                val st = runCatching { c.acceptStream() }.getOrNull() ?: break
                launch {
                    runCatching {
                        if (readVarint(st.input) != 0L) {
                            st.input.discard() // a QPACK stream (RFC 9204 section 4.2)
                            return@runCatching
                        }
                        val (type, payload) = readH3Frame(st.input)
                        assertEquals(4L, type, "the control stream's first frame is SETTINGS (RFC 9114 section 6.2.1)")
                        settings.complete(settingsOf(payload))
                        while (true) {
                            val (t, p) = readH3Frame(st.input)
                            if (t == 7L) goAway.complete(readVarint(ByteReadChannel(p)))
                        }
                    }.exceptionOrNull()?.let { settings.completeExceptionally(it) }
                }
            }
        }

    /** A DATA frame (type 0) carrying [payload] (under 64 bytes). */
    private fun dataFrame(payload: ByteArray) = byteArrayOf(0, payload.size.toByte()) + payload

    /**
     * A raw HTTP/3 client: Extended CONNECT to [path], the closing handshake (its Close after the server's on `/bye`,
     * first on `/ws`), then the server's FIN; it then holds its own FIN back ([finAfter]: a slow client, or none at all).
     * Returns the STOP_SENDING codes the server sent while the FIN was held, and after it.
     */
    private suspend fun h3Close(
        path: String,
        sendFin: Boolean,
    ): Pair<Long?, Long?> {
        val (server, port) = tlsServer { routes() }
        val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
        try {
            val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
            try {
                c.peerSettings.filterNotNull().first()
                val st: QuicStream = rawExtendedConnect(c.quic, "websocket", path, listOf("sec-websocket-version" to "13"))
                return coroutineScope {
                    val stopped = async { st.awaitSendStopped() }
                    assertEquals(1L, readH3Frame(st.input).first, "the 200's HEADERS")
                    if (path == "/ws") {
                        st.output.writeFully(dataFrame(clientClose))
                        st.output.flush()
                    }
                    // the server's Close (in DATA frames), then its FIN
                    val data = ByteChannel()
                    val reader =
                        launch {
                            while (true) {
                                val (type, payload) = runCatching { readH3Frame(st.input) }.getOrNull() ?: break
                                if (type == 0L) {
                                    data.writeFully(payload)
                                    data.flush()
                                }
                            }
                            data.flushAndClose()
                        }
                    assertEquals(8, readServerFrame(data))
                    if (path == "/bye") {
                        st.output.writeFully(dataFrame(clientClose))
                        st.output.flush()
                    }
                    reader.join()
                    data.discard()
                    val serverFin = TimeSource.Monotonic.markNow()
                    // a slow client: the FIN is held; no STOP_SENDING may come meanwhile (the server's close wait is 5 s)
                    val whileHeld =
                        withTimeoutOrNull(if (sendFin) SLOW_CLIENT else 10.seconds) { stopped.await() }
                    if (!sendFin) {
                        // not before the close wait: the server gives a client 5 s to end its side (a 1 s margin for a slow
                        // machine on the lower bound only)
                        val took = serverFin.elapsedNow()
                        assertTrue(whileHeld == null || took > 4.seconds, "STOP_SENDING $took after the server's FIN")
                        return@coroutineScope whileHeld to null
                    }
                    st.output.flushAndClose()
                    // and none after the FIN either
                    val afterFin = withTimeoutOrNull(SLOW_CLIENT) { stopped.await() }
                    stopped.cancel()
                    whileHeld to afterFin
                }
            } finally {
                c.close()
            }
        } finally {
            ep.close()
            server.stop(100, 500)
        }
    }

    /**
     * A stop with a long grace period while the server waits for a client's FIN after its own (the close wait, 5 s): the
     * client is stopped at once with H3_NO_ERROR, as after the close wait, and the stop is over well within it.
     *
     * The client is a bare QUIC connection with its own control stream, not a Kuicksilver HTTP/3 client: the stop sends
     * its GOAWAY too (RFC 9114 section 5.2), on the control stream, and the STOP_SENDING may arrive before or after it
     * (two streams: QUIC orders neither against the other). A Kuicksilver client closes its connection when a GOAWAY finds
     * it idle, and a stream opened raw on its QUIC connection is no exchange of its: with the GOAWAY first (seen on the
     * Windows CI runner) it closed with H3_NO_ERROR before the STOP_SENDING arrived. This client closes, as an idle
     * client may, only once it has both.
     */
    @Test fun negative_h3StopEndsTheWaitForTheClientsFin() =
        h3ServerTest {
            val (server, port) = tlsServer { routes() }
            val ep = QuicEndpoint.bind(InetSocketAddress("127.0.0.1", 0))
            var stopped = false
            try {
                val c =
                    ep.connect(
                        InetSocketAddress("127.0.0.1", port),
                        QuicClientConfig.Builder(ServerFixtures.clientTls(alpn = listOf("h3"))).build(),
                    )
                try {
                    coroutineScope {
                        val settings = CompletableDeferred<Map<Long, Long>>()
                        val goAway = CompletableDeferred<Long>()
                        val serverStreams = launch { readServerStreams(c, settings, goAway) }
                        val control = c.openUni()
                        control.output.writeFully(byteArrayOf(0x00, 0x04, 0x00)) // control stream, empty SETTINGS
                        control.output.flush()
                        // RFC 9220 section 3: no Extended CONNECT before SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08) = 1
                        assertEquals(1L, withTimeout(10.seconds) { settings.await() }[0x08L], "SETTINGS_ENABLE_CONNECT_PROTOCOL")
                        val st: QuicStream = rawExtendedConnect(c, "websocket", "/ws", listOf("sec-websocket-version" to "13"))
                        val stopSending = async { st.awaitSendStopped() }
                        assertEquals(1L, readH3Frame(st.input).first, "the 200's HEADERS")
                        st.output.writeFully(dataFrame(clientClose))
                        st.output.flush()
                        // the server's Close, then its FIN
                        while (runCatching { readH3Frame(st.input) }.isSuccess) continue
                        assertNull(withTimeoutOrNull(SLOW_CLIENT) { stopSending.await() }, "the server waits for the FIN")
                        assertTrue(!goAway.isCompleted, "no GOAWAY before the stop")
                        val started = TimeSource.Monotonic.markNow()
                        val stop = launch(Dispatchers.IO) { server.stop(10_000, 20_000) }
                        assertEquals(Http3ErrorCode.NO_ERROR, withTimeout(10.seconds) { stopSending.await() })
                        // the stop's graceful GOAWAY (RFC 9114 section 5.2), before or after the STOP_SENDING
                        withTimeout(10.seconds) { goAway.await() }
                        // the exchange is over (stopped), and a client idle after a GOAWAY closes its connection: so the
                        // stop does not wait out its idle-close fallback for this one
                        c.close(Http3ErrorCode.NO_ERROR)
                        withTimeout(10.seconds) { stop.join() }
                        stopped = true
                        val took = started.elapsedNow()
                        assertTrue(took < 3.seconds, "the stop took $took, the close wait is 5 s")
                        serverStreams.cancel()
                    }
                } finally {
                    c.close()
                }
            } finally {
                ep.close()
                if (!stopped) server.stop(100, 500)
            }
        }

    @Test fun h3NoStopSendingWhileTheClientHoldsItsFinClientCloses() =
        h3ServerTest {
            assertEquals(null to null, h3Close("/ws", sendFin = true))
        }

    @Test fun h3NoStopSendingWhileTheClientHoldsItsFinServerCloses() =
        h3ServerTest {
            assertEquals(null to null, h3Close("/bye", sendFin = true))
        }

    /**
     * A client that never sends its FIN is stopped with H3_NO_ERROR once the server's close wait (5 s) is over, not
     * before. Before, the server stopped it right after its own FIN.
     */
    @Test fun negative_h3ClientWithoutFinIsStoppedWithNoErrorAfterTheCloseWait() =
        h3ServerTest {
            assertEquals(Http3ErrorCode.NO_ERROR, h3Close("/ws", sendFin = false).first)
        }

    /**
     * A client that sends frames after its Close (8 MiB, RFC 6455 section 5.5.1 forbids them) and withholds its FIN: the
     * server reads and drops them within its close wait, buffering none, so the client's writes never stall on flow
     * control; it is stopped with H3_NO_ERROR once the close wait is over. Before, the frame guard went on copying them
     * into the ended session's input, which nobody read, until that channel was full (about 1 MiB, then the stream's
     * window), for every such stream for 5 s.
     */
    @Test fun negative_h3BytesAfterTheClientsCloseAreDroppedNotBuffered() =
        h3ServerTest {
            val (server, port) = tlsServer { routes() }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                try {
                    c.peerSettings.filterNotNull().first()
                    val st = rawExtendedConnect(c.quic, "websocket", "/ws", listOf("sec-websocket-version" to "13"))
                    coroutineScope {
                        val stopped = async { st.awaitSendStopped() }
                        assertEquals(1L, readH3Frame(st.input).first, "the 200's HEADERS")
                        st.output.writeFully(dataFrame(clientClose))
                        st.output.flush()
                        // the server's Close and FIN
                        while (runCatching { readH3Frame(st.input) }.isSuccess) continue
                        val serverFin = TimeSource.Monotonic.markNow()
                        // 16 000-byte masked Binary frames (key 0) in DATA frames of 16 008 bytes (a 2-byte varint length)
                        val ws = byteArrayOf(0x82.toByte(), 0xFE.toByte(), 0x3E, 0x80.toByte(), 0, 0, 0, 0) + ByteArray(16_000)
                        val frame = byteArrayOf(0, (0x40 or (ws.size shr 8)).toByte(), ws.size.toByte()) + ws
                        withTimeout(4.seconds) {
                            repeat(8 * 1024 * 1024 / ws.size) { st.output.writeFully(frame) }
                            st.output.flush()
                        }
                        assertEquals(Http3ErrorCode.NO_ERROR, withTimeout(10.seconds) { stopped.await() })
                        val took = serverFin.elapsedNow()
                        assertTrue(took > 4.seconds, "STOP_SENDING $took after the server's FIN")
                    }
                } finally {
                    c.close()
                }
            } finally {
                ep.close()
                server.stop(100, 500)
            }
        }

    private companion object {
        /** How long the slow clients hold their FIN back: a behaviour under test, not a wait. */
        val SLOW_CLIENT = 500.milliseconds

        /** The server's wait for the client's close_notify in the TLS tests (its own is 3 s): the slow path, made long. */
        val PEER_WAIT = 30.seconds

        /** The bound on the server's FIN after the closing handshake: a third of [PEER_WAIT]. */
        val FIN_WITHIN = 10.seconds
    }
}
