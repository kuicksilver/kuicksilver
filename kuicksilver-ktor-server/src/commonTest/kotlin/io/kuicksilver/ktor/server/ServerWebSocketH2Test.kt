// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class, io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.http.content.OutgoingContent
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import io.ktor.server.websocket.webSocketRaw
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.RawWebSocket
import io.ktor.websocket.readReason
import io.ktor.websocket.readText
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.runtime.H2ClientConnection
import io.kuicksilver.http2.runtime.H2ClientStream
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.ktor.network.connectTcp
import io.kuicksilver.ktor.network.tls
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.coroutines.CoroutineContext
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import io.ktor.client.plugins.websocket.webSocket as clientWebSocket
import io.ktor.client.request.get as clientGet

/**
 * WebSockets over HTTP/2 (RFC 8441) through Ktor's own `webSocket {}` routes: the server engine with `http2` advertises
 * SETTINGS_ENABLE_CONNECT_PROTOCOL (`webSocketsOverHttp2`, on by default), takes an Extended CONNECT with `:protocol =
 * websocket` as Ktor's upgrade request and answers it with `:status 200`; the stream then carries the frames. The client
 * here is the HTTP/2 runtime driven by hand, so every field and status is the server's own.
 */
class ServerWebSocketH2Test {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val version13 = listOf("sec-websocket-version" to "13")

    private fun Application.echo() {
        install(WebSockets)
        routing {
            webSocket("/ws") {
                for (frame in incoming) if (frame is Frame.Text) send(Frame.Text("${call.request.httpVersion}:" + frame.readText()))
            }
        }
    }

    /** An HTTP/2 client connection to 127.0.0.1:[port] (TLS, ALPN `h2`), its server's SETTINGS in hand, for [block]. */
    private suspend fun <T> h2(
        port: Int,
        block: suspend (H2ClientConnection) -> T,
    ): T {
        val selector = SelectorManager(Dispatchers.IO)
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        try {
            val t = connectTcp(selector, InetSocketAddress("127.0.0.1", port)).tls(ServerFixtures.clientTls(alpn = listOf("h2")))
            try {
                assertEquals("h2", t.negotiatedAlpn)
                val c =
                    H2ClientConnection.start(
                        t.openReadChannel(),
                        t.openWriteChannel(),
                        Http2Settings(),
                        scope,
                        Duration.INFINITE,
                        { t.close() },
                    )
                withTimeout(10.seconds) { c.awaitServerSettings() }
                try {
                    return block(c)
                } finally {
                    c.abort(kotlinx.io.IOException("the test is over"))
                }
            } finally {
                t.close()
            }
        } finally {
            scope.cancel()
            selector.close()
        }
    }

    private fun H2ClientConnection.connect(
        protocol: String = "websocket",
        path: String = "/ws",
        fields: List<Pair<String, String>> = version13,
    ): H2ClientStream {
        assertTrue(tryReserve())
        return open("CONNECT", "https", "server.test", path, fields, endStream = false, protocol = protocol)
    }

    /** A client-side WebSocket session on [s]: its output is sent as the stream's DATA, ended with END_STREAM. */
    private fun CoroutineScope.session(s: H2ClientStream): Pair<io.ktor.websocket.WebSocketSession, ByteWriteChannel> {
        val out = ByteChannel()
        launch { runCatching { s.sendBody(out, stallMillis = null) { error("no stall") } } }
        return RawWebSocket(s.body, out, masking = true, coroutineContext = coroutineContext) to out
    }

    @Test fun echoOverExtendedConnect() =
        serverTest {
            val (server, port) = h2TlsServer { echo() }
            try {
                h2(port) { c ->
                    assertTrue(c.serverAllowsExtendedConnect, "SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 (RFC 8441 section 3)")
                    val s = c.connect()
                    val head = s.response()
                    assertEquals(200, head.status, "RFC 8441 section 5: a 2xx, never 101 (RFC 9113 section 8.6)")
                    // RFC 8441 section 5: no Sec-WebSocket-Accept, no connection-specific fields; RFC 9110 section 9.3.6: no
                    // content-length on a 2xx to CONNECT
                    val names = head.fields.map { it.first }
                    for (n in listOf("sec-websocket-accept", "connection", "upgrade", "content-length", "transfer-encoding")) {
                        assertTrue(n !in names, "$n in ${head.fields}")
                    }
                    coroutineScopeWithJob { scope ->
                        val (ws, _) = scope.session(s)
                        ws.outgoing.send(Frame.Text("ping"))
                        assertEquals("HTTP/2:ping", (ws.incoming.receive() as Frame.Text).readText())
                        ws.outgoing.send(Frame.Close(CloseReason(CloseReason.Codes.NORMAL, "bye")))
                        assertEquals(CloseReason.Codes.NORMAL.code, (ws.incoming.receive() as Frame.Close).readReason()?.code)
                        // RFC 8441 section 5: the orderly close is the server's END_STREAM, not a reset
                        assertTrue(withTimeout(10.seconds) { s.awaitServerEnd() })
                    }
                    s.release()
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * Our client against our server: the client's WebSocket goes as an Extended CONNECT on the HTTP/2 connection its GET
     * opened (one TCP connection for both), the server's `webSocket {}` route sees an HTTP/2 call, and both directions
     * end in order.
     */
    @Test fun kuicksilverClientOverH2() =
        serverTest {
            val opened =
                kotlinx.coroutines.channels.Channel<io.ktor.http.HttpProtocolVersion>(
                    kotlinx.coroutines.channels.Channel.UNLIMITED,
                )
            val closed = CompletableDeferred<CloseReason?>()
            val (server, port) =
                h2TlsServer(configure = {
                    eventListener =
                        object : KuicksilverServerEventListener() {
                            override fun connectionOpened(
                                protocol: io.ktor.http.HttpProtocolVersion,
                                remote: InetSocketAddress?,
                            ) {
                                opened.trySend(protocol)
                            }
                        }
                }) {
                    install(WebSockets)
                    routing {
                        get("/") { call.respondText("ok") }
                        webSocket("/ws") {
                            for (frame in incoming) {
                                if (frame is Frame.Text) {
                                    send(
                                        Frame.Text("${call.request.httpVersion}:" + frame.readText()),
                                    )
                                }
                            }
                            closed.complete(closeReason.await())
                        }
                    }
                }
            try {
                io.ktor.client
                    .HttpClient(io.kuicksilver.ktor.client.Kuicksilver) {
                        install(io.ktor.client.plugins.websocket.WebSockets)
                        engine {
                            trust =
                                io.kuicksilver.tls.TrustConfig
                                    .AnchoredCa(listOf(io.kuicksilver.tls.Certificate(TestCerts.testCa)))
                            http3 { discovery = io.kuicksilver.ktor.client.Http3DiscoveryMode.H1Only }
                        }
                    }.use { c ->
                        assertEquals(
                            io.ktor.http.HttpProtocolVersion.HTTP_2_0,
                            withTimeout(10.seconds) { c.clientGet("https://127.0.0.1:$port/") }.version,
                        )
                        withTimeout(10.seconds) {
                            c.clientWebSocket("wss://127.0.0.1:$port/ws") {
                                assertEquals(io.ktor.http.HttpProtocolVersion.HTTP_2_0, call.response.version)
                                send(Frame.Text("hello"))
                                assertEquals("HTTP/2:hello", (incoming.receive() as Frame.Text).readText())
                            }
                        }
                        assertEquals(CloseReason.Codes.NORMAL.code, withTimeout(10.seconds) { closed.await() }?.code)
                    }
                assertEquals(io.ktor.http.HttpProtocolVersion.HTTP_2_0, opened.receive())
                assertTrue(opened.tryReceive().isFailure, "one connection for the GET and the WebSocket")
            } finally {
                server.stop(100, 500)
            }
        }

    /** RFC 9110 section 7.8: upgrade tokens are case-insensitive, so `:protocol = WebSocket` is a WebSocket too. */
    @Test fun protocolTokenInAnyCase() =
        serverTest {
            val (server, port) = h2TlsServer { echo() }
            try {
                h2(port) { c ->
                    val s = c.connect(protocol = "WebSocket")
                    assertEquals(200, s.response().status)
                    s.release()
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun settingAdvertisedOnlyWhenEnabled() =
        serverTest {
            for (enabled in listOf(true, false)) {
                val (server, port) = h2TlsServer(configure = { webSocketsOverHttp2 = enabled }) { echo() }
                try {
                    h2(port) { c -> assertEquals(enabled, c.serverAllowsExtendedConnect) }
                    RawH2Client.connect(port).use { raw ->
                        raw.preface()
                        raw.await { it.type == RawFrame.SETTINGS }
                        assertEquals(if (enabled) 1L else null, assertNotNull(raw.serverSettings)[0x8])
                    }
                } finally {
                    server.stop(100, 500)
                }
            }
        }

    /** RFC 9220 section 3, as on HTTP/3: an Extended CONNECT for a protocol the engine does not serve gets 501. */
    @Test fun unknownProtocol501() =
        serverTest {
            val (server, port) = h2TlsServer { echo() }
            try {
                h2(port) { c ->
                    val s = c.connect(protocol = "webtransport-x")
                    assertEquals(501, s.response().status)
                    s.release()
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun nonWebSocketRouteAnswersItsStatus() =
        serverTest {
            val (server, port) =
                h2TlsServer {
                    install(WebSockets)
                    routing { }
                }
            try {
                h2(port) { c ->
                    val s = c.connect()
                    assertEquals(404, s.response().status)
                    s.release()
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 9110 section 9.3.6: "Any 2xx (Successful) response indicates that the sender ... will switch to tunnel mode": a
     * route that is not a WebSocket one answering the CONNECT with a 2xx would make the client believe a WebSocket is open
     * that nobody accepted. It is answered 501 instead, as an unsupported `:protocol` is.
     */
    @Test fun negative_plainRouteDoesNotOpenATunnel() =
        serverTest {
            val (server, port) = h2TlsServer { routing { get("/ws") { call.respondText("not a websocket") } } }
            try {
                h2(port) { c ->
                    val s = c.connect()
                    assertEquals(501, s.response().status)
                    s.release()
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 8441 section 5: Sec-WebSocket-Version is "used in the CONNECT request ... as defined in [RFC6455]"; RFC 6455
     * section 4.2.1 requires a version of 13 (otherwise the server "MUST stop processing the client's handshake and
     * return an HTTP response with an appropriate error code (such as 400 Bad Request)"), and section 4.2.2 answers a
     * version the server does not understand with "an appropriate HTTP error code (such as 426 Upgrade Required) and a
     * |Sec-WebSocket-Version| header field indicating the version(s) the server is capable of understanding".
     */
    @Test fun negative_versionOtherThan13IsRefused() =
        serverTest {
            val reached = CompletableDeferred<Unit>()
            val (server, port) =
                h2TlsServer {
                    install(WebSockets)
                    routing { webSocket("/ws") { reached.complete(Unit) } }
                }
            try {
                h2(port) { c ->
                    val missing = c.connect(fields = emptyList())
                    assertEquals(400, missing.response().status)
                    missing.release()
                    val eight = c.connect(fields = listOf("sec-websocket-version" to "8"))
                    val head = eight.response()
                    assertEquals(426, head.status)
                    assertEquals(listOf("13"), head.fields.filter { it.first == "sec-websocket-version" }.map { it.second })
                    eight.release()
                    val two = c.connect(fields = listOf("sec-websocket-version" to "13", "sec-websocket-version" to "13"))
                    assertEquals(400, two.response().status)
                    two.release()
                }
                assertTrue(!reached.isCompleted, "the route never ran")
            } finally {
                server.stop(100, 500)
            }
        }

    /** With `webSocketsOverHttp2 = false` no SETTINGS_ENABLE_CONNECT_PROTOCOL is sent, so `:protocol` makes the request malformed. */
    @Test fun negative_extendedConnectRefusedWhenDisabled() =
        serverTest {
            val (server, port) = h2TlsServer(configure = { webSocketsOverHttp2 = false }) { echo() }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    raw.headers(1, extendedConnect(), endStream = false)
                    val rst = assertNotNull(raw.await { it.stream == 1 })
                    assertEquals(RawFrame.RST_STREAM, rst.type)
                    assertEquals(Http2ErrorCode.PROTOCOL_ERROR.code, rst.errorCode)
                    assertNull(assertNotNull(raw.serverSettings)[0x8], "SETTINGS_ENABLE_CONNECT_PROTOCOL is not sent")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 9113 section 8.5: after the initial HEADERS only DATA go on the stream, and anything else "MUST be treated as a
     * stream error (Section 5.4.2) if received": a client's HEADERS (trailers) on its WebSocket stream resets it with
     * PROTOCOL_ERROR, and the session ends; the connection stays.
     */
    @Test fun negative_headersOnAWebSocketStreamAreAStreamError() =
        serverTest {
            val ended = CompletableDeferred<Unit>()
            val (server, port) =
                h2TlsServer {
                    install(WebSockets)
                    routing {
                        webSocket("/ws") {
                            try {
                                for (frame in incoming) { }
                            } finally {
                                ended.complete(Unit)
                            }
                        }
                    }
                }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    raw.headers(1, extendedConnect(), endStream = false)
                    assertNotNull(raw.await { it.stream == 1 && it.type == RawFrame.HEADERS })
                    raw.headers(1, listOf("x-trailer" to "1"), endStream = true)
                    val rst = assertNotNull(raw.await { it.stream == 1 && it.type == RawFrame.RST_STREAM })
                    assertEquals(Http2ErrorCode.PROTOCOL_ERROR.code, rst.errorCode)
                    withTimeout(10.seconds) { ended.await() }
                    raw.headers(3, RawH2Client.get("/"), endStream = true)
                    assertNotNull(raw.await { it.stream == 3 && it.type == RawFrame.HEADERS }, "the connection goes on")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** RFC 8441 section 5: a RST_STREAM (CANCEL) is the TCP reset of RFC 6455: the server's session ends, nothing escapes. */
    @Test fun peerResetEndsTheSession() =
        serverTest {
            val log = CapturedLog()
            val started = CompletableDeferred<Unit>()
            val ended = CompletableDeferred<Unit>()
            val (server, port) =
                h2TlsServer(log = log) {
                    install(WebSockets)
                    routing {
                        webSocket("/ws") {
                            started.complete(Unit)
                            try {
                                for (frame in incoming) { }
                            } finally {
                                ended.complete(Unit)
                            }
                        }
                    }
                }
            try {
                h2(port) { c ->
                    val s = c.connect()
                    assertEquals(200, s.response().status)
                    withTimeout(10.seconds) { started.await() }
                    s.cancel()
                    withTimeout(10.seconds) { ended.await() }
                    s.release()
                }
                assertTrue(log.lines.all { it.level == "ERROR" && "Websocket handler failed" in it.message }, "${log.lines}")
            } finally {
                server.stop(100, 500)
            }
        }

    /** Ktor's writer closes the output right after a server Close frame; the client's Close still arrives. */
    @Test fun serverInitiatedCloseReceivesClientReason() =
        serverTest {
            val reply = CompletableDeferred<CloseReason?>()
            val (server, port) =
                h2TlsServer {
                    install(WebSockets)
                    routing {
                        webSocketRaw("/ws") {
                            outgoing.send(Frame.Close(CloseReason(CloseReason.Codes.GOING_AWAY, "server bye")))
                            reply.complete((incoming.receiveCatching().getOrNull() as? Frame.Close)?.readReason())
                        }
                    }
                }
            try {
                h2(port) { c ->
                    val s = c.connect()
                    assertEquals(200, s.response().status)
                    coroutineScopeWithJob { scope ->
                        val (ws, _) = scope.session(s)
                        assertEquals("server bye", (ws.incoming.receive() as Frame.Close).readReason()?.message)
                        ws.outgoing.send(Frame.Close(CloseReason(CloseReason.Codes.NORMAL, "client bye")))
                        assertEquals(CloseReason(CloseReason.Codes.NORMAL, "client bye"), withTimeout(5.seconds) { reply.await() })
                    }
                    s.release()
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * The frames are checked against the extensions the handshake negotiated (RFC 6455 section 5.2), as over HTTP/1.1 and
     * HTTP/3: RSV1 without an extension fails the connection with a Close frame with code 1002.
     */
    @Test fun negative_rsv1WithoutNegotiationClosesWith1002() =
        serverTest {
            val (server, port) = h2TlsServer { echo() }
            try {
                h2(port) { c ->
                    val s = c.connect()
                    assertEquals(200, s.response().status)
                    val out = ByteChannel()
                    coroutineScopeWithJob { scope ->
                        scope.launch { runCatching { s.sendBody(out, stallMillis = null) { error("no stall") } } }
                        out.writeFully(byteArrayOf(0xC1.toByte(), 0x80.toByte(), 1, 2, 3, 4))
                        out.flush()
                        val head = withTimeout(10.seconds) { s.body.readByteArray(4) }
                        assertEquals(0x88.toByte(), head[0], "a Close frame")
                        assertEquals(1002, ((head[2].toInt() and 0xff) shl 8) or (head[3].toInt() and 0xff))
                        out.close()
                    }
                    s.release()
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A call cancelled while its upgrade runs, with an upgrade that never ends by itself: the stream is reset with CANCEL
     * (RFC 8441 section 5: "RST exceptions are represented with the RST_STREAM frame ... with the CANCEL error code"),
     * never left open both ways.
     */
    @Test fun cancelledUpgradeResetsItsStreamWithCancel() =
        serverTest {
            val (server, port) =
                h2TlsServer {
                    routing {
                        get("/ws") {
                            val callJob = call.coroutineContext.job
                            call.respond(
                                object : OutgoingContent.ProtocolUpgrade() {
                                    override suspend fun upgrade(
                                        input: ByteReadChannel,
                                        output: ByteWriteChannel,
                                        engineContext: CoroutineContext,
                                        userContext: CoroutineContext,
                                    ): Job {
                                        callJob.cancel()
                                        return Job()
                                    }
                                },
                            )
                        }
                    }
                }
            try {
                h2(port) { c ->
                    val s = c.connect()
                    // the reset may overtake the 200 the client reads (both are queued), so the head itself may fail with it
                    val failure =
                        withTimeout(10.seconds) {
                            assertFailsWith<Http2Exception.StreamReset> {
                                s.response()
                                val b = ByteArray(1024)
                                while (s.body.readAvailable(b, 0, b.size) >= 0) { }
                            }
                        }
                    assertEquals(Http2ErrorCode.CANCEL, failure.code)
                    s.release()
                }
            } finally {
                server.stop(100, 500)
            }
        }

    private fun extendedConnect(path: String = "/ws"): List<Pair<String, String>> =
        listOf(
            ":method" to "CONNECT",
            ":protocol" to "websocket",
            ":scheme" to "https",
            ":authority" to "server.test",
            ":path" to path,
            "sec-websocket-version" to "13",
        )
}

/** Runs [block] with a scope whose coroutines are cancelled when it returns. */
private suspend fun <T> coroutineScopeWithJob(block: suspend (CoroutineScope) -> T): T {
    val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    try {
        return block(scope)
    } finally {
        scope.cancel()
    }
}
