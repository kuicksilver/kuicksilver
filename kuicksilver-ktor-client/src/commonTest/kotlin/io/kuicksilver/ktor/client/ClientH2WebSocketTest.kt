// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.plugins.websocket.WebSocketException
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.Frame
import io.ktor.websocket.RawWebSocket
import io.ktor.websocket.readText
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.runtime.H2ServerStream
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.concurrent.atomics.AtomicInt
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * WebSockets over HTTP/2 (RFC 8441) in the client engine: a WebSocket goes as an Extended CONNECT on an HTTP/2 connection
 * to its origin whose server enabled it (SETTINGS_ENABLE_CONNECT_PROTOCOL = 1, section 3), waiting for that connection's
 * SETTINGS before it decides; otherwise it is the HTTP/1.1 Upgrade of 0.2 (a connection that offers `http/1.1` only). The
 * server is our HTTP/2 runtime over a TLS listener on loopback, answering as each test needs.
 */
class ClientH2WebSocketTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private suspend fun ok(r: H2ServerStream) {
        r.respond(200, listOf("content-type" to "text/plain"))
        r.sendBody(ByteReadChannel("h2".encodeToByteArray()))
    }

    /** A server-side WebSocket echo on [r] (answered 200 with [fields]): each text frame back with "echo:". */
    private suspend fun CoroutineScope.echo(
        r: H2ServerStream,
        fields: List<Pair<String, String>> = emptyList(),
    ) {
        r.respond(200, fields)
        val out = ByteChannel()
        val sender = launch { runCatching { r.sendBody(out) } }
        val ws = RawWebSocket(r.body, out, masking = false, coroutineContext = coroutineContext)
        try {
            for (frame in ws.incoming) {
                when (frame) {
                    is Frame.Text -> {
                        ws.outgoing.send(Frame.Text("echo:" + frame.readText()))
                    }

                    is Frame.Close -> {
                        ws.outgoing.send(Frame.Close())
                    }

                    else -> {}
                }
            }
        } finally {
            ws.outgoing.close()
            sender.join()
        }
    }

    private fun client() = testClient(block = { install(WebSockets) })

    private fun engine(c: io.ktor.client.HttpClient) = c.engine as KuicksilverEngine

    @Test fun webSocketUsesAnH2ConnectionThatAllowsExtendedConnect() =
        clientTest {
            val request = CompletableDeferred<H2ServerStream>()
            val ended = CompletableDeferred<Boolean>()
            tlsH2WithSilentUdp(enableConnectProtocol = true, onRequest = { _, r ->
                if (r.method != "CONNECT") return@tlsH2WithSilentUdp ok(r)
                request.complete(r)
                echo(r, listOf("sec-websocket-protocol" to "chat"))
                // the client's END_STREAM after its Close: its side read to the end, no reset
                ended.complete(runCatching { r.body.readBuffer() }.isSuccess && !r.failed)
            }) { port, log ->
                client().use { c ->
                    assertEquals(HttpProtocolVersion.HTTP_2_0, c.get("https://127.0.0.1:$port/").version)
                    var version: HttpProtocolVersion? = null
                    var subprotocol: String? = null
                    c.webSocket("wss://127.0.0.1:$port/ws?x=1", request = { header("Sec-WebSocket-Protocol", "chat, superchat") }) {
                        version = call.response.version
                        subprotocol = call.response.headers["sec-websocket-protocol"]
                        send(Frame.Text("hi"))
                        assertEquals("echo:hi", (incoming.receive() as Frame.Text).readText())
                    }
                    assertEquals(HttpProtocolVersion.HTTP_2_0, version)
                    assertEquals("chat", subprotocol)
                    val r = request.await()
                    // RFC 8441 sections 4, 5: CONNECT with :protocol, :scheme https (wss), the WebSocket URI's path and
                    // authority; no Connection, Upgrade, Host or Sec-WebSocket-Key; Sec-WebSocket-Version as in RFC 6455
                    assertEquals("websocket", r.protocol)
                    assertEquals("https", r.scheme)
                    assertEquals("/ws?x=1", r.path)
                    assertEquals("127.0.0.1:$port", r.authority)
                    val names = r.fields.map { it.first }
                    for (n in listOf("connection", "upgrade", "host", "sec-websocket-key")) assertFalse(n in names, "$n in ${r.fields}")
                    assertEquals(listOf("13"), r.fields.filter { it.first == "sec-websocket-version" }.map { it.second })
                    assertTrue(withTimeout(10.seconds) { ended.await() }, "an orderly close both ways (END_STREAM, no reset)")
                    assertEquals(1, log.acceptCount, "one TCP connection for the GET and the WebSocket")
                }
            }
        }

    /** A server that did not enable Extended CONNECT: the WebSocket opens a connection of its own with `http/1.1` only. */
    @Test fun webSocketWithoutTheSettingGoesOverH1() =
        clientTest {
            val connects = CompletableDeferred<Unit>()
            tlsH2WithSilentUdp(onRequest = { _, r ->
                if (r.method == "CONNECT") connects.complete(Unit)
                ok(r)
            }, h1 = { _, input, _ -> readRequest(input) }) { port, log ->
                client().use { c ->
                    assertEquals(HttpProtocolVersion.HTTP_2_0, c.get("https://127.0.0.1:$port/").version)
                    runCatching { withTimeout(10.seconds) { c.webSocket("wss://127.0.0.1:$port/ws") {} } }
                    assertEquals(listOf<String?>("h2", "http/1.1"), log.protocols)
                    assertFalse(connects.isCompleted)
                }
            }
        }

    /**
     * RFC 8441 section 3: a client MUST NOT send `:protocol` before it received SETTINGS_ENABLE_CONNECT_PROTOCOL, and
     * whether it may is known only from the server's SETTINGS: on a connection whose SETTINGS have not arrived yet, the
     * WebSocket waits for them (within the connect timeout) and then takes the connection, instead of deciding on the
     * initial value (0) and opening another connection.
     */
    @Test fun webSocketWaitsForTheServersSettings() =
        clientTest {
            val release = CompletableDeferred<Unit>()
            val getArrived = CompletableDeferred<Unit>()
            val connected = CompletableDeferred<Unit>()
            tlsH2WithSilentUdp(enableConnectProtocol = true, holdOutputUntil = release, onRequest = { _, r ->
                if (r.method != "CONNECT") {
                    getArrived.complete(Unit)
                    return@tlsH2WithSilentUdp ok(r)
                }
                connected.complete(Unit)
                echo(r)
            }) { port, log ->
                client().use { c ->
                    coroutineScopeOf { scope ->
                        val get = scope.async { c.get("https://127.0.0.1:$port/").bodyAsText() }
                        // the GET's HEADERS reached the server: its connection is in the client's pool, SETTINGS still held
                        withTimeout(10.seconds) { getArrived.await() }
                        val ws =
                            scope.async {
                                c.webSocket("wss://127.0.0.1:$port/ws") {
                                    send(Frame.Text("a"))
                                    assertEquals("echo:a", (incoming.receive() as Frame.Text).readText())
                                }
                            }
                        release.complete(Unit)
                        assertEquals("h2", get.await())
                        withTimeout(10.seconds) { ws.await() }
                    }
                    assertTrue(connected.isCompleted)
                    assertEquals(listOf<String?>("h2"), log.protocols)
                }
            }
        }

    /** A non-2xx answer is no tunnel (RFC 9110 section 9.3.6): the handshake fails as an HTTP/1.1 one without 101 does. */
    @Test fun negative_refusedConnectFailsTheHandshake() =
        clientTest {
            tlsH2WithSilentUdp(enableConnectProtocol = true, onRequest = { _, r ->
                if (r.method != "CONNECT") return@tlsH2WithSilentUdp ok(r)
                r.respond(403, listOf("content-length" to "2"))
                r.sendBody(ByteReadChannel("no".encodeToByteArray()))
            }) { port, _ ->
                client().use { c ->
                    c.get("https://127.0.0.1:$port/")
                    assertFailsWith<WebSocketException> { c.webSocket("wss://127.0.0.1:$port/ws") {} }
                }
            }
        }

    /**
     * RFC 6455 section 4.1 (RFC 8441 section 5 keeps its Sec-WebSocket-Extensions and Sec-WebSocket-Protocol rules): an
     * extension or a subprotocol the client did not offer fails the WebSocket connection; the stream is reset with CANCEL.
     */
    @Test fun negative_unofferedExtensionOrSubprotocolFailsTheHandshake() =
        clientTest {
            val answers =
                listOf(
                    listOf("sec-websocket-extensions" to "permessage-deflate"),
                    listOf("sec-websocket-protocol" to "chat"),
                    listOf("sec-websocket-protocol" to "chat", "sec-websocket-protocol" to "chat"),
                )
            val resets = kotlinx.coroutines.channels.Channel<Throwable?>(kotlinx.coroutines.channels.Channel.UNLIMITED)
            var next = 0
            tlsH2WithSilentUdp(enableConnectProtocol = true, onRequest = { _, r ->
                if (r.method != "CONNECT") return@tlsH2WithSilentUdp ok(r)
                val failed = CompletableDeferred<Throwable>()
                r.invokeOnFailure { failed.complete(it) }
                r.respond(200, answers[next++])
                resets.send(withTimeout(10.seconds) { failed.await() })
            }) { port, _ ->
                client().use { c ->
                    c.get("https://127.0.0.1:$port/")
                    repeat(answers.size) { i ->
                        val offer = if (i == 2) "chat, superchat" else null
                        assertFailsWith<WebSocketException>("answer ${answers[i]}") {
                            c.webSocket("wss://127.0.0.1:$port/ws", request = { offer?.let { header("Sec-WebSocket-Protocol", it) } }) {}
                        }
                        val reset = assertIs<Http2Exception.StreamReset>(resets.receive())
                        assertEquals(Http2ErrorCode.CANCEL, reset.code)
                    }
                }
            }
        }

    /**
     * RFC 8441 section 5: a WebSocket the application abandons before its session opened (here while the server has not
     * answered yet) is reset with CANCEL ("RST exceptions are represented with the RST_STREAM frame ... with the CANCEL
     * error code"). Once open, Ktor's `webSocket {}` closes a cancelled session itself with a Close frame, and the stream
     * ends with END_STREAM.
     */
    @Test fun cancelledHandshakeResetsItsStreamWithCancel() =
        clientTest {
            val failure = CompletableDeferred<Throwable>()
            val arrived = CompletableDeferred<Unit>()
            tlsH2WithSilentUdp(enableConnectProtocol = true, onRequest = { _, r ->
                if (r.method != "CONNECT") return@tlsH2WithSilentUdp ok(r)
                r.invokeOnFailure { failure.complete(it) }
                arrived.complete(Unit)
                runCatching { r.body.readBuffer() } // no answer: the client gives up first
            }) { port, _ ->
                client().use { c ->
                    c.get("https://127.0.0.1:$port/")
                    coroutineScopeOf { scope ->
                        val ws = scope.launch { c.webSocket("wss://127.0.0.1:$port/ws") {} }
                        withTimeout(10.seconds) { arrived.await() }
                        ws.cancel()
                    }
                    val reset = assertIs<Http2Exception.StreamReset>(withTimeout(10.seconds) { failure.await() })
                    assertEquals(Http2ErrorCode.CANCEL, reset.code)
                }
            }
        }

    /** An HTTP/1.1 WebSocket echo on a TLS connection: the 101 with its real accept, then each text frame back with "h1:". */
    private suspend fun CoroutineScope.h1Echo(
        input: io.ktor.utils.io.ByteReadChannel,
        output: io.ktor.utils.io.ByteWriteChannel,
    ) {
        var key = ""
        input.readLine(io.ktor.utils.io.LineEnding.Lenient) ?: return
        while (true) {
            val h = input.readLine(io.ktor.utils.io.LineEnding.Lenient) ?: return
            if (h.isEmpty()) break
            if (h.startsWith("Sec-WebSocket-Key:", ignoreCase = true)) key = h.substringAfter(':').trim()
        }
        output.writeStringUtf8(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                "Sec-WebSocket-Accept: ${kotlin.io.encoding.Base64.encode(
                    io.ktor.util.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encodeToByteArray()),
                )}\r\n\r\n",
        )
        output.flush()
        val ws = RawWebSocket(input, output, masking = false, coroutineContext = coroutineContext)
        for (frame in ws.incoming) {
            when (frame) {
                is Frame.Text -> {
                    ws.outgoing.send(Frame.Text("h1:" + frame.readText()))
                }

                is Frame.Close -> {
                    ws.outgoing.send(Frame.Close())
                }

                else -> {}
            }
        }
        ws.outgoing.close()
    }

    /** The WebSocket's echo and the version it went over. */
    private suspend fun io.ktor.client.HttpClient.echoOnce(port: Int): Pair<HttpProtocolVersion, String> {
        var result: Pair<HttpProtocolVersion, String>? = null
        withTimeout(10.seconds) {
            webSocket("wss://127.0.0.1:$port/ws") {
                send(Frame.Text("x"))
                result = call.response.version to (incoming.receive() as Frame.Text).readText()
            }
        }
        return result!!
    }

    /**
     * RFC 9113 section 8.7: a CONNECT the server refused with REFUSED_STREAM was not processed and goes again; here on the
     * same connection, which still allows Extended CONNECT.
     */
    @Test fun refusedStreamWebSocketGoesAgain() =
        clientTest {
            val connects = AtomicInt(0)
            tlsH2WithSilentUdp(enableConnectProtocol = true, onRequest = { _, r ->
                if (r.method != "CONNECT") return@tlsH2WithSilentUdp ok(r)
                if (connects.addAndFetch(1) == 1) r.reset(Http2ErrorCode.REFUSED_STREAM) else echo(r)
            }) { port, log ->
                client().use { c ->
                    c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_2_0 to "echo:x", c.echoOnce(port))
                    assertEquals(2, connects.load())
                    assertEquals(1, log.acceptCount)
                }
            }
        }

    /**
     * A CONNECT above the server's GOAWAY was not processed (RFC 9113 section 8.7) and goes again; the connection takes no
     * new streams any more, and a WebSocket never opens an HTTP/2 connection, so the repeat goes over HTTP/1.1.
     */
    @Test fun webSocketAboveAGoAwayGoesAgainOverH1() =
        clientTest {
            val conns = Channel<io.kuicksilver.http2.runtime.H2ServerConnection>(Channel.UNLIMITED)
            tlsH2WithSilentUdp(
                enableConnectProtocol = true,
                onConnection = { _, conn -> conns.send(conn) },
                h1 = { _, input, output -> h1Echo(input, output) },
                onRequest = { _, r ->
                    if (r.method != "CONNECT") return@tlsH2WithSilentUdp ok(r)
                    conns.receive().goAway(Http2ErrorCode.NO_ERROR)
                    r.reset(Http2ErrorCode.REFUSED_STREAM)
                },
            ) { port, log ->
                client().use { c ->
                    c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_1_1 to "h1:x", c.echoOnce(port))
                    assertEquals(listOf<String?>("h2", "http/1.1"), log.protocols)
                }
            }
        }

    /**
     * RFC 9113 section 7: HTTP_1_1_REQUIRED on the CONNECT marks the route, and the WebSocket goes again over HTTP/1.1
     * (a WebSocket handshake is idempotent and has no body).
     */
    @Test fun http11RequiredSendsTheWebSocketOverH1() =
        clientTest {
            tlsH2WithSilentUdp(
                enableConnectProtocol = true,
                h1 = { _, input, output -> h1Echo(input, output) },
                onRequest = { _, r -> if (r.method == "CONNECT") r.reset(Http2ErrorCode.HTTP_1_1_REQUIRED) else ok(r) },
            ) { port, log ->
                client().use { c ->
                    c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_1_1 to "h1:x", c.echoOnce(port))
                    assertEquals(listOf<String?>("h2", "http/1.1"), log.protocols)
                }
            }
        }

    /** Through an HTTP CONNECT proxy the HTTP/2 connection is end to end with the origin, so the WebSocket uses it too. */
    @Test fun throughAConnectProxyTheWebSocketGoesOverH2() =
        clientTest {
            tlsH2WithSilentUdp(enableConnectProtocol = true, onRequest = { _, r ->
                if (r.method == "CONNECT") echo(r) else ok(r)
            }) { port, log ->
                ClientProxyTest().tunnelProxy(port) { proxyPort, head ->
                    testClient(
                        engine = {
                            proxy =
                                io.ktor.client.engine.ProxyBuilder
                                    .http(io.ktor.http.Url("http://127.0.0.1:$proxyPort"))
                        },
                        block = { install(WebSockets) },
                    ).use { c ->
                        assertEquals(HttpProtocolVersion.HTTP_2_0, c.get("https://127.0.0.1:$port/").version)
                        assertEquals(HttpProtocolVersion.HTTP_2_0 to "echo:x", c.echoOnce(port))
                        assertTrue(head().first().startsWith("CONNECT 127.0.0.1:$port"))
                        assertEquals(1, log.acceptCount)
                    }
                }
            }
        }

    /**
     * A connection whose server's SETTINGS never come does not hold a WebSocket for the whole connect timeout: after the
     * settings budget it goes over HTTP/1.1.
     */
    @Test fun negative_settingsThatNeverComeSendTheWebSocketOverH1() =
        clientTest {
            val never = CompletableDeferred<Unit>()
            val getArrived = CompletableDeferred<Unit>()
            tlsH2WithSilentUdp(
                enableConnectProtocol = true,
                holdOutputUntil = never,
                h1 = { _, input, output -> h1Echo(input, output) },
                onRequest = { _, r ->
                    getArrived.complete(Unit)
                    ok(r)
                },
            ) { port, log ->
                testClient(engine = { connectTimeout = 30.seconds }, block = { install(WebSockets) }).use { c ->
                    engine(c).h1.h2WebSocketSettingsWaitMillis = 200
                    coroutineScopeOf { scope ->
                        scope.launch { runCatching { c.get("https://127.0.0.1:$port/") } }
                        withTimeout(10.seconds) { getArrived.await() }
                        assertEquals(HttpProtocolVersion.HTTP_1_1 to "h1:x", c.echoOnce(port))
                    }
                    assertEquals(listOf<String?>("h2", "http/1.1"), log.protocols)
                }
            }
        }

    /**
     * The orderly close's wait is bounded as a whole: a server that never opens its window again keeps the session's last
     * frames (and END_STREAM) from going out, and after the close wait the stream is reset with CANCEL and its slot comes
     * back, instead of a sender that waits for ever.
     */
    @Test fun negative_closeWaitIsBoundedWhenTheServerNeverOpensTheWindow() =
        clientTest {
            val failure = CompletableDeferred<Throwable>()
            val sent = CompletableDeferred<Unit>()
            tlsH2WithSilentUdp(
                settings = Http2Settings(initialStreamWindow = 1_024),
                enableConnectProtocol = true,
                onRequest = { _, r ->
                    if (r.method != "CONNECT") return@tlsH2WithSilentUdp ok(r)
                    r.invokeOnFailure { failure.complete(it) }
                    r.respond(200)
                    sent.await()
                    // a Close 1000 of the server's, so the client's session closes at once; the stream stays open, and the
                    // client's frames are never read: no WINDOW_UPDATE
                    r.sendBody(ByteReadChannel(byteArrayOf(0x88.toByte(), 2, 0x03, 0xE8.toByte())), end = false)
                    kotlinx.coroutines.awaitCancellation()
                },
            ) { port, _ ->
                client().use { c ->
                    engine(c).h1.h2WebSocketCloseWaitMillis = 200
                    c.get("https://127.0.0.1:$port/")
                    withTimeout(10.seconds) {
                        c.webSocket("wss://127.0.0.1:$port/ws") {
                            outgoing.send(Frame.Binary(true, ByteArray(8_192)))
                            sent.complete(Unit)
                            while (!incoming.receiveCatching().isClosed) { }
                        }
                    }
                    val reset = assertIs<Http2Exception.StreamReset>(withTimeout(10.seconds) { failure.await() })
                    assertEquals(Http2ErrorCode.CANCEL, reset.code)
                    assertEquals(0, engine(c).h1.h2.streamCount)
                }
            }
        }

    /**
     * A connection that carries only a WebSocket is in use, not idle: the pool's idle retirement (idleTimeout) does not
     * count it while the session runs, and does once it ended.
     */
    @Test fun aConnectionCarryingAWebSocketIsNotIdle() =
        clientTest {
            val opened = CompletableDeferred<Unit>()
            val proceed = CompletableDeferred<Unit>()
            tlsH2WithSilentUdp(enableConnectProtocol = true, onRequest = { _, r ->
                if (r.method == "CONNECT") echo(r) else ok(r)
            }) { port, _ ->
                client().use { c ->
                    val pool = engine(c).h1.h2
                    c.get("https://127.0.0.1:$port/")
                    assertTrue(pool.evictExpired() != null, "idle after the GET: its retirement is scheduled")
                    coroutineScopeOf { scope ->
                        val ws =
                            scope.launch {
                                c.webSocket("wss://127.0.0.1:$port/ws") {
                                    opened.complete(Unit)
                                    proceed.await()
                                }
                            }
                        withTimeout(10.seconds) { opened.await() }
                        assertEquals(null, pool.evictExpired(), "the WebSocket's stream: nothing idle to retire")
                        assertEquals(1, pool.connectionCount)
                        proceed.complete(Unit)
                        ws.join()
                    }
                }
            }
        }

    /** A server's GOAWAY at or above the WebSocket's stream lets the session go on (RFC 9113 section 6.8). */
    @Test fun goAwayLeavesAnOpenSessionRunning() =
        clientTest {
            val conns = Channel<io.kuicksilver.http2.runtime.H2ServerConnection>(Channel.UNLIMITED)
            tlsH2WithSilentUdp(enableConnectProtocol = true, onConnection = { _, conn -> conns.send(conn) }, onRequest = { _, r ->
                if (r.method == "CONNECT") echo(r) else ok(r)
            }) { port, _ ->
                client().use { c ->
                    c.get("https://127.0.0.1:$port/")
                    val conn = conns.receive()
                    withTimeout(10.seconds) {
                        c.webSocket("wss://127.0.0.1:$port/ws") {
                            send(Frame.Text("a"))
                            assertEquals("echo:a", (incoming.receive() as Frame.Text).readText())
                            conn.goAway(Http2ErrorCode.NO_ERROR)
                            send(Frame.Text("b"))
                            assertEquals("echo:b", (incoming.receive() as Frame.Text).readText())
                        }
                    }
                }
            }
        }

    /**
     * Messages larger than a stream window both ways: the session's reading credits the peer (WINDOW_UPDATE as it
     * consumes) and the sender waits for window, so 2 MiB pass a 64 KiB stream window intact.
     */
    @Test fun messagesLargerThanTheWindowsPassBothWays() =
        clientTest {
            tlsH2WithSilentUdp(
                settings = Http2Settings(initialStreamWindow = 65_536, maxStreamWindow = 65_536),
                enableConnectProtocol = true,
                onRequest = { _, r ->
                    if (r.method != "CONNECT") return@tlsH2WithSilentUdp ok(r)
                    r.respond(200)
                    val out = ByteChannel()
                    val sender = launch { runCatching { r.sendBody(out) } }
                    val ws = RawWebSocket(r.body, out, masking = false, coroutineContext = coroutineContext)
                    for (frame in ws.incoming) {
                        if (frame is Frame.Binary) ws.outgoing.send(Frame.Binary(true, frame.data.reversedArray()))
                        if (frame is Frame.Close) break
                    }
                    ws.outgoing.close()
                    sender.join()
                },
            ) { port, _ ->
                testClient(
                    engine = { http2 { settings = Http2Settings(initialStreamWindow = 65_536, maxStreamWindow = 65_536) } },
                    block = { install(WebSockets) },
                ).use { c ->
                    c.get("https://127.0.0.1:$port/")
                    val big = ByteArray(2 * 1024 * 1024) { (it * 31).toByte() }
                    withTimeout(30.seconds) {
                        c.webSocket("wss://127.0.0.1:$port/ws") {
                            assertEquals(HttpProtocolVersion.HTTP_2_0, call.response.version)
                            send(Frame.Binary(true, big))
                            val back = incoming.receive() as Frame.Binary
                            assertTrue(back.data.contentEquals(big.reversedArray()))
                        }
                    }
                }
            }
        }
}

/** Runs [block] with a scope whose coroutines are cancelled once it returns. */
private suspend fun <T> coroutineScopeOf(block: suspend (CoroutineScope) -> T): T {
    val scope = CoroutineScope(kotlinx.coroutines.Dispatchers.Default + kotlinx.coroutines.SupervisorJob())
    try {
        return block(scope)
    } finally {
        scope.cancel()
    }
}

private fun CoroutineScope.cancel() = coroutineContext[kotlinx.coroutines.Job]!!.cancel()
