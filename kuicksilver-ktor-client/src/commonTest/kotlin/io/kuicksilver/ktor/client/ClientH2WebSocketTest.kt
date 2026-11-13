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
import io.kuicksilver.http2.runtime.H2StreamOutput
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicInt
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
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
     * The same with a last frame far larger than the server's window and the engine's 64 KiB lead (300 000 bytes): the
     * session's close does not wait for the lead (H2StreamOutput.flushAndClose hands the rest on and closes), so the close
     * wait still bounds it and the stream is reset with CANCEL. Before, the close waited inside the call for room that
     * never came.
     */
    @Test fun negative_closeWaitIsBoundedWithALastFrameBeyondTheLead() =
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
                            outgoing.send(Frame.Binary(true, ByteArray(300_000)))
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
     * A close the client starts (its own Close) to a server that stops reading and never answers: RFC 6455 section 7.1.1
     * lets the client close "at any time after sending ... a Close message" when the server does not close "in a
     * reasonable time period". The close wait starts when the session sends its Close; when neither the server's Close nor
     * its END_STREAM came by then, the stream is reset with CANCEL and the call ends (OkHttp gives up the same way, 60 s
     * after its Close). Before, Ktor's session waited for the server's Close for good, and the call with it.
     */
    private fun ownCloseIsBounded(lastFrame: Int) =
        clientTest {
            val failure = CompletableDeferred<Throwable>()
            tlsH2WithSilentUdp(
                settings = Http2Settings(initialStreamWindow = 1_024),
                enableConnectProtocol = true,
                onRequest = { _, r ->
                    if (r.method != "CONNECT") return@tlsH2WithSilentUdp ok(r)
                    r.invokeOnFailure { failure.complete(it) }
                    r.respond(200)
                    kotlinx.coroutines.awaitCancellation() // reads nothing (no WINDOW_UPDATE), answers nothing
                },
            ) { port, _ ->
                client().use { c ->
                    engine(c).h1.h2WebSocketCloseWaitMillis = 200
                    c.get("https://127.0.0.1:$port/")
                    withTimeout(10.seconds) {
                        c.webSocket("wss://127.0.0.1:$port/ws") {
                            outgoing.send(Frame.Binary(true, ByteArray(lastFrame)))
                            // the block ends: Ktor sends the client's Close and waits for the server's
                        }
                    }
                    val reset = assertIs<Http2Exception.StreamReset>(withTimeout(10.seconds) { failure.await() })
                    assertEquals(Http2ErrorCode.CANCEL, reset.code)
                    assertEquals(0, engine(c).h1.h2.streamCount)
                }
            }
        }

    @Test fun negative_ownCloseIsBoundedWhenTheServerNeverAnswers() = ownCloseIsBounded(8_192)

    /** The same behind a last frame far beyond the server's window and the engine's 64 KiB lead (300 000 bytes). */
    @Test fun negative_ownCloseIsBoundedBehindALastFrameBeyondTheLead() = ownCloseIsBounded(300_000)

    /**
     * The client's own Close releases the lead (as the server's Close does): a writer held behind a frame larger than the
     * lead stops waiting at once, so the Close and the stream's end go out as soon as the server opens its window, without
     * waiting for the close wait (60 s here). The server then reads everything, the Close among it, and answers it.
     */
    @Test fun negative_ownCloseReleasesTheLead() =
        clientTest {
            val gate = CompletableDeferred<Unit>()
            val serverSawClose = CompletableDeferred<Unit>()
            tlsH2WithSilentUdp(
                settings = Http2Settings(initialStreamWindow = 1_024),
                enableConnectProtocol = true,
                onRequest = { _, r ->
                    if (r.method != "CONNECT") return@tlsH2WithSilentUdp ok(r)
                    r.respond(200)
                    gate.await() // reads nothing until the client's writer was seen released
                    val out = ByteChannel()
                    val sender = launch { runCatching { r.sendBody(out) } }
                    val ws = RawWebSocket(r.body, out, masking = false, coroutineContext = coroutineContext)
                    try {
                        for (frame in ws.incoming) {
                            if (frame is Frame.Close) {
                                serverSawClose.complete(Unit)
                                ws.outgoing.send(Frame.Close())
                            }
                        }
                    } finally {
                        ws.outgoing.close()
                        sender.join()
                    }
                },
            ) { port, _ ->
                client().use { c ->
                    val output = CompletableDeferred<H2StreamOutput>()
                    engine(c).h1.h2WebSocketOutputForTest = { output.complete(it) }
                    engine(c).h1.h2WebSocketCloseWaitMillis = 60_000
                    c.get("https://127.0.0.1:$port/")
                    withTimeout(20.seconds) {
                        c.webSocket("wss://127.0.0.1:$port/ws") {
                            val out = output.await()
                            outgoing.send(Frame.Binary(true, ByteArray(300_000)))
                            out.writerWaiting.first { it } // held behind the lead
                            outgoing.send(Frame.Close())
                            // released by the Close, long before the close wait (60 s) could end anything
                            withTimeout(10.seconds) { out.writerWaiting.first { !it } }
                            gate.complete(Unit)
                            withTimeout(10.seconds) { serverSawClose.await() }
                        }
                    }
                }
            }
        }

    /**
     * The client's writer is held at the server's window plus the engine's lead (RFC 9113 section 5.2): against a server
     * that reads nothing (a 64 KiB window), the session's output waits in its flush with at most 64 KiB and one piece
     * flushed and not taken by the stream, however much the application sends.
     *
     * The application sends without end, so its session's outgoing channel is bounded ([OUTGOING_CAPACITY] frames, the
     * sender suspends): with Ktor's default, an unlimited channel, the frames the held writer does not take pile up in the
     * session as fast as the sender makes them, until the test JVM is out of heap. The sender is held too: once the
     * writer waits, it sends no more.
     */
    @Test fun negative_clientWriterIsHeldAtTheWindowAndTheLead() =
        clientTest {
            tlsH2WithSilentUdp(
                settings = Http2Settings(initialStreamWindow = 65_536, maxStreamWindow = 65_536),
                enableConnectProtocol = true,
                onRequest = { _, r ->
                    if (r.method != "CONNECT") return@tlsH2WithSilentUdp ok(r)
                    r.respond(200)
                    kotlinx.coroutines.awaitCancellation() // never reads: no WINDOW_UPDATE
                },
            ) { port, _ ->
                testClient(block = {
                    install(WebSockets) { channels { outgoing = bounded(OUTGOING_CAPACITY) } }
                }).use { c ->
                    val output = CompletableDeferred<io.kuicksilver.http2.runtime.H2StreamOutput>()
                    engine(c).h1.h2WebSocketOutputForTest = { output.complete(it) }
                    c.get("https://127.0.0.1:$port/")
                    val sent = AtomicInt(0)
                    coroutineScopeOf { scope ->
                        scope.launch {
                            runCatching {
                                c.webSocket("wss://127.0.0.1:$port/ws") {
                                    val frame = ByteArray(16_384)
                                    while (true) {
                                        outgoing.send(Frame.Binary(true, frame))
                                        sent.addAndFetch(1)
                                    }
                                }
                            }
                        }
                        val out = withTimeout(10.seconds) { output.await() }
                        // the writer waits only with more than the lead flushed and not taken, and the stream only ever takes
                        // more, so at a wait the lead is past 64 KiB by at most what that flush added (a piece of one frame)
                        var lead = 0L
                        withTimeout(10.seconds) {
                            out.writerWaiting.first {
                                lead = out.lead
                                it && lead > H2StreamOutput.DEFAULT_LIMIT
                            }
                        }
                        assertTrue(lead <= H2StreamOutput.DEFAULT_LIMIT + 16_388L, "lead $lead")
                        // and so is the sender: it settles (two reads 50 ms apart agree) within the cap, and then sends
                        // nothing more. One that is not held never settles; it is past the cap within milliseconds, where the
                        // wait stops (its frames share one array, so they cost the heap little meanwhile)
                        val settled =
                            withTimeoutOrNull(5.seconds) {
                                var previous = sent.load()
                                while (previous <= HELD_SENDER_MAX_FRAMES) {
                                    delay(50.milliseconds)
                                    val now = sent.load()
                                    if (now == previous) break
                                    previous = now
                                }
                                previous
                            }
                        assertTrue(
                            settled != null && settled <= HELD_SENDER_MAX_FRAMES,
                            "the sender did not settle: ${sent.load()} frames sent",
                        )
                        delay(250.milliseconds)
                        val later = sent.load()
                        assertEquals(settled, later, "the sender went on: $settled frames sent, then $later")
                        assertTrue(later <= HELD_SENDER_MAX_FRAMES, "$later frames sent")
                    }
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
                    // RFC 8441 section 5: an orderly close is END_STREAM both ways. The client's END_STREAM follows its Close;
                    // releasing the stream before it arrives stops the client with RST_STREAM NO_ERROR (RFC 9113 section 8.1)
                    // and fails the stream's body under the session's reader, a child of this handler, which then failed the
                    // test (about 1 in 20 on macosArm64): the handler waits for it, as the server engine does
                    assertTrue(withTimeout(10.seconds) { r.awaitClientEnd() })
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

    /**
     * The HTTP/2 form of the give-back: a WebSocket reserves a stream on its origin's HTTP/2 connection, finds that
     * connection's address held by another WebSocket (to another name, CONNECTING on its own connection), undoes the
     * reservation and waits for every key; then it reserves again and goes through. One stream is reserved while it
     * waits, none at the end.
     */
    @Test fun negative_aWebSocketWhoseConnectionsAddressIsHeldUnreservesAndWaits() =
        clientTest {
            val firstConnect = CompletableDeferred<Unit>()
            val decided = CompletableDeferred<Unit>()
            val webSocketPhase = kotlinx.coroutines.flow.MutableStateFlow(false)
            val never = CompletableDeferred<Unit>()
            val loopback4 =
                io.kuicksilver.ktor.network
                    .TcpAddress(byteArrayOf(127, 0, 0, 1), 0)
            val loopback6 =
                io.kuicksilver.ktor.network
                    .TcpAddress(ByteArray(16).also { it[15] = 1 }, 0)
            tlsH2WithSilentUdp(enableConnectProtocol = true, onRequest = { _, r ->
                if (r.method != "CONNECT") return@tlsH2WithSilentUdp ok(r)
                if (r.authority?.startsWith("b.wild.test") == true) {
                    firstConnect.complete(Unit)
                    decided.await()
                }
                echo(r)
            }) { port, _ ->
                testClient(
                    engine = {
                        familyResolverForTest = { name, v6 ->
                            when {
                                name == "b.wild.test" || !webSocketPhase.value -> {
                                    if (v6) emptyList() else listOf(loopback4)
                                }

                                v6 -> {
                                    listOf(loopback6)
                                }

                                else -> {
                                    never.await()
                                    emptyList()
                                }
                            }
                        }
                    },
                    block = { install(WebSockets) },
                ).use { c ->
                    val e = engine(c)
                    assertEquals(HttpProtocolVersion.HTTP_2_0, c.get("https://a.wild.test:$port/").version)
                    assertEquals(HttpProtocolVersion.HTTP_2_0, c.get("https://b.wild.test:$port/").version)
                    webSocketPhase.value = true
                    coroutineScopeOf { scope ->
                        val first =
                            scope.async {
                                c.webSocket("wss://b.wild.test:$port/ws") {
                                    send(Frame.Text("b"))
                                    incoming.receive()
                                }
                            }
                        withTimeout(10.seconds) { firstConnect.await() }
                        val second =
                            scope.async {
                                c.webSocket("wss://a.wild.test:$port/ws") {
                                    send(Frame.Text("a"))
                                    incoming.receive()
                                }
                            }
                        withTimeout(10.seconds) {
                            e.h1.webSocketConnecting.waitsForTest
                                .first { it >= 1 }
                        }
                        assertEquals(1, e.h1.h2.streamCount, "the waiting WebSocket kept its stream reserved")
                        decided.complete(Unit)
                        withTimeout(10.seconds) {
                            first.await()
                            second.await()
                        }
                    }
                    // A WebSocket's stream is released after its session ends (the close waits for the server's END_STREAM
                    // off the caller's path), so the count reaches 0 shortly after both sessions returned.
                    withTimeout(10.seconds) { while (e.h1.h2.streamCount != 0) delay(10) }
                    assertEquals(0, e.h1.webSocketConnecting.size())
                }
            }
            never.complete(Unit)
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

/** The outgoing channel of a session whose application sends without end: it suspends once this many frames wait. */
private const val OUTGOING_CAPACITY = 4

/**
 * The most frames a held sender gets out past a window that never opens: on the JVM, Ktor's writer takes up to 1 024 frames
 * into its serializer and the channels, the lead and the window some 20 more (1 041 measured); Kotlin/Native's writer (Ktor's
 * common one) takes one frame at a time, so far fewer there. Twice the JVM's serializer: a sender not held is far past it.
 */
private const val HELD_SENDER_MAX_FRAMES = 2 * 1_024
