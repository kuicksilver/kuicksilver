// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalKuicksilverApi::class)

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
import io.ktor.websocket.Frame
import io.ktor.websocket.RawWebSocket
import io.ktor.websocket.readText
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.runtime.H2ServerStream
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
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
