// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.plugins.websocket.WebSocketException
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.application.install
import io.ktor.server.routing.routing
import io.ktor.util.AttributeKey
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketExtension
import io.ktor.websocket.WebSocketExtensionFactory
import io.ktor.websocket.WebSocketExtensionHeader
import io.ktor.websocket.close
import io.ktor.websocket.readText
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import io.ktor.server.websocket.WebSockets as ServerWebSockets
import io.ktor.server.websocket.webSocket as serverWebSocket

/**
 * WebSocket extension negotiation in the client engine (RFC 6455 sections 4.1, 5.2 and 9.1; RFC 9220 section 3): Ktor's
 * plugin offers the installed extensions, the engine fails a handshake that accepts one it did not offer, and frames with
 * RSV bits no negotiated extension defines end the session with a Close frame with code 1002.
 */
class ClientWebSocketExtensionsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun extensionsHeaderOfferedWhenCapabilityDeclaredH1() =
        clientTest {
            val (server, port) = testServer(plain = true) { echoOfferedExtensions() }
            try {
                testClient(block = { install(WebSockets) { extensions { install(XTest) } } }).use { c ->
                    c.webSocket("ws://127.0.0.1:$port/ws") {
                        assertEquals("x-test", (incoming.receive() as Frame.Text).readText())
                        assertEquals(listOf("x-test"), extensions.flatMap { e -> e.protocols.map { it.name } })
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun extensionsHeaderOfferedWhenCapabilityDeclaredH3() =
        h3Test {
            val (server, port) = testServer { echoOfferedExtensions() } // TLS: HTTP/1.1 and HTTP/3
            try {
                testClient(Http3DiscoveryMode.H3Only, block = { install(WebSockets) { extensions { install(XTest) } } }).use { c ->
                    c.webSocket("wss://127.0.0.1:$port/ws") {
                        assertEquals("x-test", (incoming.receive() as Frame.Text).readText())
                        assertEquals(listOf("x-test"), extensions.flatMap { e -> e.protocols.map { it.name } })
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** RFC 6455 section 4.1: a 101 that accepts an extension the client did not offer fails the connection. */
    @Test fun negative_unofferedExtensionInResponseFailsHandshake() =
        clientTest {
            var opened = false
            rawH1WebSocketServer(extensions = "x-foo", frames = ByteArray(0)) { port ->
                testClient(block = { install(WebSockets) }).use { c ->
                    val e = assertFailsWith<WebSocketException> { c.webSocket("ws://127.0.0.1:$port/ws") { opened = true } }
                    assertTrue("x-foo" in e.message.orEmpty(), e.message)
                }
            }
            assertEquals(false, opened)
        }

    @Test fun negative_unofferedExtensionInResponseFailsHandshakeH3() =
        h3Test {
            var opened = false
            rawH3WebSocketServer(extensions = "x-foo", frames = ByteArray(0)) { port, _ ->
                testClient(Http3DiscoveryMode.H3Only, block = { install(WebSockets) }).use { c ->
                    assertFailsWith<WebSocketException> { c.webSocket("wss://127.0.0.1:$port/ws") { opened = true } }
                }
            }
            assertEquals(false, opened)
        }

    /** RFC 6455 section 5.2: RSV1 on a frame with no extension negotiated fails the connection with 1002. */
    @Test fun negative_rsv1WithoutNegotiationClosesWith1002() =
        clientTest {
            var received: Result<Frame>? = null
            var closeCode: Short? = null
            val reply =
                rawH1WebSocketServer(extensions = null, frames = byteArrayOf(0xC1.toByte(), 0x00)) { port ->
                    testClient(block = { install(WebSockets) }).use { c ->
                        c.webSocket("ws://127.0.0.1:$port/ws") {
                            received = runCatching { incoming.receive() }
                            closeCode = closeReason.await()?.code
                        }
                    }
                }
            assertEquals(1002, reply)
            assertTrue(received?.isFailure == true, "the bad frame is not delivered, got $received")
            assertEquals(1002.toShort(), closeCode, "the session's own close reason")
        }

    @Test fun negative_rsv1WithoutNegotiationClosesWith1002H3() =
        h3Test {
            val reply =
                rawH3WebSocketServer(extensions = null, frames = byteArrayOf(0xC1.toByte(), 0x00)) { port, served ->
                    testClient(Http3DiscoveryMode.H3Only, block = { install(WebSockets) }).use { c ->
                        c.webSocket("wss://127.0.0.1:$port/ws") {
                            assertTrue(runCatching { incoming.receive() }.isFailure)
                            assertEquals(1002.toShort(), closeReason.await()?.code)
                        }
                        // the client (and its QUIC connection) stays open until the server has read the Close reply
                        withTimeout(10.seconds) { served.await() }
                    }
                }
            assertEquals(1002, reply)
        }

    /**
     * A call that ends with a cause after its session sent the Close frame and finished its send side (the caller is
     * cancelled during the closing handshake) does not reset the HTTP/3 stream: the Close and the FIN still in flight
     * reach the peer, not a reset. The relay holds the client's packets until the call has ended, so the Close is still
     * unacknowledged when the call ends; before, the engine reset the send side then and the peer never got the Close.
     */
    @Test fun closeSentBeforeACancelledCallIsNotResetH3() =
        h3Test {
            val reply =
                rawH3WebSocketServer(extensions = null, frames = ByteArray(0), endsWithFin = true) { port, served ->
                    udpRelay(port) { relayPort, relay ->
                        testClient(Http3DiscoveryMode.H3Only, block = { install(WebSockets) }).use { c ->
                            val closeSent = CompletableDeferred<Unit>()
                            coroutineScope {
                                val call =
                                    launch {
                                        c.webSocket("wss://127.0.0.1:$relayPort/ws") {
                                            relay.blocked = true
                                            close(CloseReason(CloseReason.Codes.GOING_AWAY, "bye"))
                                            flush() // returns once the writer wrote the Close and finished the send side
                                            closeSent.complete(Unit)
                                            awaitCancellation()
                                        }
                                    }
                                withTimeout(10.seconds) { closeSent.await() }
                                call.cancel()
                                call.join()
                            }
                            relay.blocked = false
                            withTimeout(10.seconds) { served.await() }
                        }
                    }
                }
            assertEquals(1001, reply)
        }

    /** RFC 6455 section 5.1: a client fails the connection on a masked frame from the server, with 1002. */
    @Test fun negative_maskedFrameFromServerClosesWith1002() =
        clientTest {
            val masked = byteArrayOf(0x81.toByte(), 0x81.toByte(), 1, 2, 3, 4, 0x60) // text "a" masked with 01 02 03 04
            val reply =
                rawH1WebSocketServer(extensions = null, frames = masked) { port ->
                    testClient(block = { install(WebSockets) }).use { c ->
                        c.webSocket("ws://127.0.0.1:$port/ws") {
                            runCatching { incoming.receive() }
                            closeReason.await()
                        }
                    }
                }
            assertEquals(1002, reply)
        }

    /**
     * RFC 7692 section 6.1: with permessage-deflate negotiated, RSV1 belongs on the first frame of a message only; on a
     * continuation frame or a control frame it fails the connection with 1002.
     */
    @Test fun negative_rsv1OnContinuationOrControlFrameCloses1002() =
        clientTest {
            val continuation = byteArrayOf(0x41, 0x01, 0x61, 0xC0.toByte(), 0x01, 0x62) // text, RSV1, then RSV1 continuation
            val ping = byteArrayOf(0xC9.toByte(), 0x00) // ping with RSV1
            for (frames in listOf(continuation, ping)) {
                val reply =
                    rawH1WebSocketServer(extensions = "permessage-deflate", frames = frames) { port ->
                        testClient(block = { install(WebSockets) { extensions { install(FakeDeflate) } } }).use { c ->
                            c.webSocket("ws://127.0.0.1:$port/ws") {
                                runCatching { incoming.receive() }
                                closeReason.await()
                            }
                        }
                    }
                assertEquals(1002, reply, frames.joinToString { it.toUByte().toString(16) })
            }
        }

    /** The RSV1 a negotiated permessage-deflate defines passes on the first frame of a message. */
    @Test fun rsv1OnFirstFrameWithDeflateNegotiatedPasses() =
        clientTest {
            var text: String? = null
            rawH1WebSocketServer(extensions = "permessage-deflate", frames = byteArrayOf(0xC1.toByte(), 0x01, 0x61)) { port ->
                testClient(block = { install(WebSockets) { extensions { install(FakeDeflate) } } }).use { c ->
                    c.webSocket("ws://127.0.0.1:$port/ws") { text = (incoming.receive() as Frame.Text).readText() }
                }
            }
            assertEquals("a", text)
        }

    private fun io.ktor.server.application.Application.echoOfferedExtensions() {
        install(ServerWebSockets) { extensions { install(XTest) } }
        routing {
            serverWebSocket("/ws") {
                send(Frame.Text(call.request.headers["Sec-WebSocket-Extensions"] ?: "none"))
                runCatching { incoming.receive() }
            }
        }
    }

    /**
     * A raw HTTP/1.1 WebSocket server on 127.0.0.1 (a port the test binds): answers the upgrade with a 101 (with
     * [extensions] as `Sec-WebSocket-Extensions` when not null), sends [frames], then returns the close code of the
     * client's first frame (a Close frame), or -1 when the client sent none, after [block] ended.
     */
    private suspend fun rawH1WebSocketServer(
        extensions: String?,
        frames: ByteArray,
        block: suspend (Int) -> Unit,
    ): Int {
        val selector = SelectorManager(Dispatchers.Default)
        val listener = aSocket(selector).tcp().bind(InetSocketAddress("127.0.0.1", 0))
        try {
            return coroutineScope {
                val served =
                    async {
                        listener.accept().use { s ->
                            val input = s.openReadChannel()
                            val output = s.openWriteChannel(autoFlush = true)
                            while (input.readLine(LineEnding.Lenient)?.isNotEmpty() == true) continue
                            output.writeStringUtf8(
                                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                                    "Sec-WebSocket-Accept: unchecked\r\n" +
                                    (extensions?.let { "Sec-WebSocket-Extensions: $it\r\n" } ?: "") + "\r\n",
                            )
                            output.writeFully(frames)
                            closeCodeOfFirstFrame(input)
                        }
                    }
                withTimeout(20.seconds) { block((listener.localAddress as InetSocketAddress).port) }
                withTimeout(10.seconds) { served.await() }
            }
        } finally {
            listener.close()
            selector.close()
        }
    }

    /** As [rawH1WebSocketServer], over HTTP/3 (RFC 9220): the Extended CONNECT is answered with 200; [block] gets the reply too. */
    private suspend fun rawH3WebSocketServer(
        extensions: String?,
        frames: ByteArray,
        endsWithFin: Boolean = false,
        block: suspend (port: Int, served: Deferred<Int>) -> Unit,
    ): Int {
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
                    .apply { server = QuicServerConfig.Builder(serverTls).build() }
                    .build(),
                http3Settings { enableConnectProtocol = true },
            )
        try {
            return coroutineScope {
                val served =
                    async {
                        val conn = ep.accept()
                        val s =
                            conn.acceptRequest().acceptConnect(
                                Http3Headers(listOfNotNull(extensions?.let { "sec-websocket-extensions" to it })),
                            )
                        // a client that refuses the answer (an unoffered extension) may stop this stream before the frames go out
                        runCatching {
                            s.output.writeFully(frames)
                            s.output.flush()
                        }
                        val code = closeCodeOfFirstFrame(s.input)
                        // with endsWithFin, the client's send side must end with its FIN after the Close, not a reset
                        if (endsWithFin && runCatching { s.input.readBuffer() }.isFailure) -2 else code
                    }
                try {
                    withTimeout(20.seconds) { block(ep.localAddress.port, served) }
                    withTimeout(10.seconds) { served.await() }
                } finally {
                    served.cancel()
                }
            }
        } finally {
            ep.close()
        }
    }

    /** The close code of the client's first frame (masked, as a client's are), -1 for no frame or one that is not Close. */
    private suspend fun closeCodeOfFirstFrame(input: ByteReadChannel): Int =
        runCatching {
            val b0 = input.readByte().toInt() and 0xff
            val b1 = input.readByte().toInt() and 0xff
            val length = b1 and 0x7f // a Close frame's payload is at most 125 bytes
            val mask = if (b1 and 0x80 != 0) input.readByteArray(4) else ByteArray(4)
            val payload = input.readByteArray(length).mapIndexed { i, b -> (b.toInt() xor mask[i % 4].toInt()) and 0xff }
            if (b0 and 0x0f != 0x8 || payload.size < 2) -1 else (payload[0] shl 8) or payload[1]
        }.getOrDefault(-1)

    /** An extension named `x-test` that changes nothing (common code: Ktor's own deflate extension is JVM only). */
    private object XTest : NamedExtension.Factory("x-test", rsv1 = false)

    /** Answers to the name `permessage-deflate` without compressing: enough to negotiate RSV1 (frames here are plain). */
    private object FakeDeflate : NamedExtension.Factory("permessage-deflate", rsv1 = true)

    private class NamedExtension(
        override val factory: Factory,
    ) : WebSocketExtension<Unit> {
        open class Factory(
            val name: String,
            override val rsv1: Boolean,
        ) : WebSocketExtensionFactory<Unit, NamedExtension> {
            override val key: AttributeKey<NamedExtension> = AttributeKey<NamedExtension>(name)
            override val rsv2: Boolean = false
            override val rsv3: Boolean = false

            override fun install(config: Unit.() -> Unit): NamedExtension = NamedExtension(this)
        }

        override val protocols: List<WebSocketExtensionHeader> get() = listOf(WebSocketExtensionHeader(factory.name, emptyList()))

        override fun clientNegotiation(negotiatedProtocols: List<WebSocketExtensionHeader>): Boolean =
            negotiatedProtocols.any { it.name == factory.name }

        override fun serverNegotiation(requestedProtocols: List<WebSocketExtensionHeader>): List<WebSocketExtensionHeader> =
            requestedProtocols.filter { it.name == factory.name }

        override fun processOutgoingFrame(frame: Frame): Frame = frame

        override fun processIncomingFrame(frame: Frame): Frame = frame
    }
}
