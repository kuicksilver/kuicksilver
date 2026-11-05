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
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketExtension
import io.ktor.websocket.WebSocketExtensionFactory
import io.ktor.websocket.WebSocketExtensionHeader
import io.ktor.websocket.parseWebSocketExtensions
import io.ktor.websocket.readBytes
import io.ktor.websocket.readText
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
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
 * Kuicksilver's [PerMessageDeflate] (RFC 7692) in the client engine, over HTTP/1.1 and HTTP/3 (RFC 9220): against the
 * server engine with the same extension, and against raw servers that check the bytes on the wire and send what a
 * well-behaved server would not (a decompression bomb, an invalid answer).
 */
class ClientDeflateTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun bytes(vararg b: Int) = ByteArray(b.size) { b[it].toByte() }

    private val text = buildString { while (length < 64 * 1024) append("kuicksilver permessage-deflate ${length % 89} ") }
    private val binary = ByteArray(300_000) { (it % 251 xor it / 1000).toByte() }

    private fun io.ktor.server.application.Application.echo() {
        install(ServerWebSockets) { extensions { install(PerMessageDeflate) } }
        routing {
            serverWebSocket("/ws") {
                send(Frame.Text(call.request.headers["Sec-WebSocket-Extensions"] ?: "none"))
                for (frame in incoming) send(frame.copy())
            }
        }
    }

    private suspend fun roundTrip(
        discovery: Http3DiscoveryMode,
        url: (Int) -> String,
        plain: Boolean,
    ) {
        val (server, port) = testServer(plain = plain) { echo() }
        try {
            testClient(discovery, block = { install(WebSockets) { extensions { install(PerMessageDeflate) } } }).use { c ->
                c.webSocket(url(port)) {
                    assertEquals("permessage-deflate", (incoming.receive() as Frame.Text).readText(), "what the server was offered")
                    assertEquals(listOf("permessage-deflate"), extensions.flatMap { e -> e.protocols.map { it.name } })
                    repeat(3) {
                        // context takeover across messages, both ways
                        send(Frame.Text(text))
                        assertEquals(text, (incoming.receive() as Frame.Text).readText())
                    }
                    send(Frame.Binary(true, binary)) // more than one 64 KiB piece once inflated
                    assertEquals(binary.toList(), incoming.receive().readBytes().toList())
                    send(Frame.Text(""))
                    assertEquals("", (incoming.receive() as Frame.Text).readText())
                }
            }
        } finally {
            server.stop(100, 500)
        }
    }

    @Test fun roundTripOverH1() = clientTest { roundTrip(Http3DiscoveryMode.H1Only, { "ws://127.0.0.1:$it/ws" }, plain = true) }

    @Test fun roundTripOverH3() = h3Test { roundTrip(Http3DiscoveryMode.H3Only, { "wss://127.0.0.1:$it/ws" }, plain = false) }

    /** On the wire: the server's RFC 7692 section 7.2.3 examples are read, and the client's message carries RSV1, compressed. */
    @Test fun wireFormatAgainstARawServer() =
        clientTest {
            val (b0, payload) =
                rawH1Server("permessage-deflate") { input, output ->
                    // 7.2.3.1 then 7.2.3.2 (refers back into the first)
                    output.writeFully(bytes(0xc1, 0x07, 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0xc1, 0x05, 0xf2, 0x00, 0x11, 0x00, 0x00))
                    output.flush()
                    readFrame(input)
                }.second
            assertEquals(listOf("Hello", "Hello"), lastTexts)
            assertEquals(0xC1, b0, "a final text frame with RSV1")
            val server = PerMessageDeflate.install {}
            server.serverNegotiation(parseWebSocketExtensions("permessage-deflate"))
            assertEquals(
                "Hello, raw server",
                (server.processIncomingFrame(Frame.Text(true, payload, true, false, false)) as Frame.Text).readText(),
            )
        }

    private var lastTexts = emptyList<String>()

    /** RFC 7692 section 7, RFC 6455 section 4.1: an answer the client must fail on fails the call; no session opens. */
    @Test fun negative_invalidDeflateResponseFailsHandshake() =
        clientTest {
            for (answer in listOf("permessage-deflate; client_max_window_bits=10", "permessage-deflate; server_max_window_bits=16")) {
                var opened = false
                rawH1Server(answer, client = { port ->
                    testClient(block = { install(WebSockets) { extensions { install(PerMessageDeflate) } } }).use { c ->
                        val e = assertFailsWith<WebSocketException>(answer) { c.webSocket("ws://127.0.0.1:$port/ws") { opened = true } }
                        assertTrue("permessage-deflate" in e.message.orEmpty(), e.message)
                    }
                }) { _, _ -> }
                assertEquals(false, opened, answer)
            }
        }

    /** RFC 7692 section 5: an answer that accepts permessage-deflate together with another RSV1 extension fails. */
    @Test fun negative_deflateAcceptedWithAnotherRsv1ExtensionFailsHandshake() =
        clientTest {
            var opened = false
            rawH1Server("permessage-deflate, x-rsv1", client = { port ->
                testClient(block = {
                    install(WebSockets) {
                        extensions {
                            install(PerMessageDeflate)
                            install(XRsv1)
                        }
                    }
                }).use { c ->
                    val e = assertFailsWith<WebSocketException> { c.webSocket("ws://127.0.0.1:$port/ws") { opened = true } }
                    assertTrue("RSV1" in e.message.orEmpty(), e.message)
                }
            }) { _, _ -> }
            assertEquals(false, opened)
        }

    /** The other extension alone, or permessage-deflate alone, is fine. */
    @Test fun oneRsv1ExtensionAcceptedPasses() =
        clientTest {
            for (answer in listOf("permessage-deflate", "x-rsv1")) {
                var opened = false
                rawH1Server(answer, client = { port ->
                    testClient(block = {
                        install(WebSockets) {
                            extensions {
                                install(PerMessageDeflate)
                                install(XRsv1)
                            }
                        }
                    }).use { c ->
                        c.webSocket("ws://127.0.0.1:$port/ws") { opened = true }
                    }
                }) { _, _ -> }
                assertEquals(true, opened, answer)
            }
        }

    /** An extension of the application's that uses RSV1 too (it changes nothing). */
    private object XRsv1 : WebSocketExtensionFactory<Unit, XRsv1Extension> {
        override val key: AttributeKey<XRsv1Extension> = AttributeKey("x-rsv1")
        override val rsv1: Boolean = true
        override val rsv2: Boolean = false
        override val rsv3: Boolean = false

        override fun install(config: Unit.() -> Unit): XRsv1Extension = XRsv1Extension()
    }

    private class XRsv1Extension : WebSocketExtension<Unit> {
        override val factory: WebSocketExtensionFactory<Unit, out WebSocketExtension<Unit>> = XRsv1
        override val protocols: List<WebSocketExtensionHeader> = listOf(WebSocketExtensionHeader("x-rsv1", emptyList()))

        override fun clientNegotiation(negotiatedProtocols: List<WebSocketExtensionHeader>): Boolean =
            negotiatedProtocols.any { it.name == "x-rsv1" }

        override fun serverNegotiation(requestedProtocols: List<WebSocketExtensionHeader>): List<WebSocketExtensionHeader> =
            requestedProtocols.filter { it.name == "x-rsv1" }

        override fun processOutgoingFrame(frame: Frame): Frame = frame

        override fun processIncomingFrame(frame: Frame): Frame = frame
    }

    private fun bomb(): ByteArray {
        val c = PerMessageDeflate.install { compressionLevel = 9 }
        c.serverNegotiation(parseWebSocketExtensions("permessage-deflate"))
        val payload = c.processOutgoingFrame(Frame.Binary(true, ByteArray(10 * 1024 * 1024))).data
        c.dispose()
        return payload
    }

    private fun serverFrame(
        b0: Int,
        payload: ByteArray,
    ): ByteArray {
        val n = payload.size
        val header = if (n < 126) bytes(b0, n) else bytes(b0, 126, n shr 8, n and 0xff)
        return header + payload
    }

    /** A compressed message that inflates past the limit closes the connection with 1009; the client keeps running. */
    @Test fun negative_bombFromServerClosesWith1009() =
        clientTest {
            val bomb = bomb()
            assertTrue(bomb.size < 65536)
            var closeCode: Short? = null
            var received: Result<Frame>? = null
            val reply =
                rawH1Server("permessage-deflate", client = { port ->
                    testClient(block = {
                        install(WebSockets) {
                            extensions {
                                install(PerMessageDeflate) {
                                    maxInflatedMessageSize =
                                        1024 * 1024
                                }
                            }
                        }
                    })
                        .use { c ->
                            c.webSocket("ws://127.0.0.1:$port/ws") {
                                received = runCatching { incoming.receive() }
                                closeCode = closeReason.await()?.code
                            }
                        }
                }) { input, output ->
                    output.writeFully(serverFrame(0xC2, bomb))
                    output.flush()
                    readFrame(input)
                }.second
            assertTrue(received?.isFailure == true, "nothing of the message is delivered, got $received")
            assertEquals(1009.toShort(), closeCode, "the session's own close reason")
            assertEquals(0x88, reply.first, "the client answers with a Close frame")
            assertEquals(1009, closeCodeOf(reply.second))
        }

    @Test fun negative_bombFromServerClosesWith1009H3() =
        h3Test {
            val bomb = bomb()
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
                coroutineScope {
                    val served =
                        async {
                            val s =
                                ep.accept().acceptRequest().acceptConnect(
                                    Http3Headers(
                                        listOf("sec-websocket-extensions" to "permessage-deflate"),
                                    ),
                                )
                            s.output.writeFully(serverFrame(0xC2, bomb))
                            s.output.flush()
                            readFrame(s.input)
                        }
                    testClient(Http3DiscoveryMode.H3Only, block = {
                        install(WebSockets) { extensions { install(PerMessageDeflate) { maxInflatedMessageSize = 1024 * 1024 } } }
                    }).use { c ->
                        c.webSocket("wss://127.0.0.1:${ep.localAddress.port}/ws") {
                            assertTrue(runCatching { incoming.receive() }.isFailure)
                            assertEquals(1009.toShort(), closeReason.await()?.code)
                        }
                        val (b0, payload) = withTimeout(10.seconds) { served.await() }
                        assertEquals(0x88, b0)
                        assertEquals(1009, closeCodeOf(payload))
                    }
                }
            } finally {
                ep.close()
            }
        }

    private fun closeCodeOf(payload: ByteArray) = ((payload[0].toInt() and 0xff) shl 8) or (payload[1].toInt() and 0xff)

    /** The first byte and the unmasked payload of the next frame on [input] (a client's frames are masked). */
    private suspend fun readFrame(input: ByteReadChannel): Pair<Int, ByteArray> {
        val b0 = input.readByte().toInt() and 0xff
        val b1 = input.readByte().toInt() and 0xff
        var length = (b1 and 0x7f).toLong()
        if (length == 126L) {
            length = input.readByteArray(2).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xff) }
        } else if (length == 127L) {
            length = input.readByteArray(8).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xff) }
        }
        val mask = if (b1 and 0x80 != 0) input.readByteArray(4) else ByteArray(4)
        val payload = input.readByteArray(length.toInt())
        for (i in payload.indices) payload[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
        return b0 to payload
    }

    /**
     * A raw HTTP/1.1 WebSocket server on 127.0.0.1: answers the upgrade with a 101 that accepts [extensions], then runs
     * [serve] on the connection while [client] (by default a session that sends "Hello, raw server" and collects the
     * texts it receives until the connection ends) talks to it; returns what each produced.
     */
    private suspend fun <T> rawH1Server(
        extensions: String,
        client: suspend (Int) -> Unit = { port -> defaultClient(port) },
        serve: suspend (ByteReadChannel, ByteWriteChannel) -> T,
    ): Pair<Unit, T> {
        val selector = SelectorManager(Dispatchers.IO)
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
                                    "Sec-WebSocket-Accept: unchecked\r\nSec-WebSocket-Extensions: $extensions\r\n\r\n",
                            )
                            serve(input, output)
                        }
                    }
                withTimeout(20.seconds) { client((listener.localAddress as InetSocketAddress).port) }
                Unit to withTimeout(10.seconds) { served.await() }
            }
        } finally {
            listener.close()
            selector.close()
        }
    }

    private suspend fun defaultClient(port: Int) {
        testClient(block = { install(WebSockets) { extensions { install(PerMessageDeflate) } } }).use { c ->
            c.webSocket("ws://127.0.0.1:$port/ws") {
                val texts = ArrayList<String>()
                texts += (incoming.receive() as Frame.Text).readText()
                texts += (incoming.receive() as Frame.Text).readText()
                lastTexts = texts
                send(Frame.Text("Hello, raw server"))
            }
        }
    }
}
