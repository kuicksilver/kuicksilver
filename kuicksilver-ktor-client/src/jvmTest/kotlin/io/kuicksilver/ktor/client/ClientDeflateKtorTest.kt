// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.server.application.install
import io.ktor.server.routing.routing
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketDeflateExtension
import io.ktor.websocket.WebSocketExtensionFactory
import io.ktor.websocket.readBytes
import io.ktor.websocket.readText
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeout
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import io.ktor.server.websocket.WebSockets as ServerWebSockets
import io.ktor.server.websocket.webSocket as serverWebSocket

/**
 * Ktor's own permessage-deflate (`WebSocketDeflateExtension`, JVM only) on both ends of the Kuicksilver engines: the
 * client engine lets the plugin negotiate it, and both engines let the compressed frames' RSV1 through. Then Kuicksilver's
 * [PerMessageDeflate] against Ktor's, each way round: two implementations of RFC 7692 that must understand each other.
 * The engines decompress permessage-deflate themselves whichever extension negotiated it, so text Ktor's extension
 * carries is checked as UTF-8 too (RFC 7692 section 6), both ways.
 */
class ClientDeflateKtorTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val text = buildString { while (length < 64 * 1024) append("kuicksilver websocket deflate ${length % 97} ") }

    private fun io.ktor.server.application.Application.echo() {
        install(ServerWebSockets) { extensions { install(WebSocketDeflateExtension) } }
        routing {
            serverWebSocket("/ws") {
                val got = (incoming.receive() as Frame.Text).readText()
                send(Frame.Text(got))
                send(Frame.Text(call.request.headers["Sec-WebSocket-Extensions"] ?: "none"))
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
            testClient(discovery, block = { install(WebSockets) { extensions { install(WebSocketDeflateExtension) } } }).use { c ->
                c.webSocket(url(port)) {
                    send(Frame.Text(text))
                    assertEquals(text, (incoming.receive() as Frame.Text).readText())
                    assertEquals("permessage-deflate", (incoming.receive() as Frame.Text).readText().substringBefore(';').trim())
                    assertEquals(listOf("permessage-deflate"), extensions.flatMap { e -> e.protocols.map { it.name } }.distinct())
                }
            }
        } finally {
            server.stop(100, 500)
        }
    }

    private val binary = ByteArray(200_000) { (it % 253 xor it / 777).toByte() }

    /** [clientExtension] in the client engine, [serverExtension] in the server engine; messages both ways, several times. */
    private suspend fun interop(
        clientExtension: WebSocketExtensionFactory<*, *>,
        serverExtension: WebSocketExtensionFactory<*, *>,
        discovery: Http3DiscoveryMode,
        url: (Int) -> String,
        plain: Boolean,
    ) {
        val (server, port) =
            testServer(plain = plain) {
                install(ServerWebSockets) { extensions { install(serverExtension) } }
                routing {
                    serverWebSocket("/ws") {
                        send(Frame.Text(call.request.headers["Sec-WebSocket-Extensions"] ?: "none"))
                        for (frame in incoming) {
                            // Ktor's WebSocketDeflateExtension fails to compress an empty message after an earlier one
                            // (3.6.1: "byteCount: -5 < 0"), so an empty message is answered with words
                            send(if (frame.data.isEmpty()) Frame.Text("an empty message") else frame.copy())
                        }
                    }
                }
            }
        try {
            testClient(discovery, block = { install(WebSockets) { extensions { install(clientExtension) } } }).use { c ->
                c.webSocket(url(port)) {
                    assertEquals("permessage-deflate", (incoming.receive() as Frame.Text).readText().substringBefore(';').trim())
                    assertEquals(listOf("permessage-deflate"), extensions.flatMap { e -> e.protocols.map { it.name } }.distinct())
                    repeat(3) {
                        // the LZ77 window is carried across messages both ways
                        send(Frame.Text(text))
                        assertEquals(text, (incoming.receive() as Frame.Text).readText())
                        send(Frame.Binary(true, binary))
                        assertEquals(binary.toList(), incoming.receive().readBytes().toList())
                    }
                    if (clientExtension == PerMessageDeflate) { // Ktor's cannot send one (above)
                        send(Frame.Text("")) // RFC 7692 section 7.2.3.6: a single 0x00
                        assertEquals("an empty message", (incoming.receive() as Frame.Text).readText())
                    }
                }
            }
        } finally {
            server.stop(100, 500)
        }
    }

    @Test fun kuicksilverClientWithKtorServerExtensionH1() =
        clientTest { interop(PerMessageDeflate, WebSocketDeflateExtension, Http3DiscoveryMode.H1Only, { "ws://127.0.0.1:$it/ws" }, true) }

    @Test fun kuicksilverClientWithKtorServerExtensionH3() =
        h3Test { interop(PerMessageDeflate, WebSocketDeflateExtension, Http3DiscoveryMode.H3Only, { "wss://127.0.0.1:$it/ws" }, false) }

    @Test fun ktorClientWithKuicksilverServerExtensionH1() =
        clientTest { interop(WebSocketDeflateExtension, PerMessageDeflate, Http3DiscoveryMode.H1Only, { "ws://127.0.0.1:$it/ws" }, true) }

    @Test fun ktorClientWithKuicksilverServerExtensionH3() =
        h3Test { interop(WebSocketDeflateExtension, PerMessageDeflate, Http3DiscoveryMode.H3Only, { "wss://127.0.0.1:$it/ws" }, false) }

    @Test fun ktorDeflateExtensionRoundTripH1() =
        clientTest {
            roundTrip(
                Http3DiscoveryMode.H1Only,
                { "ws://127.0.0.1:$it/ws" },
                plain = true,
            )
        }

    @Test fun ktorDeflateExtensionRoundTripH3() =
        h3Test {
            roundTrip(
                Http3DiscoveryMode.H3Only,
                { "wss://127.0.0.1:$it/ws" },
                plain = false,
            )
        }

    /**
     * RFC 7692 section 6.1: Ktor's extension compresses each fragment of a message on its own and sets RSV1 on every one,
     * which a conforming receiver refuses (Kuicksilver's server closed with 1002). The client engine sends such a message
     * as an RFC 7692 one, and this library's server reassembles it.
     */
    @Test fun ktorsFragmentedCompressedMessageGoesOutAsRfc7692() =
        clientTest {
            val (server, port) =
                testServer(plain = true) {
                    install(ServerWebSockets) { extensions { install(PerMessageDeflate) } }
                    routing { serverWebSocket("/ws") { send(Frame.Text((incoming.receive() as Frame.Text).readText())) } }
                }
            try {
                testClient(block = { install(WebSockets) { extensions { install(WebSocketDeflateExtension) } } }).use { c ->
                    c.webSocket("ws://127.0.0.1:$port/ws") {
                        send(Frame.Text(false, "fragmented ".encodeToByteArray()))
                        send(Frame.Text(false, "and compressed ".encodeToByteArray()))
                        send(Frame.Text(true, "by Ktor".encodeToByteArray()))
                        assertEquals("fragmented and compressed by Ktor", (incoming.receive() as Frame.Text).readText())
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 7692 section 6: after decompression the payload is "subject to the constraints for the original data type
     * again". A compressed text message that inflates to C0 AF, with Ktor's extension negotiated, closes with 1007: the
     * engine inflates it by the extension's name. Before, Ktor's extension inflated it in the session and nothing checked.
     */
    @Test fun negative_compressedInvalidUtf8ThroughKtorsExtensionClosesWith1007() =
        clientTest {
            // a final stored DEFLATE block holding C0 AF
            val frame = byteArrayOf(0xC1.toByte(), 0x07, 0x01, 0x02, 0x00, 0xfd.toByte(), 0xff.toByte(), 0xC0.toByte(), 0xAF.toByte())
            var closeCode: Short? = null
            val received =
                rawServer(frame) { port ->
                    testClient(block = { install(WebSockets) { extensions { install(WebSocketDeflateExtension) } } }).use { c ->
                        c.webSocket("ws://127.0.0.1:$port/ws") {
                            runCatching { incoming.receive() }
                            closeCode = closeReason.await()?.code
                        }
                    }
                }
            assertEquals(1007.toShort(), closeCode)
            assertEquals(0x88, received[0].toInt() and 0xff, "the client's Close")
        }

    /**
     * RFC 6455 section 5.6: text Ktor's extension compresses is inflated on the side and checked; a message that is not
     * UTF-8 is not sent whole (the connection is reset after its header at most).
     */
    @Test fun negative_invalidUtf8CompressedByKtorsExtensionIsNotSent() =
        clientTest {
            val received =
                rawServer(ByteArray(0)) { port ->
                    testClient(block = { install(WebSockets) { extensions { install(WebSocketDeflateExtension) } } }).use { c ->
                        runCatching {
                            c.webSocket("ws://127.0.0.1:$port/ws") {
                                send(Frame.Text(true, byteArrayOf(0xC0.toByte(), 0xAF.toByte())))
                                runCatching { incoming.receive() }
                            }
                        }
                    }
                }
            // a masked frame header is 6 bytes; the compressed payload never follows it
            assertTrue(received.size <= 6, "the server received ${received.size} bytes")
        }

    /**
     * A raw HTTP/1.1 server on 127.0.0.1 that accepts one WebSocket with `permessage-deflate`, sends [frames] and returns
     * what the client sent after the handshake until it closed the connection.
     */
    private suspend fun rawServer(
        frames: ByteArray,
        block: suspend (Int) -> Unit,
    ): ByteArray =
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { listener ->
            coroutineScope {
                val served =
                    async(Dispatchers.IO) {
                        listener.accept().use { s ->
                            val input = s.getInputStream()
                            val head = StringBuilder()
                            while (!head.endsWith("\r\n\r\n")) head.append(input.read().toChar())
                            val key =
                                head
                                    .lines()
                                    .first {
                                        it.startsWith(
                                            "Sec-WebSocket-Key:",
                                            ignoreCase = true,
                                        )
                                    }.substringAfter(':')
                                    .trim()
                            s.getOutputStream().write(
                                (
                                    switchingProtocols(key, "Sec-WebSocket-Extensions: permessage-deflate\r\n")
                                ).encodeToByteArray() + frames,
                            )
                            val out = ByteArrayOutputStream()
                            runCatching { input.copyTo(out) }
                            out.toByteArray()
                        }
                    }
                withTimeout(20.seconds) { block(listener.localPort) }
                withTimeout(10.seconds) { served.await() }
            }
        }
}
