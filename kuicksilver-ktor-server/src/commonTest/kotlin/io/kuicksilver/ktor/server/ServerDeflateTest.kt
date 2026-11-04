// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.parseWebSocketExtensions
import io.ktor.websocket.readText
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.http3Request
import io.kuicksilver.ktor.network.tls
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * [PerMessageDeflate] (RFC 7692) in the server engine, over HTTP/1.1 and HTTP/3 (RFC 9220), against a raw client: the
 * negotiation answer, compressed frames both ways on the wire, and a decompression bomb closed with 1009.
 */
class ServerDeflateTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun bytes(vararg b: Int) = ByteArray(b.size) { b[it].toByte() }

    private val mask = bytes(0x11, 0x22, 0x33, 0x44)

    /** A masked frame, as a client sends it. */
    private fun clientFrame(
        b0: Int,
        payload: ByteArray,
    ): ByteArray {
        val n = payload.size
        val header = if (n < 126) bytes(b0, 0x80 or n) else bytes(b0, 0x80 or 126, n shr 8, n and 0xff)
        return header + mask + ByteArray(n) { (payload[it].toInt() xor mask[it % 4].toInt()).toByte() }
    }

    private val closeCode = CompletableDeferred<Short?>()

    private fun Application.deflateEcho() {
        install(WebSockets) { extensions { install(PerMessageDeflate) { maxInflatedMessageSize = 1024 * 1024 } } }
        routing {
            webSocket("/ws") {
                try {
                    for (frame in incoming) if (frame is Frame.Text) send(Frame.Text("echo: " + frame.readText()))
                } finally {
                    closeCode.complete(closeReason.await()?.code)
                }
            }
        }
    }

    private fun bomb(): ByteArray {
        val c = PerMessageDeflate.install { compressionLevel = 9 }
        c.clientNegotiation(parseWebSocketExtensions("permessage-deflate"))
        val payload = c.processOutgoingFrame(Frame.Binary(true, ByteArray(10 * 1024 * 1024))).data
        c.dispose()
        return payload
    }

    /** The first byte and payload of the next (unmasked) frame from the server. */
    private suspend fun readFrame(input: ByteReadChannel): Pair<Int, ByteArray> {
        val b0 = input.readByte().toInt() and 0xff
        val b1 = input.readByte().toInt() and 0xff
        var length = b1 and 0x7f
        if (length == 126) length = input.readByteArray(2).fold(0) { a, b -> (a shl 8) or (b.toInt() and 0xff) }
        return b0 to input.readByteArray(length)
    }

    private fun closeCodeOf(payload: ByteArray) = ((payload[0].toInt() and 0xff) shl 8) or (payload[1].toInt() and 0xff)

    /** RFC 7692 section 7.2.3.1 from the client; the server's echo comes back compressed, RSV1 on its only frame. */
    private suspend fun compressedEcho(
        input: ByteReadChannel,
        output: ByteWriteChannel,
    ) {
        output.writeFully(clientFrame(0xC1, bytes(0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00)))
        output.flush()
        val (b0, payload) = readFrame(input)
        assertEquals(0xC1, b0, "a final text frame with RSV1")
        val client = PerMessageDeflate.install {}
        client.clientNegotiation(parseWebSocketExtensions("permessage-deflate"))
        assertEquals("echo: Hello", (client.processIncomingFrame(Frame.Text(true, payload, true, false, false)) as Frame.Text).readText())
        output.writeFully(clientFrame(0x88, bytes(0x03, 0xe8)))
        output.flush()
    }

    private suspend fun bombed(
        input: ByteReadChannel,
        output: ByteWriteChannel,
    ) {
        output.writeFully(clientFrame(0xC2, bomb()))
        output.flush()
        val (b0, payload) = readFrame(input)
        assertEquals(0x88, b0, "the server closes")
        assertEquals(
            CloseReason.Codes.TOO_BIG.code
                .toInt(),
            closeCodeOf(payload),
        )
        assertEquals(1009.toShort(), withTimeout(10.seconds) { closeCode.await() }, "the session's own close reason")
    }

    @Test fun compressedEchoH1() = serverTest { h1("permessage-deflate", "permessage-deflate", ::compressedEcho) }

    @Test fun compressedEchoH3() = h3ServerTest { h3("permessage-deflate", "permessage-deflate", ::compressedEcho) }

    @Test fun negative_bombFromClientClosesWith1009() = serverTest { h1("permessage-deflate", "permessage-deflate", ::bombed) }

    @Test fun negative_bombFromClientClosesWith1009H3() = h3ServerTest { h3("permessage-deflate", "permessage-deflate", ::bombed) }

    /** An offer the server must decline (RFC 7692 section 5.1) is answered without the extension. */
    @Test fun invalidOfferDeclined() =
        serverTest {
            h1("permessage-deflate; server_max_window_bits=7", expected = null) { input, output ->
                output.writeFully(clientFrame(0x81, "plain".encodeToByteArray()))
                output.flush()
                val (b0, payload) = readFrame(input)
                assertEquals(0x81, b0, "no RSV1 without the extension")
                assertEquals("echo: plain", payload.decodeToString())
            }
        }

    private suspend fun h1(
        offer: String,
        expected: String?,
        exchange: suspend (ByteReadChannel, ByteWriteChannel) -> Unit,
    ) {
        val (server, port) = tlsServer { deflateEcho() }
        val selector = SelectorManager(Dispatchers.Default)
        try {
            val socket = aSocket(selector).tcp().connect("127.0.0.1", port).tls(ServerFixtures.clientTls())
            try {
                val w = socket.openWriteChannel(autoFlush = true)
                val r = socket.openReadChannel()
                w.writeStringUtf8(
                    "GET /ws HTTP/1.1\r\nHost: server.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" +
                        "Sec-WebSocket-Extensions: $offer\r\n\r\n",
                )
                assertEquals("HTTP/1.1 101 Switching Protocols", r.readLine(LineEnding.Lenient))
                var answer: String? = null
                while (true) {
                    val line = r.readLine(LineEnding.Lenient) ?: break
                    if (line.isEmpty()) break
                    if (line.startsWith("Sec-WebSocket-Extensions:", ignoreCase = true)) answer = line.substringAfter(':').trim()
                }
                assertEquals(expected, answer)
                withTimeout(20.seconds) { exchange(r, w) }
            } finally {
                socket.close()
            }
        } finally {
            selector.close()
            server.stop(100, 500)
        }
    }

    private suspend fun h3(
        offer: String,
        expected: String?,
        exchange: suspend (ByteReadChannel, ByteWriteChannel) -> Unit,
    ) {
        val (server, port) = tlsServer { deflateEcho() }
        val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
        try {
            val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
            try {
                val request =
                    http3Request("CONNECT", "server.test", "/ws") {
                        headers = Http3Headers.of("sec-websocket-version" to "13", "sec-websocket-extensions" to offer)
                    }
                val stream = c.connect(request, "websocket")
                assertEquals(
                    expected,
                    stream.headers.fields
                        .firstOrNull { it.first == "sec-websocket-extensions" }
                        ?.second,
                )
                withTimeout(20.seconds) { exchange(stream.input, stream.output) }
            } finally {
                c.close()
            }
        } finally {
            ep.close()
            server.stop(100, 500)
        }
    }

    @Test fun bombIsSmall() = assertTrue(bomb().size < 65536)
}
