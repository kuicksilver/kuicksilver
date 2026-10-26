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
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.Frame
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.http3Request
import io.kuicksilver.ktor.network.tls
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * The server engine checks a client's WebSocket frames against the extensions its handshake negotiated (RFC 6455 section
 * 5.2): an RSV bit no extension defines fails the connection with a Close frame with code 1002, over HTTP/1.1 and over
 * HTTP/3 (RFC 9220).
 */
class ServerWebSocketGuardTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A masked text frame with RSV1 set and an empty payload, as a client would send it compressed. */
    private val rsv1Frame = byteArrayOf(0xC1.toByte(), 0x80.toByte(), 1, 2, 3, 4)

    /** An unmasked text frame "a", which no client may send (RFC 6455 section 5.1). */
    private val unmaskedFrame = byteArrayOf(0x81.toByte(), 0x01, 0x61)

    private fun Application.webSocketEcho() {
        install(WebSockets)
        routing { webSocket("/ws") { for (frame in incoming) if (frame is Frame.Text) send(frame) } }
    }

    @Test fun negative_rsv1WithoutNegotiationClosesWith1002() = serverTest { h1Violation(rsv1Frame) }

    @Test fun negative_unmaskedFrameFromClientClosesWith1002() = serverTest { h1Violation(unmaskedFrame) }

    private suspend fun h1Violation(frame: ByteArray): Unit =
        run {
            val (server, port) = tlsServer { webSocketEcho() }
            val selector = SelectorManager(Dispatchers.Default)
            try {
                val socket = aSocket(selector).tcp().connect("127.0.0.1", port).tls(ServerFixtures.clientTls())
                try {
                    val w = socket.openWriteChannel(autoFlush = true)
                    val r = socket.openReadChannel()
                    w.writeStringUtf8(
                        "GET /ws HTTP/1.1\r\nHost: server.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
                    )
                    val status = r.readLine(LineEnding.Lenient)
                    assertEquals("HTTP/1.1 101 Switching Protocols", status)
                    while (r.readLine(LineEnding.Lenient)?.isNotEmpty() == true) Unit
                    w.writeFully(frame)
                    assertEquals(1002, withTimeout(10.seconds) { closeCode(r) })
                } finally {
                    socket.close()
                }
            } finally {
                selector.close()
                server.stop(100, 500)
            }
        }

    @Test fun negative_rsv1WithoutNegotiationClosesWith1002H3() = h3ServerTest { h3Violation(rsv1Frame) }

    @Test fun negative_unmaskedFrameFromClientClosesWith1002H3() = h3ServerTest { h3Violation(unmaskedFrame) }

    private suspend fun h3Violation(frame: ByteArray): Unit =
        run {
            val (server, port) = tlsServer { webSocketEcho() }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                try {
                    val request =
                        http3Request("CONNECT", "server.test", "/ws") {
                            headers = Http3Headers.of("sec-websocket-version" to "13")
                        }
                    val stream = c.connect(request, "websocket")
                    stream.output.writeFully(frame)
                    stream.output.flush()
                    assertEquals(1002, withTimeout(10.seconds) { closeCode(stream.input) })
                } finally {
                    c.close()
                }
            } finally {
                ep.close()
                server.stop(100, 500)
            }
        }

    /** The close code of the server's first frame (unmasked), or -1 when it is not a Close frame with a code. */
    private suspend fun closeCode(input: ByteReadChannel): Int {
        val b0 = input.readByte().toInt() and 0xff
        val length = input.readByte().toInt() and 0x7f // a Close frame's payload is at most 125 bytes
        val payload = input.readByteArray(length)
        if (b0 and 0x0f != 0x8 || payload.size < 2) return -1
        return ((payload[0].toInt() and 0xff) shl 8) or (payload[1].toInt() and 0xff)
    }
}
