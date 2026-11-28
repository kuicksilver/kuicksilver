// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.discard
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.Frame
import io.kuicksilver.ktor.network.connectTcp
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The Autobahn|Testsuite's section 9 against the server as `kuicksilver-soak`'s Autobahn server runs it (a plain connector,
 * Ktor's WebSockets with PerMessageDeflate, an echo): one connection per message, a Text or Binary message of 64 KiB to
 * 16 MiB sent as one frame, echoed whole, then the client's Close, the server's, and the server's end of the connection.
 * The suite's run of int39 stopped at 9.2.1: after the 16 MiB Text echo of 9.1.6 the next connection's handshake was never
 * answered. Each connection here must be served, its echo whole, within a bound.
 */
class ServerWebSocketLargeEchoTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val mask = byteArrayOf(0x11, 0x22, 0x33, 0x44)

    private fun header(
        opcode: Int,
        n: Int,
    ): ByteArray =
        when {
            n < 126 -> {
                byteArrayOf((0x80 or opcode).toByte(), (0x80 or n).toByte())
            }

            n < 65_536 -> {
                byteArrayOf((0x80 or opcode).toByte(), (0x80 or 126).toByte(), (n shr 8).toByte(), n.toByte())
            }

            else -> {
                byteArrayOf((0x80 or opcode).toByte(), (0x80 or 127).toByte()) +
                    ByteArray(8) { (n.toLong() shr (56 - 8 * it)).toByte() }
            }
        }

    /** One server frame: its opcode and payload length (the payload is read and dropped). */
    private suspend fun readFrame(input: ByteReadChannel): Pair<Int, Long> {
        val b0 = input.readByte().toInt() and 0xff
        val b1 = input.readByte().toInt() and 0xff
        val len =
            when (val l = b1 and 0x7f) {
                126 -> input.readByteArray(2).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xff) }
                127 -> input.readByteArray(8).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xff) }
                else -> l.toLong()
            }
        input.discard(len)
        return (b0 and 0x0f) to len
    }

    private suspend fun echoOnce(
        selector: SelectorManager,
        port: Int,
        opcode: Int,
        size: Int,
    ) {
        val socket = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
        try {
            val input = socket.openReadChannel()
            val output = socket.openWriteChannel(autoFlush = false)
            output.writeStringUtf8(
                "GET /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            )
            output.flush()
            val status = withTimeout(10.seconds) { input.readLine(LineEnding.Lenient) }
            assertTrue(status!!.startsWith("HTTP/1.1 101"), "opcode $opcode, $size bytes: $status")
            while (input.readLine(LineEnding.Lenient)!!.isNotEmpty()) continue
            // the message, masked, in chunks (a 'x' payload: valid UTF-8 for Text)
            output.writeFully(header(opcode, size) + mask)
            val chunk = ByteArray(64 * 1024) { ('x'.code xor mask[it % 4].toInt()).toByte() }
            var left = size
            while (left > 0) {
                val n = minOf(left, chunk.size)
                output.writeFully(chunk, 0, n)
                left -= n
            }
            output.flush()
            val (op, len) = withTimeout(30.seconds) { readFrame(input) }
            assertEquals(opcode to size.toLong(), op to len, "the echo")
            output.writeFully(header(8, 2) + mask + byteArrayOf((0x03 xor 0x11).toByte(), (0xE8 xor 0x22).toByte()))
            output.flush()
            assertEquals(8, withTimeout(10.seconds) { readFrame(input) }.first, "the server's Close")
            withTimeout(10.seconds) { input.discard() } // the server's end of the connection
        } finally {
            socket.close()
        }
    }

    @Test fun messagesOf64KiBTo16MiBAreEchoedOneConnectionEach() =
        serverTest {
            val server =
                embeddedServer(Kuicksilver, configure = {
                    plainConnector {
                        host = "127.0.0.1"
                        port = 0
                    }
                    http2 { enabled = false }
                    http3 { enabled = false }
                }) {
                    install(WebSockets) { extensions { install(PerMessageDeflate) } }
                    routing {
                        webSocket("/echo") {
                            for (frame in incoming) {
                                when (frame) {
                                    is Frame.Text -> {
                                        send(Frame.Text(frame.fin, frame.data))
                                    }

                                    is Frame.Binary -> {
                                        send(Frame.Binary(frame.fin, frame.data))
                                    }

                                    else -> {}
                                }
                            }
                        }
                    }
                }
            server.startSuspend(false)
            val selector = SelectorManager(Dispatchers.IO)
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                withContext(Dispatchers.IO) {
                    // 9.1.1 to 9.1.6 (Text), then 9.2.1 to 9.2.6 (Binary): 64 KiB, 256 KiB, 1, 4, 8 and 16 MiB
                    for (opcode in listOf(1, 2)) {
                        for (size in listOf(65_536, 262_144, 1 shl 20, 4 shl 20, 8 shl 20, 16 shl 20)) {
                            echoOnce(selector, port, opcode, size)
                        }
                    }
                }
            } finally {
                selector.close()
                server.stop(100, 500)
            }
        }
}
