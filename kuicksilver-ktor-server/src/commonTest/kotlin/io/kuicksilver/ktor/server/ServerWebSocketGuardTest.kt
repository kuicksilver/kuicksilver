// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import io.ktor.server.websocket.webSocketRaw
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.http3Request
import io.kuicksilver.ktor.network.connectTcp
import io.kuicksilver.ktor.network.tls
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
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

    /**
     * RFC 9110 section 7.8: a server MUST ignore an Upgrade header field that is received in an HTTP/1.0 request (and
     * MUST NOT send a 1xx response to an HTTP/1.0 client, section 15.2). The request reaches the application without
     * it, so the WebSocket route does not take it. Before, Ktor's upgrade check did not look at the version and the
     * HTTP/1.0 client got `101 Switching Protocols`.
     */
    @Test fun negative_http10UpgradeIsIgnored() =
        serverTest {
            val (server, port) = tlsServer { webSocketEcho() }
            try {
                val resp =
                    withTimeout(10.seconds) {
                        rawHttp(
                            port,
                            "GET /ws HTTP/1.0\r\nHost: server.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
                        )
                    }
                assertFalse(resp.contains(" 101 "), resp)
                assertTrue(resp.startsWith("HTTP/1.1 4"), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun negative_unmaskedFrameFromClientClosesWith1002() = serverTest { h1Violation(unmaskedFrame) }

    private suspend fun h1Violation(frame: ByteArray): Unit =
        run {
            val (server, port) = tlsServer { webSocketEcho() }
            val selector = SelectorManager(Dispatchers.IO)
            try {
                val socket = connectTcp(selector, InetSocketAddress("127.0.0.1", port)).tls(ServerFixtures.clientTls())
                try {
                    val w = socket.openWriteChannel(autoFlush = true)
                    val r = socket.openReadChannel()
                    w.writeStringUtf8(
                        "GET /ws HTTP/1.1\r\nHost: server.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
                    )
                    val status = r.readLine(LineEnding.Lenient)
                    assertEquals("HTTP/1.1 101 Switching Protocols", status)
                    while (r.readLine(LineEnding.Lenient)?.isNotEmpty() == true) continue
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

    /** A masked frame from the client: [b0], then [payload] masked with a fixed key. */
    private fun masked(
        b0: Int,
        payload: ByteArray,
    ): ByteArray {
        val key = byteArrayOf(0x11, 0x22, 0x33, 0x44)
        val body = ByteArray(payload.size) { (payload[it].toInt() xor key[it % 4].toInt()).toByte() }
        return byteArrayOf(b0.toByte(), (0x80 or payload.size).toByte()) + key + body
    }

    /** The next frame from the server (unmasked, at most 125 bytes): its first byte and payload. */
    private suspend fun serverFrame(input: ByteReadChannel): Pair<Int, ByteArray> {
        val b0 = input.readByte().toInt() and 0xff
        val length = input.readByte().toInt() and 0x7f
        return b0 to input.readByteArray(length)
    }

    /** An upgraded HTTP/1.1 connection to /ws of a server with [module], for [block]. */
    private suspend fun h1WebSocket(
        module: Application.() -> Unit,
        block: suspend (io.ktor.utils.io.ByteWriteChannel, ByteReadChannel) -> Unit,
    ) {
        val (server, port) = tlsServer(module = module)
        val selector = SelectorManager(Dispatchers.IO)
        try {
            val socket = connectTcp(selector, InetSocketAddress("127.0.0.1", port)).tls(ServerFixtures.clientTls())
            try {
                val w = socket.openWriteChannel(autoFlush = true)
                val r = socket.openReadChannel()
                w.writeStringUtf8(
                    "GET /ws HTTP/1.1\r\nHost: server.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
                )
                assertEquals("HTTP/1.1 101 Switching Protocols", r.readLine(LineEnding.Lenient))
                while (r.readLine(LineEnding.Lenient)?.isNotEmpty() == true) continue
                block(w, r)
            } finally {
                socket.close()
            }
        } finally {
            selector.close()
            server.stop(100, 500)
        }
    }

    /**
     * RFC 6455 section 5.5.2: "Upon receipt of a Ping frame, an endpoint MUST send a Pong frame in response ... It SHOULD
     * respond with Pong frame as soon as is practical"; section 5.4: control frames "MAY be injected in the middle of a
     * fragmented message". The engine answers the Ping itself as soon as it reads it, with its data (section 5.5.3), while
     * the message is still incomplete, even under a raw session, which never answers a Ping. Before, the Pong was Ktor's
     * session's alone: none under a raw session, and under the default one it could follow the echo of the whole message
     * (Autobahn|Testsuite 5.6 to 5.8, 5.19 and 5.20).
     */
    @Test fun negative_pingBetweenFragmentsIsAnsweredBeforeTheMessageEnds() =
        serverTest {
            h1WebSocket({
                install(WebSockets)
                routing { webSocketRaw("/ws") { for (frame in incoming) continue } }
            }) { w, r ->
                w.writeFully(masked(0x01, "frag".encodeToByteArray()) + masked(0x89, "ping 1".encodeToByteArray()))
                val (b0, payload) = withTimeout(10.seconds) { serverFrame(r) }
                assertEquals(0x8A, b0)
                assertEquals("ping 1", payload.decodeToString())
            }
        }

    /** Under the default session, which answers Pings too, the client still gets one Pong per Ping, then the echo. */
    @Test fun negative_oneServerPongPerPing() =
        serverTest {
            h1WebSocket({ webSocketEcho() }) { w, r ->
                w.writeFully(masked(0x89, "p".encodeToByteArray()) + masked(0x81, "a".encodeToByteArray()))
                val got = ArrayList<Pair<Int, String>>()
                withTimeout(10.seconds) {
                    // the Pong and the echo, then the Close the client sends only now: a second Pong would come before it
                    repeat(2) { serverFrame(r).let { (b0, payload) -> got += b0 to payload.decodeToString() } }
                    w.writeFully(masked(0x88, byteArrayOf(0x03, 0xE8.toByte())))
                    serverFrame(r).let { (b0, _) -> got += b0 to "" }
                }
                assertEquals(listOf(0x8A to "p", 0x81 to "a", 0x88 to ""), got)
            }
        }

    /**
     * RFC 6455 section 5.5.2: a Pong is owed "unless it already received a Close frame", so also after this side's own
     * Close, until the peer's; section 5.5.1 forbids only data frames after a Close, and the transport is closed "after
     * both sending and receiving a Close message". The server closes first; the client sends a Ping before its own Close
     * and gets the Pong, then sends its Close, and only then does the server end the connection. Before, the server's FIN
     * followed its Close at once (Ktor's writer ends its channel right after its Close) and the Ping went unanswered.
     */
    @Test fun negative_pingAfterTheServersCloseIsAnsweredBeforeTheFin() =
        serverTest {
            h1WebSocket({
                install(WebSockets)
                routing {
                    webSocket("/ws") {
                        close(io.ktor.websocket.CloseReason(io.ktor.websocket.CloseReason.Codes.NORMAL, "bye"))
                        for (frame in incoming) continue
                    }
                }
            }) { w, r ->
                withTimeout(10.seconds) {
                    assertEquals(0x88, serverFrame(r).first, "the server's Close")
                    w.writeFully(masked(0x89, "still".encodeToByteArray()))
                    val (b0, payload) = serverFrame(r)
                    assertEquals(0x8A, b0, "the Pong after the server's Close")
                    assertEquals("still", payload.decodeToString())
                    w.writeFully(masked(0x88, byteArrayOf(0x03, 0xE8.toByte())))
                    assertTrue(r.readBuffer().exhausted(), "nothing more, then the end of the connection")
                }
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
