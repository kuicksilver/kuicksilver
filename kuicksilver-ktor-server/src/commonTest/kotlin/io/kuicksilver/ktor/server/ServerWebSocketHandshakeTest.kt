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
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.Frame
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Exception
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
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The server engine's side of the WebSocket opening handshake (RFC 6455 section 4.2) and of the frames after it: a
 * handshake without one valid key or without version 13 is refused with an error status instead of the application's
 * upgrade; the server never masks its frames (section 5.1); a frame over the engine's limit (section 10.4) or text that
 * is not UTF-8 (section 8.1) fails the connection with 1009 or 1007.
 */
class ServerWebSocketHandshakeTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun Application.webSocketEcho(masking: Boolean = false) {
        install(WebSockets) { this.masking = masking }
        routing { webSocket("/ws") { for (frame in incoming) if (frame is Frame.Text) send(frame) } }
    }

    private val key = "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    private val version = "Sec-WebSocket-Version: 13\r\n"

    /** The response to an upgrade request with [fields] (whole lines) besides Host, Upgrade and Connection. */
    private suspend fun handshake(fields: String): String {
        val (server, port) = tlsServer { webSocketEcho() }
        try {
            return withTimeout(10.seconds) {
                rawHttp(port, "GET /ws HTTP/1.1\r\nHost: server.test\r\nUpgrade: websocket\r\nConnection: Upgrade, close\r\n$fields\r\n")
            }
        } finally {
            server.stop(100, 500)
        }
    }

    private fun refused(
        status: String,
        fields: String,
    ) = serverTest {
        val response = handshake(fields)
        assertTrue(response.startsWith("HTTP/1.1 $status"), response)
        assertTrue(response.contains("\r\nSec-WebSocket-Version: 13\r\n"), response)
    }

    /** RFC 6455 section 4.2.1 item 5: a key is required; the request is answered with 400 Bad Request. */
    @Test fun negative_missingKeyGets400() = refused("400", version)

    @Test fun negative_keyNotSixteenBytesGets400() = refused("400", "Sec-WebSocket-Key: abc\r\n$version")

    /** RFC 6455 section 11.3.1: the key MUST NOT appear more than once in a request. */
    @Test fun negative_twoKeysGet400() = refused("400", "$key${key}$version")

    @Test fun negative_missingVersionGets400() = refused("400", key)

    @Test fun negative_twoVersionFieldsGet400() = refused("400", "$key$version$version")

    /**
     * RFC 6455 section 4.2.2, /version/: a version the server does not understand gets "an appropriate HTTP error code
     * (such as 426 Upgrade Required) and a |Sec-WebSocket-Version| header field"; RFC 9110 section 15.5.22 adds the
     * `Upgrade` field to a 426.
     */
    @Test fun negative_otherVersionGets426() =
        serverTest {
            val response = handshake("${key}Sec-WebSocket-Version: 8\r\n")
            assertTrue(response.startsWith("HTTP/1.1 426"), response)
            assertTrue(response.contains("\r\nSec-WebSocket-Version: 13\r\n"), response)
            assertTrue(response.contains("\r\nUpgrade: websocket\r\n"), response)
        }

    @Test fun validHandshakeIsUpgraded() =
        serverTest {
            val (server, port) = tlsServer { webSocketEcho() }
            try {
                h1(port) { _, r -> assertEquals("HTTP/1.1 101 Switching Protocols", r.readLine(LineEnding.Lenient)) }
            } finally {
                server.stop(100, 500)
            }
        }

    /** RFC 8441 section 5 (RFC 9220): `sec-websocket-version` is used as in RFC 6455; the engine no longer makes it up. */
    @Test fun negative_missingVersionGets400H3() = h3Refused(Http3Headers.of())

    @Test fun negative_otherVersionGets400H3() = h3Refused(Http3Headers.of("sec-websocket-version" to "8"))

    private fun h3Refused(headers: Http3Headers) =
        h3ServerTest {
            val (server, port) = tlsServer { webSocketEcho() }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                try {
                    val request = http3Request("CONNECT", "server.test", "/ws") { this.headers = headers }
                    val e = assertFailsWith<Http3Exception.ConnectRejected> { withTimeout(10.seconds) { c.connect(request, "websocket") } }
                    assertEquals(400, e.status)
                } finally {
                    c.close()
                }
            } finally {
                ep.close()
                server.stop(100, 500)
            }
        }

    /** RFC 6455 section 5.1: "A server MUST NOT mask any frames that it sends to the client", whatever Ktor's `masking`. */
    @Test fun negative_serverNeverMasks() =
        serverTest {
            val (server, port) = tlsServer { webSocketEcho(masking = true) }
            try {
                h1(port) { w, r ->
                    upgraded(r)
                    w.writeFully(maskedText("hi"))
                    val b0 = r.readByte().toInt() and 0xff
                    val b1 = r.readByte().toInt() and 0xff
                    assertEquals(0x81, b0)
                    assertEquals(0x02, b1, "no mask bit")
                    assertEquals("hi", r.readByteArray(2).decodeToString())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** RFC 6455 section 10.4: a 14-byte header claiming 2 GiB is refused with 1009 from its header. */
    @Test fun negative_frameOverTheLimitClosesWith1009() =
        frameFails(
            1009,
            byteArrayOf(0x82.toByte(), 0xff.toByte(), 0, 0, 0, 0, 0x7f, 0xff.toByte(), 0xff.toByte(), 0xf0.toByte(), 1, 2, 3, 4),
        )

    /** The limit is the engine's `webSocketMaxMessageSize`. */
    @Test fun negative_messageOverTheConfiguredLimitClosesWith1009() =
        frameFails(1009, maskedText("eleven char"), configure = { webSocketMaxMessageSize = 10 })

    /** RFC 6455 section 8.1: text that is not UTF-8 fails the connection with 1007. */
    @Test fun negative_invalidUtf8ClosesWith1007() = frameFails(1007, masked(0x81, byteArrayOf(0xC0.toByte(), 0xAF.toByte())))

    private fun frameFails(
        code: Int,
        frame: ByteArray,
        configure: KuicksilverApplicationEngine.Configuration.() -> Unit = {},
    ) = serverTest {
        val (server, port) = tlsServer(configure) { webSocketEcho() }
        try {
            h1(port) { w, r ->
                upgraded(r)
                w.writeFully(frame)
                assertEquals(code, withTimeout(10.seconds) { closeCode(r) })
            }
        } finally {
            server.stop(100, 500)
        }
    }

    private fun maskedText(text: String) = masked(0x81, text.encodeToByteArray())

    private fun masked(
        b0: Int,
        payload: ByteArray,
    ): ByteArray {
        val mask = byteArrayOf(0x37, 0xfa.toByte(), 0x21, 0x3d)
        return byteArrayOf(b0.toByte(), (0x80 or payload.size).toByte()) + mask +
            ByteArray(payload.size) { (payload[it].toInt() xor mask[it % 4].toInt()).toByte() }
    }

    /** A TLS connection to the server that has sent a valid upgrade request; [block] reads the response. */
    private suspend fun h1(
        port: Int,
        block: suspend (io.ktor.utils.io.ByteWriteChannel, ByteReadChannel) -> Unit,
    ) {
        val selector = SelectorManager(Dispatchers.IO)
        try {
            val socket = connectTcp(selector, InetSocketAddress("127.0.0.1", port)).tls(ServerFixtures.clientTls())
            try {
                val w = socket.openWriteChannel(autoFlush = true)
                val r = socket.openReadChannel()
                w.writeStringUtf8("GET /ws HTTP/1.1\r\nHost: server.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n$key$version\r\n")
                withTimeout(10.seconds) { block(w, r) }
            } finally {
                socket.close()
            }
        } finally {
            selector.close()
        }
    }

    private suspend fun upgraded(r: ByteReadChannel) {
        assertEquals("HTTP/1.1 101 Switching Protocols", r.readLine(LineEnding.Lenient))
        while (r.readLine(LineEnding.Lenient)?.isNotEmpty() == true) continue
    }

    private suspend fun closeCode(input: ByteReadChannel): Int {
        val b0 = input.readByte().toInt() and 0xff
        val length = input.readByte().toInt() and 0x7f // a Close frame's payload is at most 125 bytes
        val payload = input.readByteArray(length)
        if (b0 and 0x0f != 0x8 || payload.size < 2) return -1
        return ((payload[0].toInt() and 0xff) shl 8) or (payload[1].toInt() and 0xff)
    }
}
