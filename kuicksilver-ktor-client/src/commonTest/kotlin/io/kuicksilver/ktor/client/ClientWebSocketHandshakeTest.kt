// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.plugins.websocket.WebSocketException
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.header
import io.ktor.http.HttpHeaders
import io.ktor.http.websocket.websocketServerAccept
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.kuicksilver.ktor.network.bindTcp
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeout
import kotlin.io.encoding.Base64
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The client's check of the server's opening handshake over HTTP/1.1 (RFC 6455 section 4.1): status 101 alone opens no
 * session; `Upgrade`, `Connection`, `Sec-WebSocket-Accept`, `Sec-WebSocket-Protocol` and `Sec-WebSocket-Extensions` must
 * say what the section requires, else the handshake fails with [WebSocketException] before a session exists. Also the
 * key: new for every connection (a followed redirect included), and the frame limit (section 10.4).
 */
class ClientWebSocketHandshakeTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A 101 with the fields [fields] (whole lines) after the status line, for the request whose key is [key]. */
    private fun head(fields: String) = "HTTP/1.1 101 Switching Protocols\r\n$fields\r\n"

    private fun accept(key: String?) = "Sec-WebSocket-Accept: ${websocketServerAccept(key!!)}\r\n"

    private val upgrade = "Upgrade: websocket\r\nConnection: Upgrade\r\n"

    /** The handshake fails with [WebSocketException] whose message has [what]; no session was opened. */
    private fun refused(
        what: String,
        offer: String? = null,
        answer: (key: String?) -> String,
    ) = clientTest {
        var opened = false
        server({ _, key -> answer(key) }) { port ->
            testClient(block = { install(WebSockets) }).use { c ->
                val e =
                    assertFailsWith<WebSocketException> {
                        c.webSocket("ws://127.0.0.1:$port/ws", request = { offer?.let { header(HttpHeaders.SecWebSocketProtocol, it) } }) {
                            opened = true
                        }
                    }
                assertTrue(what in e.message.orEmpty(), e.message)
            }
        }
        assertFalse(opened, "a session was opened")
    }

    @Test fun negative_wrongAcceptFailsTheHandshake() =
        refused("Sec-WebSocket-Accept does not answer") { head(upgrade + "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") }

    @Test fun negative_missingAcceptFailsTheHandshake() = refused("0 Sec-WebSocket-Accept fields") { head(upgrade) }

    @Test fun negative_twoAcceptsFailTheHandshake() =
        refused("2 Sec-WebSocket-Accept fields") { key ->
            head(upgrade + accept(key) + accept(key))
        }

    @Test fun negative_missingUpgradeFailsTheHandshake() =
        refused(
            "Upgrade is missing",
        ) { key -> head("Connection: Upgrade\r\n" + accept(key)) }

    @Test fun negative_otherUpgradeFailsTheHandshake() =
        refused("Upgrade is \"h2c\"") { key -> head("Upgrade: h2c\r\nConnection: Upgrade\r\n" + accept(key)) }

    @Test fun negative_missingConnectionFailsTheHandshake() =
        refused("Connection has no Upgrade token") { key -> head("Upgrade: websocket\r\n" + accept(key)) }

    @Test fun negative_connectionWithoutUpgradeTokenFailsTheHandshake() =
        refused("Connection has no Upgrade token") { key -> head("Upgrade: websocket\r\nConnection: keep-alive\r\n" + accept(key)) }

    @Test fun negative_unofferedSubprotocolFailsTheHandshake() =
        refused("\"superchat\", which the client did not offer", offer = "chat") { key ->
            head(upgrade + accept(key) + "Sec-WebSocket-Protocol: superchat\r\n")
        }

    @Test fun negative_subprotocolWhenNoneOfferedFailsTheHandshake() =
        refused("which the client did not offer") { key -> head(upgrade + accept(key) + "Sec-WebSocket-Protocol: chat\r\n") }

    @Test fun negative_twoSubprotocolsFailTheHandshake() =
        refused("2 Sec-WebSocket-Protocol fields", offer = "chat, superchat") { key ->
            head(upgrade + accept(key) + "Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Protocol: superchat\r\n")
        }

    @Test fun negative_twoExtensionsFieldsFailTheHandshake() =
        refused("2 Sec-WebSocket-Extensions fields") { key ->
            head(upgrade + accept(key) + "Sec-WebSocket-Extensions: x-a\r\nSec-WebSocket-Extensions: x-b\r\n")
        }

    /** The checks are ASCII case-insensitive, `Connection` a list, and the subprotocol one the client offered. */
    @Test fun validAnswerOpensTheSession() =
        clientTest {
            var text: String? = null
            server({ _, key ->
                head("upgrade: WebSocket\r\nconnection: keep-alive, UPGRADE\r\n" + accept(key) + "Sec-WebSocket-Protocol: superchat\r\n")
            }, frames = byteArrayOf(0x81.toByte(), 0x02, 0x68, 0x69)) { port ->
                testClient(block = { install(WebSockets) }).use { c ->
                    c.webSocket("ws://127.0.0.1:$port/ws", request = { header(HttpHeaders.SecWebSocketProtocol, "chat, superchat") }) {
                        text = (incoming.receive() as Frame.Text).readText()
                    }
                }
            }
            assertEquals("hi", text)
        }

    /**
     * RFC 6455 section 4.1: "The nonce MUST be selected randomly for each connection." A redirect Ktor follows sends the
     * request again on a new connection: with a new key. Before, the key belonged to Ktor's request body and was sent again.
     */
    @Test fun negative_eachConnectionGetsANewKey() =
        clientTest {
            val keys = ArrayList<String?>()
            server({ index, key ->
                keys += key
                if (index ==
                    0
                ) {
                    "HTTP/1.1 307 Temporary Redirect\r\nLocation: /other\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    head(upgrade + accept(key))
                }
            }) { port ->
                testClient(block = { install(WebSockets) }).use { c -> c.webSocket("ws://127.0.0.1:$port/ws") {} }
            }
            assertEquals(2, keys.size, "two connections: $keys")
            assertNotEquals(keys[0], keys[1])
            for (k in keys) assertEquals(16, Base64.decode(k!!).size)
        }

    /**
     * RFC 6455 section 10.4: a frame header claiming 2 GiB is refused from its header with 1009 (message too big); the
     * engine's limit is 16 MiB by default.
     */
    @Test fun negative_frameOverTheLimitClosesWith1009() =
        clientTest {
            var closeCode: Short? = null
            var sent: Int? = null
            val header = byteArrayOf(0x82.toByte(), 0x7f, 0, 0, 0, 0, 0x7f, 0xff.toByte(), 0xff.toByte(), 0xf0.toByte())
            server({ _, key -> head(upgrade + accept(key)) }, frames = header) { port ->
                testClient(block = { install(WebSockets) }).use { c ->
                    c.webSocket("ws://127.0.0.1:$port/ws") {
                        runCatching { incoming.receive() }
                        closeCode = closeReason.await()?.code
                    }
                }
                sent = withTimeout(10.seconds) { closeCodes.receive() }
            }
            assertEquals(1009.toShort(), closeCode)
            assertEquals(1009, sent, "the Close the client sent")
        }

    /**
     * RFC 6455 section 5.3, end to end: the engine gives Ktor's session `masking = false` and masks every frame itself,
     * each with a new key (Ktor's writer would draw them from `kotlin.random.Random`).
     */
    @Test fun negative_clientEngineMasksEveryFrameWithANewKey() =
        clientTest {
            var sessionMasking: Boolean? = null
            var seen: List<List<Byte>> = emptyList()
            val keys = Channel<List<Byte>>(Channel.UNLIMITED)
            server({ _, key -> head(upgrade + accept(key)) }, afterUpgrade = { input ->
                repeat(3) {
                    val b1 = input.readByteArray(2)[1].toInt() and 0xff
                    val mask = input.readByteArray(4)
                    val payload = input.readByteArray(b1 and 0x7f)
                    assertTrue(b1 and 0x80 != 0, "masked")
                    assertEquals(
                        "m$it",
                        payload
                            .mapIndexed {
                                i,
                                b,
                                ->
                                (b.toInt() xor mask[i % 4].toInt()).toByte()
                            }.toByteArray()
                            .decodeToString(),
                    )
                    keys.send(mask.toList())
                }
            }) { port ->
                testClient(block = { install(WebSockets) }).use { c ->
                    c.webSocket("ws://127.0.0.1:$port/ws") {
                        sessionMasking = masking
                        repeat(3) { send(Frame.Text("m$it")) }
                        seen = withTimeout(10.seconds) { List(3) { keys.receive() } }
                    }
                }
            }
            assertEquals(false, sessionMasking, "Ktor's session does not mask")
            assertEquals(3, seen.toSet().size, "a new key for every frame: $seen")
        }

    /**
     * A raw HTTP/1.1 server on 127.0.0.1: per connection (numbered from 0), reads the request head and writes what
     * [answer] returns for it; after a 101 it sends [frames], reads the client's first frame and puts its close code in
     * [closeCodes] (-1 for none, or one that is not a Close).
     */
    private suspend fun server(
        answer: (index: Int, key: String?) -> String,
        frames: ByteArray = ByteArray(0),
        afterUpgrade: suspend (ByteReadChannel) -> Unit = { closeCodes.send(closeCode(it)) },
        block: suspend (Int) -> Unit,
    ) {
        val selector = SelectorManager(Dispatchers.IO)
        val listener = bindTcp(selector, "127.0.0.1", 0)
        try {
            coroutineScope {
                val served =
                    async {
                        var index = 0
                        while (true) {
                            val s = listener.accept()
                            s.use {
                                val input = s.openReadChannel()
                                val output = s.openWriteChannel(autoFlush = true)
                                val text = answer(index++, input.readWebSocketKey())
                                output.writeStringUtf8(text)
                                if (text.startsWith("HTTP/1.1 101")) {
                                    output.writeFully(frames)
                                    afterUpgrade(input)
                                }
                            }
                        }
                    }
                try {
                    withTimeout(20.seconds) { block((listener.localAddress as InetSocketAddress).port) }
                } finally {
                    served.cancel()
                }
            }
        } finally {
            listener.close()
            selector.close()
        }
    }

    private val closeCodes = Channel<Int>(Channel.UNLIMITED)

    private suspend fun closeCode(input: ByteReadChannel): Int =
        runCatching {
            val b0 = input.readByte().toInt() and 0xff
            val b1 = input.readByte().toInt() and 0xff
            val mask = input.readByteArray(4)
            val payload = input.readByteArray(b1 and 0x7f).mapIndexed { i, b -> (b.toInt() xor mask[i % 4].toInt()) and 0xff }
            if (b0 and 0x0f != 0x8 || payload.size < 2) -1 else (payload[0] shl 8) or payload[1]
        }.getOrDefault(-1)
}
