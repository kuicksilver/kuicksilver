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
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import io.ktor.server.websocket.WebSockets as ServerWebSockets
import io.ktor.server.websocket.webSocket as serverWebSocket

/**
 * Ktor's own permessage-deflate (`WebSocketDeflateExtension`, JVM only) on both ends of the Kuicksilver engines: the
 * client engine lets the plugin negotiate it, and both engines let the compressed frames' RSV1 through. Then Kuicksilver's
 * [PerMessageDeflate] against Ktor's, each way round: two implementations of RFC 7692 that must understand each other.
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
}
