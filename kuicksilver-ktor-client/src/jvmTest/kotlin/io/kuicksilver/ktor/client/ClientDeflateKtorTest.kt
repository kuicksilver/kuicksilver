// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.server.application.install
import io.ktor.server.routing.routing
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketDeflateExtension
import io.ktor.websocket.readText
import io.kuicksilver.native.KslLoader
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import io.ktor.server.websocket.WebSockets as ServerWebSockets
import io.ktor.server.websocket.webSocket as serverWebSocket

/**
 * Ktor's own permessage-deflate (`WebSocketDeflateExtension`, JVM only) on both ends of the Kuicksilver engines: the
 * client engine lets the plugin negotiate it, and both engines let the compressed frames' RSV1 through.
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
