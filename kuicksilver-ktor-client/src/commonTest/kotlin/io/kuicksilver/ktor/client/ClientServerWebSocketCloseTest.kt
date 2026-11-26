// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.client.request.get
import io.ktor.server.application.install
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.websocket.CloseReason
import io.ktor.websocket.close
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds
import io.ktor.server.websocket.WebSockets as ServerWebSockets
import io.ktor.server.websocket.webSocket as serverWebSocket

/**
 * The client engine against the server engine, over HTTP/1.1 (plain and TLS), HTTP/2 and HTTP/3: whichever side sends the
 * first Close, the server closes its side of the transport first and the client follows it (RFC 6455 sections 5.5.1 and
 * 7.1.1), long before the client's T2 (60 s here) could. Before, the server closed only after the client did (its HTTP/1.1
 * pipeline read the upgraded connection to the client's end), and the client closed its side right after its Close.
 */
class ClientServerWebSocketCloseTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private enum class Transport { H1Plain, H1Tls, H2, H3 }

    private fun closes(
        transport: Transport,
        clientFirst: Boolean,
    ) = clientTest {
        if (transport == Transport.H3 && !quicServerSupported()) return@clientTest
        val (server, port) =
            testServer(plain = transport == Transport.H1Plain, configure = { if (transport == Transport.H2) http2 { enabled = true } }) {
                install(ServerWebSockets)
                routing {
                    get("/") { call.respondText("ok") }
                    serverWebSocket("/ws") { for (f in incoming) continue }
                    serverWebSocket("/bye") { close(CloseReason(4001, "server bye")) }
                }
            }
        val hook = MutableStateFlow(emptyList<String>())
        try {
            val discovery = if (transport == Transport.H3) Http3Discovery.H3Only else null
            testClient(discovery, block = { install(WebSockets) }).use { c ->
                val e = c.engine as KuicksilverEngine
                val record: (String) -> Unit = { ev -> hook.update { it + ev } }
                e.h1.webSocketCloseWaitMillis = 60_000
                e.h3.webSocketCloseWaitMillis = 60_000
                when (transport) {
                    Transport.H2 -> e.h1.h2WebSocketClosingForTest = record
                    Transport.H3 -> e.h3.webSocketClosingForTest = record
                    else -> e.h1.webSocketClosingForTest = record
                }
                val scheme = if (transport == Transport.H1Plain) "ws" else "wss"
                if (transport == Transport.H2) c.get("https://127.0.0.1:$port/") // the HTTP/2 connection and its SETTINGS
                withTimeout(20.seconds) {
                    if (clientFirst) {
                        val s = c.webSocketSession("$scheme://127.0.0.1:$port/ws")
                        s.close(CloseReason(4000, "client bye"))
                    } else {
                        c.webSocket("$scheme://127.0.0.1:$port/bye") {
                            for (f in incoming) continue
                            assertEquals(CloseReason(4001, "server bye"), closeReason.await())
                        }
                    }
                    // the server's close came first: well within the client's T2 of 60 s
                    hook.first { it.size >= 2 }
                }
                val expected = if (transport == Transport.H2 || transport == Transport.H3) "server ended" else "server closed"
                assertEquals(listOf("waiting", expected), hook.value)
            }
        } finally {
            server.stop(0, 500)
        }
    }

    @Test fun h1PlainClientCloses() = closes(Transport.H1Plain, clientFirst = true)

    @Test fun h1PlainServerCloses() = closes(Transport.H1Plain, clientFirst = false)

    @Test fun h1TlsClientCloses() = closes(Transport.H1Tls, clientFirst = true)

    @Test fun h1TlsServerCloses() = closes(Transport.H1Tls, clientFirst = false)

    @Test fun h2ClientCloses() = closes(Transport.H2, clientFirst = true)

    @Test fun h2ServerCloses() = closes(Transport.H2, clientFirst = false)

    @Test fun h3ClientCloses() = closes(Transport.H3, clientFirst = true)

    @Test fun h3ServerCloses() = closes(Transport.H3, clientFirst = false)
}
