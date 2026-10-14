// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.install
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import io.ktor.server.websocket.webSocketRaw
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.RawWebSocket
import io.ktor.websocket.readReason
import io.ktor.websocket.readText
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.http3Request
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.seconds

/** WebSockets over HTTP/3 (RFC 9220) through Ktor's own `webSocket {}` route. */
class ServerWebSocketH3Test {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val wsRequest =
        http3Request("CONNECT", "server.test", "/ws") {
            headers = Http3Headers.of("sec-websocket-version" to "13")
        }

    private suspend fun <T> h3(
        port: Int,
        block: suspend (io.kuicksilver.http3.Http3Connection) -> T,
    ): T {
        val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
        try {
            val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
            try {
                return block(c)
            } finally {
                c.close()
            }
        } finally {
            ep.close()
        }
    }

    @Test fun echoOverExtendedConnect() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    install(WebSockets)
                    routing {
                        webSocket(
                            "/ws",
                        ) { for (frame in incoming) if (frame is Frame.Text) send(Frame.Text("echo:" + frame.readText())) }
                    }
                }
            try {
                h3(port) { c ->
                    val stream = c.connect(wsRequest, "websocket")
                    val ws = RawWebSocket(stream.input, stream.output, masking = true, coroutineContext = currentCoroutineContext())
                    ws.send(Frame.Text("ping"))
                    assertEquals("echo:ping", (ws.incoming.receive() as Frame.Text).readText())
                    ws.send(Frame.Close())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * Found on Linux Native by the client contract (testParallelWebsocketSessions over h3): a client that resets the CONNECT
     * stream fails the session's reader with H3_REQUEST_CANCELLED; that failure escaped the per-connection coroutine as an
     * uncaught exception, which Kotlin/Native turns into a process abort (the JVM only prints it).
     */
    @Test fun peerResetOfAWebSocketStreamStaysInsideTheServer() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    install(WebSockets)
                    routing {
                        webSocket(
                            "/ws",
                        ) { for (frame in incoming) if (frame is Frame.Text) send(Frame.Text("echo:" + frame.readText())) }
                    }
                }
            try {
                repeat(2) { round ->
                    h3(port) { c ->
                        val stream = c.connect(wsRequest, "websocket")
                        val ws = RawWebSocket(stream.input, stream.output, masking = true, coroutineContext = currentCoroutineContext())
                        ws.send(Frame.Text("ping$round"))
                        assertEquals("echo:ping$round", (ws.incoming.receive() as Frame.Text).readText())
                        stream.reset(Http3ErrorCode.REQUEST_CANCELLED)
                        ws.cancel()
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Ktor's writer closes the output right after a server Close frame; the client's Close still arrives. */
    @Test fun serverInitiatedCloseReceivesClientReason() =
        h3ServerTest {
            val reply = CompletableDeferred<CloseReason?>()
            val (server, port) =
                tlsServer {
                    install(WebSockets)
                    routing {
                        webSocketRaw("/ws") {
                            outgoing.send(Frame.Close(CloseReason(CloseReason.Codes.GOING_AWAY, "server bye")))
                            reply.complete((incoming.receiveCatching().getOrNull() as? Frame.Close)?.readReason())
                        }
                    }
                }
            try {
                h3(port) { c ->
                    val stream = c.connect(wsRequest, "websocket")
                    val ws = RawWebSocket(stream.input, stream.output, masking = true, coroutineContext = currentCoroutineContext())
                    assertEquals("server bye", (ws.incoming.receive() as Frame.Close).readReason()?.message)
                    ws.outgoing.send(Frame.Close(CloseReason(CloseReason.Codes.NORMAL, "client bye")))
                    assertEquals(CloseReason(CloseReason.Codes.NORMAL, "client bye"), withTimeout(5.seconds) { reply.await() })
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun settingAdvertisedOnlyWhenEnabled() =
        h3ServerTest {
            for (enabled in listOf(true, false)) {
                val (server, port) = tlsServer(configure = { webSocketsOverHttp3 = enabled }) { }
                try {
                    h3(port) { c ->
                        assertEquals(
                            enabled,
                            c.peerSettings
                                .filterNotNull()
                                .first()
                                .enableConnectProtocol,
                        )
                    }
                } finally {
                    server.stop(100, 500)
                }
            }
        }

    @Test fun unknownProtocol501() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    install(WebSockets)
                    routing { webSocket("/ws") { } }
                }
            try {
                h3(
                    port,
                ) { c ->
                    assertEquals(
                        501,
                        assertFailsWith<Http3Exception.ConnectRejected> { c.connect(wsRequest, "webtransport-x") }.status,
                    )
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun nonWebSocketRouteAnswersItsStatus() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    install(WebSockets)
                    routing { }
                }
            try {
                h3(
                    port,
                ) { c -> assertEquals(404, assertFailsWith<Http3Exception.ConnectRejected> { c.connect(wsRequest, "websocket") }.status) }
            } finally {
                server.stop(100, 500)
            }
        }
}
