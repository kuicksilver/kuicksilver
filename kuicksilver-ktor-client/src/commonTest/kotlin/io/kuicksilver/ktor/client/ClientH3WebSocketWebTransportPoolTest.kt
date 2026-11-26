// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.DefaultClientWebSocketSession
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.server.application.install
import io.ktor.server.routing.routing
import io.ktor.server.websocket.webSocket
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import io.ktor.websocket.readText
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.ktor.server.webTransport
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlinx.io.readString
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.time.Duration.Companion.seconds

/**
 * A WebSocket and WebTransport sessions on one pooled HTTP/3 connection: the WebSocket keeps the connection in use until
 * the session ended (not its call), WebTransport sessions until they closed, and the connection closes, when drained or
 * replaced in the pool, only once both kinds of user are gone. "Still open" is shown by a round trip on it, never by a
 * wait.
 */
class ClientH3WebSocketWebTransportPoolTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private suspend fun echo(session: WebTransportSession) {
        while (true) {
            val st = runCatching { session.acceptBidi() }.getOrNull() ?: return
            st.input.copyTo(st.output)
            st.output.flushAndClose()
        }
    }

    private suspend fun roundTrip(
        session: WebTransportSession,
        text: String,
    ): String {
        val st = session.openBidi()
        st.output.writeFully(text.encodeToByteArray())
        st.output.flushAndClose()
        return withTimeout(10.seconds) { st.input.readBuffer().readString() }
    }

    private suspend fun DefaultClientWebSocketSession.roundTrip(text: String): String {
        send(Frame.Text(text))
        return (withTimeout(10.seconds) { incoming.receive() } as Frame.Text).readText()
    }

    /** Waits for the pool's connections to be used as [expected]: a fall comes with a release, so it waits for releases. */
    private suspend fun KuicksilverEngine.awaitActive(expected: List<Pair<Boolean, Int>>) {
        try {
            withTimeout(15.seconds) { h3.releasesForTest.first { h3.activeForTest() == expected } }
        } catch (e: Throwable) {
            throw AssertionError("active ${h3.activeForTest()} != $expected", e)
        }
    }

    private suspend fun withServer(block: suspend (HttpClient, KuicksilverEngine, Int) -> Unit) {
        val (server, port) =
            testServer(configure = { http3 { webTransport { enabled = true } } }) {
                install(io.ktor.server.websocket.WebSockets)
                routing {
                    webTransport("/wt") { echo(it) }
                    webSocket("/ws") {
                        for (f in incoming) if (f is Frame.Text) send(Frame.Text(f.readText()))
                    }
                }
            }
        try {
            testClient(Http3Discovery.H3Only, block = { install(WebSockets) }).use { client ->
                block(client, client.engine as KuicksilverEngine, port)
            }
        } finally {
            server.stopSuspend(100, 1000)
        }
    }

    @Test fun webSocketAndWebTransportShareThePooledConnection() =
        h3Test {
            withServer { client, engine, port ->
                val wt = client.webTransport("https://127.0.0.1:$port/wt")
                assertEquals("a", roundTrip(wt, "a"))
                engine.awaitActive(listOf(true to 1))
                // the WebSocket over HTTP/3 joins the WebTransport-capable pooled connection
                val ws = client.webSocketSession("wss://127.0.0.1:$port/ws")
                assertEquals("x", ws.roundTrip("x"))
                assertEquals(1, engine.h3.connectionsForProbe(), "one connection")
                engine.awaitActive(listOf(true to 2))
                // the WebTransport session ends; the WebSocket keeps the connection
                wt.close(0, "")
                withTimeout(10.seconds) { engine.h3.webTransportSessions.first { it == 0 } }
                engine.awaitActive(listOf(true to 1))
                assertEquals("y", ws.roundTrip("y"))
                // a second session joins while the WebSocket is open
                val wt2 = client.webTransport("https://127.0.0.1:$port/wt")
                assertEquals("b", roundTrip(wt2, "b"))
                engine.awaitActive(listOf(true to 2))
                ws.close(CloseReason(CloseReason.Codes.NORMAL, "bye"))
                engine.awaitActive(listOf(true to 1))
                assertEquals("c", roundTrip(wt2, "c"))
                wt2.close(0, "")
                engine.awaitActive(listOf(true to 0))
                assertEquals(1, engine.h3.connectionsForProbe(), "still the one connection")
            }
        }

    /** closeHttp3Connections() with a session and a WebSocket on the connection: it closes once both ended, not before. */
    @Test fun negative_drainedConnectionStaysOpenUntilTheWebSocketEnds() =
        h3Test {
            withServer { client, engine, port ->
                val wt = client.webTransport("https://127.0.0.1:$port/wt")
                val ws = client.webSocketSession("wss://127.0.0.1:$port/ws")
                assertEquals("x", ws.roundTrip("x"))
                val conn = engine.h3.connectionsForTest().single()
                engine.awaitActive(listOf(true to 2))
                client.closeHttp3Connections()
                // both users still go on over the drained connection
                assertEquals("a", roundTrip(wt, "a"))
                assertEquals("y", ws.roundTrip("y"))
                assertFalse(conn.closed.isCompleted, "both still use it")
                val releases = engine.h3.releasesForTest.value
                wt.close(0, "")
                withTimeout(10.seconds) { engine.h3.webTransportSessions.first { it == 0 } }
                // the session released the connection: the WebSocket alone keeps it
                withTimeout(15.seconds) { engine.h3.releasesForTest.first { it > releases } }
                assertEquals("z", ws.roundTrip("z"))
                assertFalse(conn.closed.isCompleted, "the WebSocket still uses it")
                ws.close(CloseReason(CloseReason.Codes.NORMAL, "bye"))
                withTimeout(20.seconds) { conn.closed.await() }
            }
        }

    /** A WebSocket on a request-only pooled connection that a WebTransport session replaces: the old one waits for it. */
    @Test fun negative_replacedRequestOnlyConnectionStaysOpenUntilItsWebSocketEnds() =
        h3Test {
            withServer { client, engine, port ->
                val ws = client.webSocketSession("wss://127.0.0.1:$port/ws")
                assertEquals("x", ws.roundTrip("x"))
                val old = engine.h3.connectionsForTest().single()
                engine.awaitActive(listOf(false to 1))
                val wt = client.webTransport("https://127.0.0.1:$port/wt")
                assertEquals("a", roundTrip(wt, "a"))
                // the pool holds the WebTransport-capable connection now; the replaced one is retired, still in use
                engine.awaitActive(listOf(true to 1))
                assertEquals("y", ws.roundTrip("y"))
                assertFalse(old.closed.isCompleted, "the WebSocket still uses the replaced connection")
                ws.close(CloseReason(CloseReason.Codes.NORMAL, "bye"))
                withTimeout(20.seconds) { old.closed.await() }
                assertEquals("b", roundTrip(wt, "b"))
                wt.close(0, "")
                engine.awaitActive(listOf(true to 0))
            }
        }
}
