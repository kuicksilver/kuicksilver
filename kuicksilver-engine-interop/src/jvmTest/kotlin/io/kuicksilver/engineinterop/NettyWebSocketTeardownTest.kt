// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.engineinterop

import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import kotlinx.coroutines.Job
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * Our client against Ktor's Netty server (wss://, permessage-deflate), the client and the server closed right after the
 * session's `close()`, in either order and with the closing handshake awaited or not: the client's engine ends at once
 * each time. A client closed while a session waited for the server's Close or FIN used to wait out its close wait (5 s;
 * the leak sentinel's 4990 ms in `ClientToNettyWebSocketTest`); its close now ends every wait for the server
 * (WebSocketLifetime.hurry).
 */
internal class NettyWebSocketTeardownTest {
    private fun teardown(
        serverFirst: Boolean,
        awaitClose: Boolean,
    ) = interopTest(120.seconds) {
        val times = ArrayList<Long>()
        repeat(4) {
            val s = startServer(ServerEngine.Netty, tls = true, deflate = true)
            val c = ktorClient(ClientEngine.Kuicksilver, http2 = false, deflate = true)
            try {
                val ws = c.webSocketSession(s.wsUrl("/ws/echo"))
                ws.send(Frame.Text("x"))
                withTimeout(10.seconds) { ws.incoming.receive() }
                ws.close()
                if (awaitClose) withTimeout(10.seconds) { ws.closeReason.await() }
                val t = TimeSource.Monotonic.markNow()
                if (serverFirst) {
                    s.close()
                    c.close()
                } else {
                    c.close()
                    s.close()
                }
                withTimeout(30.seconds) { c.engine.coroutineContext[Job]!!.join() }
                times += t.elapsedNow().inWholeMilliseconds
            } finally {
                c.close()
                s.close()
            }
        }
        assertTrue(times.all { it < 3_000 }, "the client's engine ended after $times ms")
    }

    @Test fun clientThenServer() = teardown(serverFirst = false, awaitClose = false)

    @Test fun serverThenClient() = teardown(serverFirst = true, awaitClose = false)

    @Test fun closeAwaitedThenClientThenServer() = teardown(serverFirst = false, awaitClose = true)
}
