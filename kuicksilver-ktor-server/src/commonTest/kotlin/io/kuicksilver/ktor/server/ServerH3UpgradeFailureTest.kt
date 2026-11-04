// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.install
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import io.ktor.websocket.Frame
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.http3Request
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Every HTTP/3 request stream ends, whatever happens to its call: a call that fails after Ktor committed its response
 * (an upgrade's own failure, before its answer went out) cannot get Ktor's 500 any more, so the engine resets the stream
 * with H3_INTERNAL_ERROR (RFC 9114 section 8.1) instead of leaving the client waiting for an answer that never comes.
 */
class ServerH3UpgradeFailureTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun negative_upgradeThatFailsAfterTheCommitResetsTheStream() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    install(WebSockets)
                    routing { webSocket("/ws") { send(Frame.Text("never")) } }
                }
            server.engine.beforeH3UpgradeForTest = { throw IllegalStateException("the upgrade failed") }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                try {
                    val request =
                        http3Request("CONNECT", "server.test", "/ws") { headers = Http3Headers.of("sec-websocket-version" to "13") }
                    val failure = runCatching { withTimeout(10.seconds) { c.connect(request, "websocket") } }.exceptionOrNull()
                    assertTrue(failure !is TimeoutCancellationException, "the request stream ends, not a 10 s wait")
                    assertTrue(failure is Http3Exception, "the client sees the stream reset: $failure")
                } finally {
                    c.close()
                }
            } finally {
                ep.close()
                server.stop(100, 500)
            }
        }
}
