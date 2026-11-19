// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.response.respondText
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.network.connectTcp
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * A connection accepted just before the server stops, whose first request is still on its way: closed as idle at once,
 * its client cannot tell whether the request was processed, and must not repeat a non-idempotent one (RFC 9112 section
 * 9.3.1). So a connection that has received nothing yet gets a short window for its first byte
 * (NEW_CONNECTION_FIRST_BYTE from its acceptance, within the request-head deadline and the grace period, as Go's
 * `Server.Shutdown` takes a new connection for idle only after 5 s); its first request is then answered with
 * `Connection: close`. A keep-alive connection idle between requests still closes at once (RFC 9112 section 9.5).
 */
class StopFirstRequestJvmTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun negative_aFirstRequestThatComesJustAfterTheStopBeganIsAnswered() =
        serverTest {
            val server =
                kuicksilverServer(null, configure = {
                    plainConnector {
                        host = "127.0.0.1"
                        port = 0
                    }
                    http3 = false
                }) { routing { post("/order") { call.respondText("placed") } } }
            server.startSuspend(wait = false)
            val port =
                server.engine
                    .resolvedConnectors()
                    .first()
                    .port
            val selector = SelectorManager(Dispatchers.IO)
            try {
                val tcp = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                try {
                    val w = tcp.openWriteChannel(autoFlush = true)
                    val r = tcp.openReadChannel()
                    withTimeout(10.seconds) { server.engine.openTcpSockets.first { it == 1 } }
                    coroutineScope {
                        val stop = async { server.stopSuspend(10_000, 15_000) }
                        // the request comes 300 ms after the stop began: a client that was still sending it
                        delay(300.milliseconds)
                        w.writeStringUtf8("POST /order HTTP/1.1\r\nHost: s\r\nContent-Length: 0\r\n\r\n")
                        val got = StringBuilder()
                        val b = ByteArray(4096)
                        withTimeout(15.seconds) {
                            while (true) {
                                val n = r.readOrFail(b)
                                if (n < 0) break
                                got.append(b.decodeToString(0, n))
                            }
                        }
                        assertTrue(got.startsWith("HTTP/1.1 200 "), "the first request was not answered: '$got'")
                        assertTrue(Regex("(?im)^connection: *close\\r?$").containsMatchIn(got), "no Connection: close: '$got'")
                        assertTrue(got.endsWith("placed"), "$got")
                        withTimeout(15.seconds) { stop.await() }
                    }
                } finally {
                    tcp.close()
                }
            } finally {
                selector.close()
            }
        }
}
