// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.net.BindException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** [assertNoLoopbackSquatter]: a test server on 127.0.0.1 passes it; one on the wildcard address is caught where it is exposed. */
class LoopbackSquatterTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))

    private suspend fun started(host: String?): Server {
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector /* wildcard on purpose: the shadowed server */ {
                    tls { identity = ServerFixtures.identity() }
                    host?.let { this.host = it }
                    port = 0
                }
                http3 { enabled = false }
            }) { routing { get("/") { call.respondText("ok") } } }
        server.startSuspend(wait = false)
        return server
    }

    private suspend fun Server.port() =
        engine
            .resolvedConnectors()
            .first()
            .port

    @Test fun loopbackServerPasses() =
        runBlocking {
            withTimeout(30.seconds) {
                val server = started("127.0.0.1")
                try {
                    val port = server.port()
                    assertNoLoopbackSquatter(port)
                    // and the request still reaches the server
                    val r = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                    assertTrue(r.startsWith("HTTP/1.1 200 "), r)
                } finally {
                    server.stopSuspend(100, 500)
                }
            }
        }

    /**
     * The failure the check exists for, made on purpose: a listener on 127.0.0.1 next to a wildcard server takes the
     * connections to 127.0.0.1, and the check reports the server. An OS that refuses that listener (Linux: the wildcard
     * bind owns the port on every address) cannot shadow the server, and the check passes there.
     */
    @Test fun negative_wildcardServerIsShadowedOnLoopback() =
        runBlocking {
            withTimeout(30.seconds) {
                val server = started(null)
                try {
                    val port = server.port()
                    val reported = runCatching { assertNoLoopbackSquatter(port) }.exceptionOrNull()
                    ServerSocket().use { squatter ->
                        val took =
                            try {
                                squatter.bind(InetSocketAddress(loopback, port))
                                true
                            } catch (_: BindException) {
                                false
                            }
                        assertEquals(took, reported != null, "the check reports exactly the servers a squatter can shadow ($reported)")
                        if (!took) return@withTimeout
                        squatter.soTimeout = 10_000 // a bound for a broken run, not a wait: the connection is in the backlog already
                        Socket(loopback, port).use { client ->
                            squatter.accept().use { stolen ->
                                assertEquals(client.localPort, stolen.port, "the connection to 127.0.0.1 reached the squatter")
                            }
                        }
                    }
                } finally {
                    server.stopSuspend(100, 500)
                }
            }
        }
}
