// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The engine's request-head deadline on real sockets (`requestHeaderTimeoutSeconds`); the timing itself is covered on
 * virtual time by `h1.H1PipelineTimeoutTest`. Each test waits for the server to close, about one second.
 */
class ServerH1TimeoutTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A client that connects to a TLS connector and never starts the handshake is closed at the deadline. */
    @Test fun negative_silentClientOnTlsConnectorIsClosed() =
        serverTest {
            val (server, port) =
                tlsServer(
                    configure = { requestHeaderTimeoutSeconds = 1 },
                ) { routing { get("/") { call.respondText("ok") } } }
            try {
                val received = withTimeout(10.seconds) { rawHttp(port, "", tls = null) }
                assertEquals("", received)
            } finally {
                server.stop(100, 500)
            }
        }

    /** A head left unfinished on a plain connector gets 408 and the connection closes. */
    @Test fun negative_unfinishedHeadGets408() =
        serverTest {
            val server =
                embeddedServer(Kuicksilver, configure = {
                    requestHeaderTimeoutSeconds = 1
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                }) { routing { get("/") { call.respondText("ok") } } }
            server.startSuspend(false)
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                val received = withTimeout(10.seconds) { rawHttp(port, "GET / HTTP/1.1\r\nHost: s\r\n", tls = null) }
                assertTrue(received.startsWith("HTTP/1.1 408 "), received)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun requestHeaderTimeoutMustBePositive() {
        val c = KuicksilverApplicationEngine.Configuration()
        assertEquals(30, c.requestHeaderTimeoutSeconds)
        for (bad in listOf(0, -1)) {
            val e = assertFailsWith<IllegalArgumentException> { c.requestHeaderTimeoutSeconds = bad }
            assertEquals("requestHeaderTimeoutSeconds must be positive", e.message)
        }
    }
}
