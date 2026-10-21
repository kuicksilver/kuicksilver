// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.http.HttpProtocolVersion
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.application.Application
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.network.tls
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withTimeout
import kotlinx.io.IOException
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

    /**
     * A client that asks for a large response and never reads it (send-side slowloris) is disconnected about the idle
     * timeout after the socket stopped taking data, on a plain and on a TLS connector: the engine reports the connection
     * closed, and the client, once it reads, reaches the end of the stream. Before, the response writer and the socket's
     * close waited for the client for ever.
     */
    @Test fun negative_clientThatNeverReadsIsDisconnected() =
        serverTest {
            for (tls in listOf(false, true)) {
                val closed = CompletableDeferred<Unit>()
                val events =
                    object : KuicksilverServerEventListener() {
                        override fun connectionClosed(
                            protocol: HttpProtocolVersion,
                            remote: InetSocketAddress?,
                        ) {
                            closed.complete(Unit)
                        }
                    }
                val large: Application.() -> Unit = {
                    routing {
                        get("/large") {
                            call.respondBytesWriter {
                                val chunk = ByteArray(64 * 1024)
                                repeat(4096) { writeFully(chunk) } // 256 MiB
                            }
                        }
                    }
                }
                val configure: KuicksilverApplicationEngine.Configuration.() -> Unit = {
                    connectionIdleTimeoutSeconds = 1
                    eventListener = events
                }
                val (server, port) =
                    if (tls) {
                        tlsServer(configure, module = large)
                    } else {
                        val s =
                            embeddedServer(Kuicksilver, configure = {
                                configure()
                                connector {
                                    host = "127.0.0.1"
                                    port = 0
                                }
                            }, module = large)
                        s.startSuspend(false)
                        s to
                            s.engine
                                .resolvedConnectors()
                                .first()
                                .port
                    }
                val selector = SelectorManager(Dispatchers.Default)
                try {
                    val tcp = aSocket(selector).tcp().connect("127.0.0.1", port)
                    val socket: Socket = if (tls) tcp.tls(ServerFixtures.clientTls()) else tcp
                    val w = socket.openWriteChannel(autoFlush = true)
                    val r = socket.openReadChannel()
                    w.writeStringUtf8("GET /large HTTP/1.1\r\nHost: s\r\n\r\n")
                    w.flush()
                    withTimeout(20.seconds) { closed.await() }
                    // what the kernel had taken is still readable; then the stream ends (or is reset), it does not hang
                    withTimeout(20.seconds) {
                        val b = ByteArray(1 shl 16)
                        try {
                            while (r.readAvailable(b, 0, b.size) >= 0) Unit
                        } catch (_: IOException) {
                        }
                    }
                    socket.close()
                } finally {
                    selector.close()
                    server.stop(100, 500)
                }
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
