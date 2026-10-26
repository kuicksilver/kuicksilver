// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.http.HttpProtocolVersion
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.application.Application
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.network.connectTcp
import io.kuicksilver.ktor.network.tls
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
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

    /**
     * A client that asks for a large response and never reads it (send-side slowloris) is disconnected about the idle
     * timeout after the socket stopped taking data, on a plain and on a TLS connector: the engine reports the connection
     * closed, and the client, once it reads, finds the connection reset. Before, the response writer and the socket's
     * close waited for the client for ever. The client is the engines' own socket ([connectTcp]), which turns a write to a
     * reset connection into an error: ktor-network's Kotlin/Native socket lets it raise SIGPIPE, which ends the process.
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
                    sendStallTimeoutForTest = 1.seconds
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
                    val tcp = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                    val socket: Socket = if (tls) tcp.tls(ServerFixtures.clientTls()) else tcp
                    val w = socket.openWriteChannel(autoFlush = true)
                    val r = socket.openReadChannel()
                    w.writeStringUtf8("GET /large HTTP/1.1\r\nHost: s\r\n\r\n")
                    w.flush()
                    withTimeout(20.seconds) { closed.await() }
                    // what the kernel had taken may still be readable; then the connection is reset (or ends), it does not hang
                    withTimeout(20.seconds) {
                        val b = ByteArray(1 shl 16)
                        try {
                            while (r.readAvailable(b, 0, b.size) >= 0) continue
                        } catch (e: Exception) {
                            // the reset: an IOException on the JVM, a PosixException on Kotlin/Native
                            if (e is CancellationException) throw e
                        }
                    }
                    socket.close()
                } finally {
                    selector.close()
                    server.stop(100, 500)
                }
            }
        }

    /**
     * Connections cut because their clients do not read release their sockets, on a plain and on a TLS connector, and
     * `connectionClosed` comes only after that. Before, the abort of a TLS connection cancelled the raw socket's job
     * before the raw socket was closed, so it never closed its descriptor (review of bb8fcb4a: 9 of 16 TLS sockets still
     * open after their `connectionClosed`).
     */
    @Test fun negative_abortedConnectionsReleaseTheirSockets() =
        serverTest {
            for (tls in listOf(false, true)) {
                val clients = 16
                val closed = Channel<Unit>(Channel.UNLIMITED)
                val events =
                    object : KuicksilverServerEventListener() {
                        override fun connectionClosed(
                            protocol: HttpProtocolVersion,
                            remote: InetSocketAddress?,
                        ) {
                            closed.trySend(Unit)
                        }
                    }
                val (server, port) =
                    largeResponseServer(tls) {
                        connectionIdleTimeoutSeconds = 1
                        sendStallTimeoutForTest = 1.seconds
                        eventListener = events
                    }
                val selector = SelectorManager(Dispatchers.Default)
                val sockets = ArrayList<Socket>()
                try {
                    repeat(clients) {
                        // the engines' own socket: the aborts reset these connections, and a write to one (the TLS
                        // close_notify) must fail, not raise SIGPIPE as ktor-network's Kotlin/Native socket lets it
                        val tcp = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                        val socket: Socket = if (tls) tcp.tls(ServerFixtures.clientTls()) else tcp
                        sockets += socket
                        val w = socket.openWriteChannel(autoFlush = true)
                        w.writeStringUtf8("GET /large HTTP/1.1\r\nHost: s\r\n\r\n")
                        w.flush()
                    }
                    withTimeout(30.seconds) { repeat(clients) { closed.receive() } }
                    assertEquals(0, server.engine.openTcpSockets.value, "server sockets still open after connectionClosed (tls=$tls)")
                } finally {
                    sockets.forEach { it.close() }
                    selector.close()
                    server.stop(100, 500)
                }
            }
        }

    /** A server with `GET /large?mib=N` (N MiB, 256 by default), on a plain or a TLS connector without HTTP/3. */
    private suspend fun largeResponseServer(
        tls: Boolean,
        configure: KuicksilverApplicationEngine.Configuration.() -> Unit,
    ): Pair<Server, Int> {
        val large: Application.() -> Unit = {
            routing {
                get("/large") {
                    val mib = call.request.queryParameters["mib"]?.toInt() ?: 256
                    call.respondBytesWriter(contentLength = mib * 1024L * 1024) {
                        val chunk = ByteArray(64 * 1024) { 'x'.code.toByte() }
                        repeat(mib * 16) { writeFully(chunk) }
                    }
                }
            }
        }
        if (tls) {
            return tlsServer({
                http3 = false
                configure()
            }, module = large)
        }
        val s =
            embeddedServer(Kuicksilver, configure = {
                configure()
                connector {
                    host = "127.0.0.1"
                    port = 0
                }
            }, module = large)
        s.startSuspend(false)
        return s to
            s.engine
                .resolvedConnectors()
                .first()
                .port
    }

    /**
     * A slow client's last response is not cut by the close: with a 1 s idle timeout, a client reading 512 KiB/s (plain) or
     * 1 MiB/s (TLS) through a 64 KiB receive buffer gets the whole of a 4 MiB (plain) or 8 MiB (TLS) `Connection: close`
     * response, which takes seconds to drain after the engine has handed it all to the socket (sizes and rates that fail
     * with a close bounded by the idle timeout). The close bound is the stall deadline on progress, not a fixed time. Before,
     * the close was aborted after the idle timeout.
     *
     * The stall deadline (15 s here) has to outlast the client's own buffering: ktor's socket reader takes up to 1 MiB
     * (and the TLS layer as much again) before the client reads it, and refills only once that is nearly drained, so the
     * server's socket takes nothing for that buffer's worth of reading, about 2 s here. With 3 s, and a reader that a
     * pause per read made four times slower on Windows, those gaps passed the deadline and the close was aborted.
     */
    @Test fun negative_slowReaderGetsTheWholeClosingResponse() =
        serverTest {
            for (tls in listOf(false, true)) {
                val mib = if (tls) 8 else 4
                val (server, port) =
                    largeResponseServer(tls) {
                        connectionIdleTimeoutSeconds = 1
                        sendStallTimeoutForTest = 15.seconds
                    }
                try {
                    val text =
                        slowHttp(
                            port,
                            "GET /large?mib=$mib HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n",
                            tls = if (tls) ServerFixtures.clientTls() else null,
                            bytesPerSecond = if (tls) 1024L * 1024 else 512L * 1024,
                        )
                    val body = text.substringAfter("\r\n\r\n").length
                    assertEquals(mib * 1024 * 1024, body, "tls=$tls: the closing response was cut at $body bytes")
                } finally {
                    server.stop(100, 500)
                }
            }
        }

    /**
     * A request body that stops arriving (slow POST, R.U.D.Y.): after the idle timeout without a byte, the handler's read
     * fails, the client gets `408 Request Timeout` with `Connection: close`, and the connection closes. Before, the
     * handler waited for the rest of the body for ever.
     */
    @Test fun negative_stalledRequestBodyGets408() =
        serverTest {
            val server =
                embeddedServer(Kuicksilver, configure = {
                    connectionIdleTimeoutSeconds = 1
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                }) { routing { post("/echo") { call.respondText(call.receiveText()) } } }
            server.startSuspend(false)
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                val received =
                    withTimeout(10.seconds) {
                        rawHttp(port, "POST /echo HTTP/1.1\r\nHost: s\r\nContent-Length: 100\r\n\r\n0123456789", tls = null)
                    }
                assertTrue(received.startsWith("HTTP/1.1 408 "), received)
                assertTrue(received.contains("\r\nConnection: close\r\n"), received)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * `Expect: 100-continue` through the engine: the body deadline starts when the engine has sent `100 Continue` (as the
     * handler asks for the body), so a client that then sends nothing gets 408 after the idle timeout.
     */
    @Test fun negative_bodyThatNeverFollowsContinueGets408() =
        serverTest {
            val server =
                embeddedServer(Kuicksilver, configure = {
                    connectionIdleTimeoutSeconds = 1
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                }) { routing { post("/echo") { call.respondText(call.receiveText()) } } }
            server.startSuspend(false)
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                val received =
                    withTimeout(10.seconds) {
                        rawHttp(port, "POST /echo HTTP/1.1\r\nHost: s\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n", tls = null)
                    }
                assertTrue(received.startsWith("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 408 "), received)
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
