// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationStopPreparing
import io.ktor.server.engine.ConnectorType
import io.ktor.server.engine.EngineConnectorBuilder
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readLineStrict
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.network.tls
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

class ServerH1Test {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val get = "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n"

    @Test fun getOverTls() =
        serverTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get(
                            "/",
                        ) { call.respondText("ok ${call.request.httpVersion} ${call.request.local.scheme}") }
                    }
                }
            try {
                assertTrue(port > 0)
                val resp = rawHttp(port, get)
                assertTrue(resp.startsWith("HTTP/1.1 200"), resp)
                assertTrue(resp.endsWith("ok HTTP/1.1 https"), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun keepAliveTwoRequests() =
        serverTest {
            val (server, port) = tlsServer { routing { get("/") { call.respondText("p=${call.request.local.remotePort}") } } }
            try {
                val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\n\r\n$get")
                val bodies = Regex("p=(\\d+)").findAll(resp).map { it.groupValues[1] }.toList()
                assertEquals(2, bodies.size, resp)
                assertEquals(bodies[0], bodies[1])
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun chunkedResponse() =
        serverTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/") {
                            call.respondBytesWriter {
                                writeStringUtf8("a")
                                flush()
                                writeStringUtf8("b")
                            }
                        }
                    }
                }
            try {
                val resp = rawHttp(port, get)
                assertTrue(resp.contains("Transfer-Encoding: chunked"), resp)
                assertTrue(resp.contains("1\r\na\r\n"), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun plainHttpConnector() =
        serverTest {
            val server =
                embeddedServer(Kuicksilver, configure = {
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                }) { routing { get("/") { call.respondText("plain ${call.request.local.scheme}") } } }
            server.startSuspend(false)
            try {
                val resp =
                    rawHttp(
                        server.engine
                            .resolvedConnectors()
                            .first()
                            .port,
                        get,
                        tls = null,
                    )
                assertTrue(resp.endsWith("plain http"), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun identityTurnsPortConnectorIntoTls() =
        serverTest {
            val server =
                embeddedServer(Kuicksilver, configure = {
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                    identity =
                        ServerFixtures.identity()
                }) { routing { get("/") { call.respondText("tls ${call.request.local.scheme}") } } }
            server.startSuspend(false)
            try {
                val resp =
                    rawHttp(
                        server.engine
                            .resolvedConnectors()
                            .first()
                            .port,
                        get,
                    )
                assertTrue(resp.endsWith("tls https"), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun handshakeFailureClosesOnlyThatConnection() =
        serverTest {
            val (server, port) = tlsServer { routing { get("/") { call.respondText("ok") } } }
            try {
                assertFailsWith<TlsException> {
                    rawHttp(
                        port,
                        get,
                        ServerFixtures.clientTls(trust = TrustConfig.AnchoredCa(listOf(io.kuicksilver.tls.Certificate(TestCerts.otherCa)))),
                    )
                }
                assertTrue(rawHttp(port, get).endsWith("ok"))
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun peerCertificatesOptionalClientAuth() =
        serverTest {
            val (server, port) =
                tlsServer(connector = {
                    clientAuth = ClientAuth.Optional
                    trust =
                        TrustConfig.AnchoredCa(listOf(ServerFixtures.testCa))
                }) {
                    routing { get("/") { call.respondText("certs=${call.request.peerCertificates.size}") } }
                }
            try {
                rawHttp(port, get).let { assertTrue(it.endsWith("certs=0"), it) }
                val withCert =
                    ServerFixtures.clientTls(
                        identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf()),
                    )
                rawHttp(port, get, withCert).let { assertTrue(!it.endsWith("certs=0"), it) } // the validated chain: leaf and CA
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun stopClosesThePort() =
        serverTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/") {
                            delay(50)
                            call.respondText("ok")
                        }
                    }
                }
            assertTrue(rawHttp(port, get).endsWith("ok"))
            server.stop(100, 500)
            assertFailsWith<Throwable> { rawHttp(port, get) }
        }

    /**
     * A graceful stop does not wait for an idle keep-alive client. Before, its connection sat in the request parser until
     * the idle timeout, so `stop(gracePeriod, ...)` took the whole grace period (here 30 s) while any keep-alive client
     * was connected; now the connection closes as soon as accepting stops.
     */
    @Test fun gracefulStopClosesIdleKeepAliveConnections() =
        serverTest {
            val (server, port) = tlsServer { routing { get("/") { call.respondText("ok") } } }
            val selector = SelectorManager(Dispatchers.Default)
            try {
                val socket = aSocket(selector).tcp().connect("127.0.0.1", port).tls(ServerFixtures.clientTls())
                val w = socket.openWriteChannel(autoFlush = true)
                val r = socket.openReadChannel()
                w.writeStringUtf8("GET / HTTP/1.1\r\nHost: server.test\r\n\r\n")
                assertEquals("HTTP/1.1 200 OK", r.readLineStrict())
                while (r.readLineStrict()?.isNotEmpty() == true) continue // the rest of the head
                assertEquals("ok", r.readByteArray(2).decodeToString())

                withTimeout(10.seconds) { server.stopSuspend(30_000, 40_000) }
                assertEquals(null, r.readLineStrict(), "the idle keep-alive connection is still open after the stop")
                socket.close()
            } finally {
                selector.close()
            }
        }

    /**
     * A graceful stop waits, up to its grace period, for a response in flight, also a large one to a slow client (Ktor's
     * and Go's `Shutdown` semantics). Before, a connection ended as soon as its socket's `close()` had been called, while
     * the socket was still draining the response; once every connection had, the listener's job completed and closed its
     * selector under the sockets still sending, so the response was cut (on main: at 3.5 of 4 MiB, the stop returning
     * after 3.4 s). A connection now ends only once its socket has closed.
     */
    @Test fun negative_gracefulStopWaitsForALargeResponseInFlight() =
        serverTest {
            val size = 4 * 1024 * 1024
            for (tls in listOf(false, true)) {
                val inHandler = CompletableDeferred<Unit>()
                val stopping = CompletableDeferred<Unit>()
                val module: Application.() -> Unit = {
                    monitor.subscribe(ApplicationStopPreparing) { stopping.complete(Unit) }
                    routing {
                        get("/") {
                            inHandler.complete(Unit)
                            stopping.await()
                            call.respondBytesWriter(contentLength = size.toLong()) {
                                val chunk = ByteArray(64 * 1024) { 'x'.code.toByte() }
                                repeat(size / chunk.size) { writeFully(chunk) }
                            }
                        }
                    }
                }
                val (server, port) =
                    if (tls) {
                        tlsServer(configure = { http3 = false }, module = module)
                    } else {
                        val s =
                            embeddedServer(Kuicksilver, configure = {
                                connector {
                                    host = "127.0.0.1"
                                    port = 0
                                }
                            }, module = module)
                        s.startSuspend(false)
                        s to
                            s.engine
                                .resolvedConnectors()
                                .first()
                                .port
                    }
                coroutineScope {
                    val response =
                        async {
                            slowHttp(
                                port,
                                "GET / HTTP/1.1\r\nHost: server.test\r\n\r\n",
                                tls = if (tls) ServerFixtures.clientTls() else null,
                                // far slower than the server writes: the response is still draining when its handler returns
                                bytesPerSecond = 1024L * 1024,
                            )
                        }
                    inHandler.await()
                    // a grace period well past the 4 s drain: a stop that ran out of it would cut the response by design
                    withTimeout(30.seconds) { server.stopSuspend(20_000, 25_000) }
                    val text = response.await()
                    val body = text.substringAfter("\r\n\r\n")
                    assertEquals(size, body.length, "tls=$tls: the response in flight was cut at ${body.length} bytes")
                }
            }
        }

    /**
     * A response the server writes once a graceful stop has begun carries `Connection: close` (as Go's `Shutdown` makes
     * its in-flight responses do), so the client knows the connection ends after it rather than finding it closed.
     */
    @Test fun responseDuringGracefulStopSaysConnectionClose() =
        serverTest {
            val inHandler = CompletableDeferred<Unit>()
            val stopping = CompletableDeferred<Unit>()
            val (server, port) =
                tlsServer {
                    monitor.subscribe(ApplicationStopPreparing) { stopping.complete(Unit) }
                    routing {
                        get("/") {
                            inHandler.complete(Unit)
                            stopping.await()
                            call.respondText("ok")
                        }
                    }
                }
            coroutineScope {
                val response = async { rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\n\r\n") }
                inHandler.await()
                withTimeout(10.seconds) { server.stopSuspend(30_000, 40_000) }
                val text = response.await()
                assertTrue(text.endsWith("ok"), text)
                assertTrue(text.contains("Connection: close"), text)
            }
        }

    /**
     * A connector on `::1` listens on `::1` only: an IPv4 connect to its port (another address of this host) is refused.
     */
    @Test fun negative_ipv6ConnectorListensOnItsAddressOnly() =
        serverTest {
            val server =
                embeddedServer(Kuicksilver, configure = {
                    connector {
                        host = "::1"
                        port = 0
                    }
                }) { routing { get("/") { call.respondText("reached") } } }
            if (runCatching { server.startSuspend(false) }.isFailure) {
                println("negative_ipv6ConnectorListensOnItsAddressOnly skipped: needs an IPv6 loopback")
                return@serverTest
            }
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                val v4 = runCatching { rawHttp(port, get, tls = null) }
                assertTrue(v4.isFailure, "127.0.0.1:$port reached the connector bound to ::1: ${v4.getOrNull()}")
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun unsupportedConnectorFailsWithConfig() =
        serverTest {
            val server =
                embeddedServer(Kuicksilver, configure = {
                    connectors.add(
                        EngineConnectorBuilder(ConnectorType.HTTPS).apply {
                            host =
                                "127.0.0.1"
                            ; port = 0
                        },
                    )
                }) { }
            assertFailsWith<TlsException.Config> { server.startSuspend(false) }
            runCatching { server.stop(10, 10) }
        }
}
