// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.ktor.utils.io.InternalAPI::class)

package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.HttpClientEngineBase
import io.ktor.client.engine.HttpClientEngineConfig
import io.ktor.client.engine.ProxyBuilder
import io.ktor.client.engine.http
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.WebTransportCloseInfo
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.ktor.server.webTransport
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.io.readString
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** `HttpClient.webTransport`: WebTransport sessions on the engine's pooled HTTP/3 connections (RFC 9114 section 3.3). */
class ClientWebTransportTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private class OtherEngine : HttpClientEngineBase("other") {
        override val config: HttpClientEngineConfig = HttpClientEngineConfig()

        override suspend fun execute(data: HttpRequestData): HttpResponseData = error("not used")
    }

    private fun KuicksilverEngine.sessions() = h3.webTransportSessions

    @Test fun echoAgainstKuicksilverServer() =
        h3Test {
            val (server, port) =
                testServer(configure = { webTransport = true }) {
                    routing {
                        webTransport("/wt") { session ->
                            val st = session.acceptBidi()
                            st.input.copyTo(st.output)
                            st.output.flushAndClose()
                            session.sendDatagram(session.receiveDatagram())
                            session.closed.await()
                        }
                    }
                }
            try {
                testClient(Http3DiscoveryMode.Auto).use { client ->
                    val session = client.webTransport("https://127.0.0.1:$port/wt")
                    val st = session.openBidi()
                    st.output.writeFully("ping".encodeToByteArray())
                    st.output.flushAndClose()
                    assertEquals("ping", withTimeout(10.seconds) { st.input.readBuffer().readString() })
                    session.trySendDatagram(byteArrayOf(4, 2))
                    assertContentEquals(byteArrayOf(4, 2), withTimeout(10.seconds) { session.receiveDatagram() })
                    session.close(0, "done")
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /**
     * A session uses the pooled connection of its origin and keeps it in use; closing the session returns it to normal
     * idle handling (it stays pooled), after the session's close reached the server.
     */
    @Test fun closingTheSessionReturnsTheConnectionToThePool() =
        h3Test {
            val seen = CompletableDeferred<WebTransportCloseInfo>()
            val (server, port) =
                testServer(configure = { webTransport = true }) { routing { webTransport("/wt") { seen.complete(it.closed.await()) } } }
            try {
                testClient(Http3DiscoveryMode.Auto).use { client ->
                    val engine = client.engine as KuicksilverEngine
                    val session = client.webTransport("https://127.0.0.1:$port/wt")
                    assertEquals(1, engine.sessions().value)
                    assertEquals(1, engine.h3.connectionsForProbe()) // the pooled one
                    session.close(7, "bye")
                    withTimeout(10.seconds) { engine.sessions().first { it == 0 } }
                    assertEquals(1, engine.h3.connectionsForProbe(), "still pooled, idle")
                    val info = withTimeout(10.seconds) { seen.await() }
                    assertEquals(7L to "bye", info.code to info.reason)
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /** RFC 9114 section 3.3: two sessions to one origin share one connection (both sides declare flow control). */
    @Test fun twoSessionsOfOneOriginShareOneConnection() =
        h3Test {
            val (server, port) = testServer(configure = { webTransport = true }) { routing { webTransport("/wt") { echo(it) } } }
            try {
                testClient(Http3DiscoveryMode.Auto).use { client ->
                    val engine = client.engine as KuicksilverEngine
                    val a = client.webTransport("https://127.0.0.1:$port/wt")
                    val b = client.webTransport("https://127.0.0.1:$port/wt")
                    assertEquals(1, engine.h3.connectionsForProbe(), "one connection")
                    assertEquals("a", roundTrip(a, "a"))
                    assertEquals("b", roundTrip(b, "b"))
                    // one session ends; the other keeps working on the same connection
                    a.close(0, "")
                    withTimeout(10.seconds) { a.closed.await() }
                    assertEquals("b again", roundTrip(b, "b again"))
                    assertEquals(1, engine.h3.connectionsForProbe())
                    b.close()
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /** Requests to the origin go over the same connection as its sessions (it replaced the request-only one). */
    @Test fun requestsShareTheSessionsConnection() =
        h3Test {
            val (server, port) =
                testServer(configure = { webTransport = true }) {
                    routing {
                        webTransport("/wt") { it.closed.await() }
                        get("/") { call.respondText("ok") }
                    }
                }
            try {
                testClient(Http3DiscoveryMode.H3Only).use { client ->
                    val engine = client.engine as KuicksilverEngine
                    assertEquals("ok", client.get("https://127.0.0.1:$port/").bodyAsText())
                    val session = client.webTransport("https://127.0.0.1:$port/wt")
                    assertEquals("ok", client.get("https://127.0.0.1:$port/").bodyAsText())
                    // the request-only connection was idle: it closed at once; one connection carries both
                    withTimeout(10.seconds) { while (engine.h3.connectionsForProbe() != 1) kotlinx.coroutines.yield() }
                    assertEquals(1, engine.h3.connectionsForTest().size)
                    session.close()
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /**
     * Section 5.2: a server at its session limit refuses one more with H3_REQUEST_REJECTED; the session opens on a second
     * connection, and both keep working.
     */
    @Test fun serverLimitReachedOpensASecondConnection() =
        h3Test {
            val (server, port) =
                testServer(configure = {
                    webTransport = true
                    http3Settings =
                        http3Settings {
                            enableConnectProtocol = true
                            webTransport = true
                            webTransportMaxSessions = 1
                        }
                }) { routing { webTransport("/wt") { echo(it) } } }
            try {
                testClient(Http3DiscoveryMode.Auto).use { client ->
                    val engine = client.engine as KuicksilverEngine
                    val a = client.webTransport("https://127.0.0.1:$port/wt")
                    val b = client.webTransport("https://127.0.0.1:$port/wt")
                    assertEquals(2, engine.h3.connectionsForProbe(), "a second connection for the second session")
                    assertEquals("a", roundTrip(a, "a"))
                    assertEquals("b", roundTrip(b, "b"))
                    // a third shares the second connection? No: it is full too (limit 1), so a third one
                    val c = client.webTransport("https://127.0.0.1:$port/wt")
                    assertEquals("c", roundTrip(c, "c"))
                    // the extra connection closes with its session
                    b.close()
                    withTimeout(10.seconds) { while (engine.h3.connectionsForProbe() != 2) kotlinx.coroutines.yield() }
                    a.close()
                    c.close()
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /**
     * Sessions racing past a full connection share one new connection rather than opening one each (RFC 9114 section 3.3:
     * "Clients SHOULD NOT open more than one HTTP/3 connection to a given IP address and UDP port"): ten at once with four
     * a connection take three connections, every session works, and the extra ones close with their last session.
     */
    @Test fun negative_racingSessionsShareTheExtraConnections() =
        h3Test {
            val (server, port) = testServer(configure = { webTransport = true }) { routing { webTransport("/wt") { echo(it) } } }
            try {
                testClient(Http3DiscoveryMode.Auto).use { client ->
                    val engine = client.engine as KuicksilverEngine
                    val sessions =
                        coroutineScope { List(10) { async { client.webTransport("https://127.0.0.1:$port/wt") } }.map { it.await() } }
                    assertEquals(3, engine.h3.connectionsForProbe(), "four sessions a connection")
                    sessions.forEachIndexed { i, s -> assertEquals("s$i", roundTrip(s, "s$i")) }
                    for (s in sessions) s.close()
                    withTimeout(20.seconds) { while (engine.h3.connectionsForProbe() > 1) kotlinx.coroutines.yield() }
                    assertEquals(0, engine.sessions().value)
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /** Section 5.1: without flow control on the server a connection carries one session; the second gets its own. */
    @Test fun negative_withoutFlowControlEachSessionGetsAConnection() =
        h3Test {
            val (server, port) =
                testServer(configure = {
                    webTransport = true
                    http3Settings =
                        http3Settings {
                            enableConnectProtocol = true
                            webTransport = true
                            webTransportInitialMaxStreamsBidi = 0
                            webTransportInitialMaxStreamsUni = 0
                            webTransportInitialMaxData = 0
                        }
                }) { routing { webTransport("/wt") { echo(it) } } }
            try {
                testClient(Http3DiscoveryMode.Auto).use { client ->
                    val engine = client.engine as KuicksilverEngine
                    val a = client.webTransport("https://127.0.0.1:$port/wt")
                    val b = client.webTransport("https://127.0.0.1:$port/wt")
                    assertEquals(2, engine.h3.connectionsForProbe())
                    assertEquals("a", roundTrip(a, "a"))
                    assertEquals("b", roundTrip(b, "b"))
                    a.close()
                    b.close()
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /** The connection's loss ends every session on it, with the connection's reason. */
    @Test fun connectionLossEndsEverySession() =
        h3Test {
            val (server, port) = testServer(configure = { webTransport = true }) { routing { webTransport("/wt") { it.closed.await() } } }
            testClient(Http3DiscoveryMode.Auto).use { client ->
                val engine = client.engine as KuicksilverEngine
                val a = client.webTransport("https://127.0.0.1:$port/wt")
                val b = client.webTransport("https://127.0.0.1:$port/wt")
                engine.h3
                    .connectionsForTest()
                    .single()
                    .quic
                    .close(0x100, "gone")
                val ia = withTimeout(10.seconds) { a.closed.await() }
                val ib = withTimeout(10.seconds) { b.closed.await() }
                assertTrue(ia.cause != null && ib.cause != null, "$ia / $ib")
                assertFailsWith<io.kuicksilver.http3.WebTransportException.SessionClosed> { a.openBidi() }
                withTimeout(10.seconds) { engine.sessions().first { it == 0 } }
            }
            server.stopSuspend(100, 1000)
        }

    /** The server ending the session ends it on the client too, and frees its place. */
    @Test fun serverCloseEndsTheSession() =
        h3Test {
            val (server, port) = testServer(configure = { webTransport = true }) { routing { webTransport("/wt") { } } }
            try {
                testClient(Http3DiscoveryMode.Auto).use { client ->
                    val engine = client.engine as KuicksilverEngine
                    val session = client.webTransport("https://127.0.0.1:$port/wt")
                    assertEquals(0L, withTimeout(10.seconds) { session.closed.await() }.code)
                    withTimeout(10.seconds) { engine.sessions().first { it == 0 } }
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun serverWithoutWtFailsWithSettings() =
        h3Test {
            val (server, port) = testServer { routing { } }
            try {
                testClient(Http3DiscoveryMode.Auto).use { client ->
                    val engine = client.engine as KuicksilverEngine
                    assertFailsWith<Http3Exception.Settings> { client.webTransport("https://127.0.0.1:$port/wt") }
                    withTimeout(10.seconds) { engine.sessions().first { it == 0 } } // no session stays counted
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun negative_nonKuicksilverEngineFails() =
        clientTest {
            HttpClient(OtherEngine()).use { client ->
                assertFailsWith<IllegalStateException> { client.webTransport("https://example.com/wt") }
            }
        }

    @Test fun negative_plainHttpRefused() =
        clientTest {
            testClient(Http3DiscoveryMode.Auto).use { client ->
                assertFailsWith<IllegalArgumentException> { client.webTransport("http://127.0.0.1:1/wt") }
            }
        }

    /** After HttpClient.close() no endpoint is bound again: the call fails and leaves nothing behind. */
    @Test fun negative_afterCloseFails() =
        clientTest {
            val client = testClient(Http3DiscoveryMode.Auto)
            val engine = client.engine as KuicksilverEngine
            client.close() // refuses at once, before the engine's asynchronous cleanup
            val e = assertFailsWith<IllegalStateException> { client.webTransport("https://127.0.0.1:1/wt") }
            assertEquals("the client is closed", e.message)
            assertFalse(engine.h3.endpointBoundForTest)
            assertEquals(0, engine.sessions().value)
        }

    /** WebTransport runs over UDP: a proxy that applies to the URL refuses it, with how to get around that. */
    @Test fun negative_proxyRefused() =
        clientTest {
            testClient(Http3DiscoveryMode.Auto, engine = { proxy = ProxyBuilder.http("http://127.0.0.1:9") }).use { client ->
                val e = assertFailsWith<UnsupportedOperationException> { client.webTransport("https://127.0.0.1:1/wt") }
                assertTrue("webTransportIgnoresProxy" in e.message.orEmpty(), e.message)
                assertEquals(0, (client.engine as KuicksilverEngine).sessions().value)
            }
        }

    @Test fun proxyIgnoredWhenAsked() =
        h3Test {
            val (server, port) = testServer(configure = { webTransport = true }) { routing { webTransport("/wt") { } } }
            try {
                testClient(Http3DiscoveryMode.Auto, engine = {
                    proxy = ProxyBuilder.http("http://127.0.0.1:9")
                    http3 { webTransportIgnoresProxy = true }
                }).use { client ->
                    assertEquals(0L, withTimeout(10.seconds) { client.webTransport("https://127.0.0.1:$port/wt").closed.await() }.code)
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun negative_h1OnlyRefused() =
        clientTest {
            testClient(Http3DiscoveryMode.H1Only).use { client ->
                assertFailsWith<UnsupportedOperationException> { client.webTransport("https://127.0.0.1:1/wt") }
            }
        }

    /** At most maxWebTransportSessions at once; one more fails at once instead of waiting. */
    @Test fun negative_sessionCapExceeded() =
        h3Test {
            val (server, port) = testServer(configure = { webTransport = true }) { routing { webTransport("/wt") { it.closed.await() } } }
            try {
                testClient(Http3DiscoveryMode.Auto, engine = { http3 { maxWebTransportSessions = 1 } }).use { client ->
                    val first = client.webTransport("https://127.0.0.1:$port/wt")
                    val e = assertFailsWith<IllegalStateException> { client.webTransport("https://127.0.0.1:$port/wt") }
                    assertTrue("maxWebTransportSessions" in e.message.orEmpty(), e.message)
                    assertEquals(1, (client.engine as KuicksilverEngine).sessions().value)
                    first.close()
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /** A call cancelled while the server has not answered the CONNECT frees its place. */
    @Test fun cancellationDuringConnectReleasesTheConnection() =
        h3Test {
            val ep =
                Http3Endpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            server =
                                QuicServerConfig
                                    .Builder(
                                        tlsConfig(TlsRole.Server) {
                                            alpn = listOf("h3")
                                            identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
                                        },
                                    ).build()
                        }.build(),
                    http3Settings {
                        enableConnectProtocol = true
                        webTransport = true
                    },
                )
            try {
                coroutineScope {
                    val got = CompletableDeferred<Unit>()
                    launch {
                        val conn = ep.accept()
                        conn.acceptRequest() // and never answered
                        got.complete(Unit)
                    }
                    testClient(Http3DiscoveryMode.Auto).use { client ->
                        val engine = client.engine as KuicksilverEngine
                        val call = async { client.webTransport("https://127.0.0.1:${ep.localAddress.port}/wt") }
                        withTimeout(10.seconds) { got.await() }
                        call.cancel()
                        withTimeout(10.seconds) { engine.sessions().first { it == 0 } }
                    }
                }
            } finally {
                ep.close()
            }
        }

    /** An address whose handshake fails gives way to the next resolved one within the connect timeout. */
    @Test fun nextAddressAfterAFailedHandshake() =
        h3Test {
            val (server, port) = testServer(configure = { webTransport = true }) { routing { webTransport("/wt") { } } }
            val wrong =
                QuicEndpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig
                                    .Builder(
                                        tlsConfig(TlsRole.Server) {
                                            alpn = listOf("not-h3") // refuses our handshake at once
                                            identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
                                        },
                                    ).build()
                        }.build(),
                )
            try {
                testClient(Http3DiscoveryMode.Auto, engine = {
                    resolverForTest = { _, p ->
                        listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), wrong.localAddress.port), TcpAddress(byteArrayOf(127, 0, 0, 1), p))
                    }
                }).use { client ->
                    assertEquals(0L, withTimeout(10.seconds) { client.webTransport("https://server.test:$port/wt").closed.await() }.code)
                }
            } finally {
                wrong.close()
                server.stopSuspend(100, 1000)
            }
        }

    private suspend fun echo(session: io.kuicksilver.http3.WebTransportSession) {
        while (true) {
            val st = runCatching { session.acceptBidi() }.getOrNull() ?: return
            st.input.copyTo(st.output)
            st.output.flushAndClose()
        }
    }

    private suspend fun roundTrip(
        session: io.kuicksilver.http3.WebTransportSession,
        text: String,
    ): String {
        val st = session.openBidi()
        st.output.writeFully(text.encodeToByteArray())
        st.output.flushAndClose()
        return withTimeout(10.seconds) { st.input.readBuffer().readString() }
    }
}
