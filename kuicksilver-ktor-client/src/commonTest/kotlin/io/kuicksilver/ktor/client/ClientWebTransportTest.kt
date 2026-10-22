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
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.routing.routing
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.readRemaining
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

/** `HttpClient.webTransport`: a WebTransport session on a dedicated HTTP/3 connection of the engine. */
class ClientWebTransportTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private class OtherEngine : HttpClientEngineBase("other") {
        override val config: HttpClientEngineConfig = HttpClientEngineConfig()

        override suspend fun execute(data: HttpRequestData): HttpResponseData = error("not used")
    }

    private fun KuicksilverEngine.dedicated() = h3.dedicatedCount

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
                    assertEquals("ping", withTimeout(10.seconds) { st.input.readRemaining().readString() })
                    session.trySendDatagram(byteArrayOf(4, 2))
                    assertContentEquals(byteArrayOf(4, 2), withTimeout(10.seconds) { session.receiveDatagram() })
                    session.close(0, "done")
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /** Each session has a connection of its own, outside the pool; closing the session closes it. */
    @Test fun closeClosesDedicatedConnection() =
        h3Test {
            val seen = CompletableDeferred<WebTransportCloseInfo>()
            val (server, port) =
                testServer(configure = { webTransport = true }) { routing { webTransport("/wt") { seen.complete(it.closed.await()) } } }
            try {
                testClient(Http3DiscoveryMode.Auto).use { client ->
                    val engine = client.engine as KuicksilverEngine
                    val session = client.webTransport("https://127.0.0.1:$port/wt")
                    assertEquals(1, engine.dedicated().value)
                    assertEquals(0, engine.h3.connectionsForProbe()) // not pooled
                    session.close(7, "bye")
                    withTimeout(10.seconds) { engine.dedicated().first { it == 0 } }
                    assertEquals(0, engine.h3.connectionsForProbe())
                    // the connection closed after the session's close reached the server, not instead of it
                    val info = withTimeout(10.seconds) { seen.await() }
                    assertEquals(7L to "bye", info.code to info.reason)
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /** The server ending the session ends the dedicated connection too. */
    @Test fun serverCloseClosesDedicatedConnection() =
        h3Test {
            val (server, port) = testServer(configure = { webTransport = true }) { routing { webTransport("/wt") { } } }
            try {
                testClient(Http3DiscoveryMode.Auto).use { client ->
                    val engine = client.engine as KuicksilverEngine
                    val session = client.webTransport("https://127.0.0.1:$port/wt")
                    assertEquals(0L, withTimeout(10.seconds) { session.closed.await() }.code)
                    withTimeout(10.seconds) { engine.dedicated().first { it == 0 } }
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
                    withTimeout(10.seconds) { engine.dedicated().first { it == 0 } } // the connection does not stay
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
            client.close()
            assertFailsWith<IllegalStateException> { client.webTransport("https://127.0.0.1:1/wt") }
            assertFalse(engine.h3.endpointBoundForTest)
            assertEquals(0, engine.dedicated().value)
        }

    /** WebTransport runs over UDP: a proxy that applies to the URL refuses it, with how to get around that. */
    @Test fun negative_proxyRefused() =
        clientTest {
            testClient(Http3DiscoveryMode.Auto, engine = { proxy = ProxyBuilder.http("http://127.0.0.1:9") }).use { client ->
                val e = assertFailsWith<UnsupportedOperationException> { client.webTransport("https://127.0.0.1:1/wt") }
                assertTrue("webTransportIgnoresProxy" in e.message.orEmpty(), e.message)
                assertEquals(0, (client.engine as KuicksilverEngine).dedicated().value)
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
                    assertEquals(1, (client.engine as KuicksilverEngine).dedicated().value)
                    first.close()
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /** A call cancelled while the server has not answered the CONNECT closes the connection it opened. */
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
                        withTimeout(10.seconds) { engine.dedicated().first { it == 0 } }
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
}
