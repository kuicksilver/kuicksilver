// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.seconds

/** HTTP/3 over real UDP on loopback with OpenSSL (KslQuicCrypto) and ALPN h3. */
class RealUdpH3Test {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun loopbackGet() =
        runBlocking {
            withTimeout(60.seconds) {
                val server =
                    Http3Endpoint.bind(
                        InetSocketAddress("127.0.0.1", 0),
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                this.server =
                                    QuicServerConfig.Builder(H3Fixtures.server()).build()
                            }.build(),
                    )
                val client = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
                try {
                    val serving =
                        launch {
                            val conn = server.accept()
                            coroutineScope {
                                while (true) {
                                    val r = conn.acceptRequest()
                                    launch {
                                        val w = r.respond(200)
                                        w.output.writeStringUtf8("hello ${r.path}")
                                        w.finish()
                                    }
                                }
                            }
                        }
                    val conn = client.connect(server.localAddress, H3Fixtures.client())
                    assertEquals("h3", conn.quic.negotiatedAlpn)
                    val bodies =
                        coroutineScope {
                            (0 until 100)
                                .map { i ->
                                    async {
                                        conn
                                            .request(
                                                http3Request("GET", "server.test", "/$i"),
                                            ).body
                                            .readAllBytes()
                                            .decodeToString()
                                    }
                                }.awaitAll()
                        }
                    assertEquals((0 until 100).map { "hello /$it" }, bodies)
                    serving.cancel() // before the client closes: a finish() still running would fail on that close
                    conn.close()
                } finally {
                    client.close()
                    server.close()
                }
            }
        }

    /** RFC 9114 section 5.2: an endpoint closed by the application ends its connections with H3_NO_ERROR, not code 0 (H3 has no code 0). */
    @Test fun closingAnEndpointClosesItsConnectionsWithH3NoError() =
        runBlocking {
            withTimeout(60.seconds) {
                val server =
                    Http3Endpoint.bind(
                        InetSocketAddress("127.0.0.1", 0),
                        QuicEndpointConfig
                            .Builder()
                            .apply { this.server = QuicServerConfig.Builder(H3Fixtures.server()).build() }
                            .build(),
                    )
                val client = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
                try {
                    val accepted = async { server.accept() }
                    val conn = client.connect(server.localAddress, H3Fixtures.client())
                    val serverSide = accepted.await()
                    server.close()
                    // the code on the wire (Http3Exception normalizes an unknown code such as 0 to H3_NO_ERROR)
                    val e = conn.quic.closed.await() as io.kuicksilver.quic.QuicException.ConnectionLost.ApplicationClosed
                    assertEquals(Http3ErrorCode.NO_ERROR, e.code, "$e")
                    assertEquals(io.kuicksilver.quic.Initiator.Peer, e.initiator)
                    serverSide.closed.await()
                    // and the client side: closing the client endpoint closes with H3_NO_ERROR too
                    val server2 =
                        Http3Endpoint.bind(
                            InetSocketAddress("127.0.0.1", 0),
                            QuicEndpointConfig
                                .Builder()
                                .apply { this.server = QuicServerConfig.Builder(H3Fixtures.server()).build() }
                                .build(),
                        )
                    try {
                        val accepted2 = async { server2.accept() }
                        client.connect(server2.localAddress, H3Fixtures.client())
                        val s2 = accepted2.await()
                        client.close()
                        val e2 = s2.quic.closed.await() as io.kuicksilver.quic.QuicException.ConnectionLost.ApplicationClosed
                        assertEquals(Http3ErrorCode.NO_ERROR, e2.code, "$e2")
                    } finally {
                        server2.close()
                    }
                } finally {
                    client.close()
                    server.close()
                }
            }
        }

    @Test fun alpnWithoutH3Rejected() =
        runBlocking {
            assertFailsWith<IllegalArgumentException> {
                Http3Endpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig.Builder(H3Fixtures.server(alpn = "hq-interop")).build()
                        }.build(),
                )
            }
            Unit
        }
}
