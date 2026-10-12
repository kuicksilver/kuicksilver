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
                                                Http3Request("GET", authority = "server.test", path = "/$i"),
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
