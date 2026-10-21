// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/** `Http3Endpoint.accept` serves every client even when one of them never lets HTTP/3 start (review h-http H1). */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class Http3EndpointAcceptTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * A client that allows only two unidirectional streams (RFC 9114 section 6.2 requires three) and is still connected
     * held `accept()` forever, so no later client was served. Now its connection is handed over at once (and closes with
     * H3_GENERAL_PROTOCOL_ERROR later), and the next client is accepted and answered.
     */
    @Test fun negative_acceptIsNotHeldByAClientWithoutUniStreamCredit(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val net = MemoryNet()
                val serverIo = net.open(InetSocketAddress("10.0.0.2", 443))
                val stuckIo = net.open(InetSocketAddress("10.0.0.1", 1111))
                val goodIo = net.open(InetSocketAddress("10.0.0.3", 2222))
                val server =
                    Http3Endpoint.bind(
                        serverIo.localAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                this.server = QuicServerConfig.Builder(H3Fixtures.server()).build()
                                crypto = NullCryptoProvider
                                io = { serverIo }
                            }.build(),
                    )
                val stuck =
                    QuicEndpoint.bind(
                        stuckIo.localAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                crypto = NullCryptoProvider
                                io = { stuckIo }
                            }.build(),
                    )
                val good =
                    Http3Endpoint.bind(
                        goodIo.localAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                crypto = NullCryptoProvider
                                io = { goodIo }
                            }.build(),
                    )
                try {
                    stuck.connect(
                        server.localAddress,
                        QuicClientConfig.Builder(H3Fixtures.client()).apply { quic = quicConfig { maxUniStreams = 2 } }.build(),
                    )
                    withTimeout(10.seconds) { server.accept() } // the stuck client's connection
                    coroutineScope {
                        val accepted = async { server.accept() }
                        val client = good.connect(server.localAddress, H3Fixtures.client())
                        val conn = withTimeout(10.seconds) { accepted.await() }
                        launch { conn.acceptRequest().respond(204).finish() }
                        assertEquals(204, client.request(http3Request("GET", "server.test", "/")).status)
                        client.close()
                    }
                } finally {
                    good.close()
                    stuck.close()
                    server.close()
                }
            }
        }
}
