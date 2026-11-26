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
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** `Http3Endpoint.accept` serves every client even when one of them never lets HTTP/3 start (0.2.1 review). */
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
                                runtime { crypto = NullCryptoProvider }
                                runtime { io = { serverIo } }
                            }.build(),
                    )
                val stuck =
                    QuicEndpoint.bind(
                        stuckIo.localAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                runtime { crypto = NullCryptoProvider }
                                runtime { io = { stuckIo } }
                            }.build(),
                    )
                val good =
                    Http3Endpoint.bind(
                        goodIo.localAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                runtime { crypto = NullCryptoProvider }
                                runtime { io = { goodIo } }
                            }.build(),
                    )
                try {
                    stuck.connect(
                        server.localAddress,
                        QuicClientConfig.Builder(H3Fixtures.client()).apply { quic = quicConfig { expert { maxUniStreams = 2 } } }.build(),
                    )
                    withTimeout(10.seconds) { server.accept() } // the stuck client's connection
                    coroutineScope {
                        val accepted = async { server.accept() }
                        val client = good.connect(server.localAddress, H3Fixtures.client())
                        val conn = withTimeout(10.seconds) { accepted.await() }
                        val served = launch { conn.acceptRequest().respond(204).finish() }
                        assertEquals(204, client.request(http3Request("GET", "server.test", "/")).status)
                        // the client has the 204 before the server's last flush returns: closing first failed that flush
                        served.join()
                        client.close()
                    }
                } finally {
                    good.close()
                    stuck.close()
                    server.close()
                }
            }
        }

    /**
     * RFC 9114 section 6.2: our transport parameters "MUST allow the peer to create at least three unidirectional streams".
     * A configuration that grants fewer is refused before anything is bound or sent, on both sides, never clamped.
     */
    @Test fun negative_fewerThanThreeUniStreamsIsRefused(): Unit =
        runBlocking {
            val net = MemoryNet()
            val serverIo = net.open(InetSocketAddress("10.0.0.2", 443))
            val two = quicConfig { expert { maxUniStreams = 2 } }
            val e =
                assertFailsWith<IllegalArgumentException> {
                    Http3Endpoint.bind(
                        serverIo.localAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                this.server = QuicServerConfig.Builder(H3Fixtures.server()).apply { quic = two }.build()
                                runtime { crypto = NullCryptoProvider }
                                runtime { io = { serverIo } }
                            }.build(),
                    )
                }
            assertTrue("RFC 9114 section 6.2" in e.message.orEmpty(), e.message)
            val clientIo = net.open(InetSocketAddress("10.0.0.1", 1111))
            val client =
                Http3Endpoint.bind(
                    clientIo.localAddress,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            runtime { crypto = NullCryptoProvider }
                            runtime { io = { clientIo } }
                        }.build(),
                )
            try {
                assertFailsWith<IllegalArgumentException> { client.connect(serverIo.localAddress, H3Fixtures.client(), two) }
                assertFailsWith<IllegalArgumentException> { client.connectEarly(serverIo.localAddress, H3Fixtures.client(), two) }
            } finally {
                client.close()
            }
        }

    private fun serverConfig(
        socket: io.kuicksilver.quic.DatagramIo,
        quic: io.kuicksilver.quic.QuicConfig,
    ) = QuicEndpointConfig
        .Builder()
        .apply {
            this.server = QuicServerConfig.Builder(H3Fixtures.server()).apply { this.quic = quic }.build()
            runtime { crypto = NullCryptoProvider }
            runtime { io = { socket } }
        }.build()

    /**
     * RFC 9114 section 6.1: "at least 100 request streams SHOULD be permitted at a time". A server that permits 99 is refused
     * at bind, naming the option and the RFC; 100 binds. A client's own limit has no floor (the server opens no request
     * streams): one that permits a single bidirectional stream connects and is served.
     */
    @Test fun negative_serverWithFewerThan100RequestStreamsIsRefused(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val net = MemoryNet()
                val refusedIo = net.open(InetSocketAddress("10.0.0.4", 443))
                val e =
                    assertFailsWith<IllegalArgumentException> {
                        Http3Endpoint.bind(refusedIo.localAddress, serverConfig(refusedIo, quicConfig { maxBidiStreams = 99 }))
                    }
                assertEquals(
                    "an HTTP/3 server needs QuicConfig maxBidiStreams >= 100 (RFC 9114 section 6.1: at least 100 request streams " +
                        "SHOULD be permitted at a time), not 99",
                    e.message,
                )
                val serverIo = net.open(InetSocketAddress("10.0.0.2", 443))
                val server = Http3Endpoint.bind(serverIo.localAddress, serverConfig(serverIo, quicConfig { maxBidiStreams = 100 }))
                val clientIo = net.open(InetSocketAddress("10.0.0.1", 1111))
                val client =
                    Http3Endpoint.bind(
                        clientIo.localAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                runtime { crypto = NullCryptoProvider }
                                runtime { io = { clientIo } }
                            }.build(),
                    )
                try {
                    coroutineScope {
                        val accepted = async { server.accept() }
                        val c = client.connect(server.localAddress, H3Fixtures.client(), quicConfig { maxBidiStreams = 1 })
                        val conn = withTimeout(10.seconds) { accepted.await() }
                        val served = launch { conn.acceptRequest().respond(204).finish() }
                        assertEquals(204, c.request(http3Request("GET", "server.test", "/")).status)
                        served.join()
                        c.close()
                    }
                } finally {
                    client.close()
                    server.close()
                }
            }
        }

    /**
     * RFC 9114 section 6.2: the transport parameters "SHOULD also provide at least 1,024 bytes of flow-control credit to each
     * unidirectional stream". 1023 bytes (the QuicConfig initialStreamWindow) is refused on both sides, at bind, connect and
     * connectEarly, before anything is sent; 1024 binds.
     */
    @Test fun negative_streamCreditBelow1024IsRefused(): Unit =
        runBlocking {
            val net = MemoryNet()
            val small = quicConfig { flowControl { initialStreamWindow = 1023 } }
            val serverIo = net.open(InetSocketAddress("10.0.0.2", 443))
            val e = assertFailsWith<IllegalArgumentException> { Http3Endpoint.bind(serverIo.localAddress, serverConfig(serverIo, small)) }
            assertEquals(
                "HTTP/3 needs QuicConfig flowControl { initialStreamWindow } >= 1024 (RFC 9114 section 6.2: at least 1,024 bytes of " +
                    "flow-control credit SHOULD go to each unidirectional stream), not 1023",
                e.message,
            )
            val okIo = net.open(InetSocketAddress("10.0.0.3", 443))
            Http3Endpoint.bind(okIo.localAddress, serverConfig(okIo, quicConfig { flowControl { initialStreamWindow = 1024 } })).close()
            val clientIo = net.open(InetSocketAddress("10.0.0.1", 1111))
            val client =
                Http3Endpoint.bind(
                    clientIo.localAddress,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            runtime { crypto = NullCryptoProvider }
                            runtime { io = { clientIo } }
                        }.build(),
                )
            try {
                val c = assertFailsWith<IllegalArgumentException> { client.connect(serverIo.localAddress, H3Fixtures.client(), small) }
                assertEquals(e.message, c.message)
                assertFailsWith<IllegalArgumentException> { client.connectEarly(serverIo.localAddress, H3Fixtures.client(), small) }
            } finally {
                client.close()
            }
        }
}
