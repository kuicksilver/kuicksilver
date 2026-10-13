// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.seconds

/** ALPN agreement for HTTP/3 (RFC 9114 section 3.1, RFC 9001 section 8.1, review T2). */
class Http3EndpointAlpnTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A client that offers another protocol too never speaks HTTP/3 to a server that chose that one. */
    @Test fun negative_clientRefusesServerThatChoseAnotherProtocol(): Unit =
        runBlocking {
            val net = MemoryNet()
            val a = net.open(InetSocketAddress("10.0.0.1", 1111))
            val b = net.open(InetSocketAddress("10.0.0.2", 443))
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default + CoroutineExceptionHandler { _, _ -> })
            val serverTls =
                tlsConfig(TlsRole.Server) {
                    alpn = listOf("h3-29")
                    identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
                }
            val server =
                QuicEndpoint.bind(
                    b.localAddress,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server = QuicServerConfig.Builder(serverTls).build()
                            crypto = KslQuicCrypto
                            io = { b }
                        }.build(),
                )
            val client =
                Http3Endpoint.bind(
                    a.localAddress,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            crypto = KslQuicCrypto
                            io = { a }
                        }.build(),
                )
            try {
                scope.launch { while (true) server.accept() }
                val tls =
                    tlsConfig(TlsRole.Client) {
                        alpn = listOf("h3", "h3-29")
                        serverName = "server.test"
                        trust = TrustConfig.AnchoredCa(listOf(H3Fixtures.testCa))
                    }
                val e =
                    assertFailsWith<Http3Exception.Protocol> {
                        withTimeout(10.seconds) { client.connect(server.localAddress, tls) }
                    }
                assertEquals(Http3ErrorCode.GENERAL_PROTOCOL_ERROR, e.h3Code)
            } finally {
                scope.cancel()
                client.close()
                server.close()
            }
        }
}
