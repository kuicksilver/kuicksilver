// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.IoPreference
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.testing.MemoryNetwork
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyResult
import io.kuicksilver.tls.tlsConfig
import io.ktor.network.sockets.InetSocketAddress
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

/**
 * Whole QUIC connections through two [QuicEndpoint]s (the server and the client runtime: endpoint loops, coroutines,
 * timers) over a [MemoryNetwork], with ksl crypto: [connection] connects, waits until the server accepted, and closes. The
 * server's side of each connection ends on its own (draining), overlapping the next ones, as on a busy server.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
public class EndpointHandshakes private constructor(
    private val identity: TlsIdentity.InMemory,
    internal val server: QuicEndpoint,
    internal val client: QuicEndpoint,
) : AutoCloseable {
    internal val clientConfig = QuicClientConfig.Builder(tlsConfig(TlsRole.Client) { alpn = listOf("bench"); serverName = "server.test"; trust = TrustConfig.Custom { chain, _, _ -> VerifyResult.Accepted(chain) } }).build()

    /** One connection: handshake, the server's accept, the client's close. */
    public suspend fun connection() {
        coroutineScope {
            val accepted = async { server.accept() }
            val c = client.connect(server.localAddress, clientConfig)
            accepted.await()
            c.close()
        }
    }

    override fun close() { client.close(); server.close(); identity.close() }

    public companion object {
        /** Two endpoints over a [MemoryNetwork]. */
        public suspend fun open(): EndpointHandshakes {
            val net = MemoryNetwork(receiveBuffer = 4096)
            val identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
            val serverTls = tlsConfig(TlsRole.Server) { alpn = listOf("bench"); this.identity = identity }
            val serverIo = net.open(InetSocketAddress("10.0.0.2", 443))
            val clientIo = net.open(InetSocketAddress("10.0.0.1", 40000))
            val server = QuicEndpoint.bind(serverIo.localAddress, QuicEndpointConfig.Builder().apply { this.server = QuicServerConfig.Builder(serverTls).build(); io = { serverIo } }.build())
            val client = QuicEndpoint.bind(clientIo.localAddress, QuicEndpointConfig.Builder().apply { io = { clientIo } }.build())
            return EndpointHandshakes(identity, server, client)
        }

        /** Two endpoints on loopback UDP through the platform's socket ([DatagramIo.open]: the accelerated `ksl` one where it exists). */
        public suspend fun openUdp(prefer: IoPreference = IoPreference.Accelerated): EndpointHandshakes {
            val identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
            val serverTls = tlsConfig(TlsRole.Server) { alpn = listOf("bench"); this.identity = identity }
            val lo = InetSocketAddress("127.0.0.1", 0)
            val server = QuicEndpoint.bind(lo, QuicEndpointConfig.Builder().apply { this.server = QuicServerConfig.Builder(serverTls).build(); io = { DatagramIo.open(it, prefer) } }.build())
            val client = QuicEndpoint.bind(lo, QuicEndpointConfig.Builder().apply { io = { DatagramIo.open(it, prefer) } }.build())
            return EndpointHandshakes(identity, server, client)
        }
    }
}
