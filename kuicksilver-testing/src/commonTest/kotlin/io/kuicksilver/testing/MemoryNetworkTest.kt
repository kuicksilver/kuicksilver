// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.PathChangeReason
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.quicClientConfig
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.quicEndpointConfig
import io.kuicksilver.quic.quicServerConfig
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** MemoryNetwork carries real QUIC connections (OpenSSL TLS) between endpoints without sockets, on every platform. */
class MemoryNetworkTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val serverAddr = InetSocketAddress("10.0.0.2", 443)
    private val clientAddr = InetSocketAddress("10.0.0.1", 50000)
    private val clientTls =
        tlsConfig(TlsRole.Client) {
            alpn = listOf("sample")
            serverName = "server.test"
            trust =
                TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa)))
        }
    private val serverTls =
        tlsConfig(TlsRole.Server) {
            alpn = listOf("sample")
            identity =
                TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
        }

    private suspend fun endpoints(net: MemoryNetwork): Pair<QuicEndpoint, QuicEndpoint> {
        val server =
            QuicEndpoint.bind(
                serverAddr,
                quicEndpointConfig {
                    this.server = quicServerConfig(serverTls)
                    io = { net.open(it) }
                },
            )
        val client = QuicEndpoint.bind(clientAddr, quicEndpointConfig { io = { net.open(it) } })
        return server to client
    }

    private suspend fun echo(
        c: QuicConnection,
        s: QuicConnection,
        size: Int,
    ) = coroutineScope {
        launch {
            val st = s.acceptStream()
            val buf = ByteArray(8192)
            while (true) {
                val n = st.input.readAvailable(buf, 0, buf.size)
                if (n <=
                    0
                ) {
                    break
                }
                st.output.writeFully(buf, 0, n)
                st.output.flush()
            }
            st.output.flushAndClose()
        }
        val data = ByteArray(size) { (it * 31).toByte() }
        val st = c.openBidi()
        launch {
            st.output.writeFully(data, 0, size)
            st.output.flushAndClose()
        }
        val got = ByteArray(size)
        var off = 0
        while (off < size) {
            val n = st.input.readAvailable(got, off, size - off)
            if (n <= 0) break
            off += n
        }
        assertContentEquals(data, got)
    }

    @Test fun echoOverMemoryNetworkWithRealTls() =
        runBlocking {
            val net = MemoryNetwork()
            val (server, client) = endpoints(net)
            try {
                withTimeout(30.seconds) {
                    val c = client.connect(serverAddr, quicClientConfig(clientTls))
                    val s = server.accept()
                    echo(c, s, 64 * 1024)
                    c.close()
                    s.close()
                }
            } finally {
                client.close()
                server.close()
            }
        }

    @Test fun migrationOverMemoryNetworkWithRealTls() =
        runBlocking {
            val net = MemoryNetwork()
            val (server, client) = endpoints(net)
            try {
                withTimeout(30.seconds) {
                    val c = client.connect(serverAddr, quicClientConfig(clientTls))
                    val s = server.accept()
                    echo(c, s, 16 * 1024)
                    val newAddr = InetSocketAddress("10.0.0.3", 3333)
                    val change = c.migrate(net.open(newAddr))
                    assertEquals(PathChangeReason.ActiveMigration, change.reason)
                    assertEquals(newAddr, change.new.localAddress)
                    echo(c, s, 64 * 1024)
                    c.close()
                    s.close()
                }
            } finally {
                client.close()
                server.close()
            }
        }

    @Test fun cutAddressDropsTraffic() =
        runBlocking {
            val net = MemoryNetwork()
            val (server, client) = endpoints(net)
            try {
                withTimeout(30.seconds) {
                    net.cut(serverAddr)
                    val config = quicClientConfig(clientTls) { quic = quicConfig { handshakeTimeout = 1.seconds } }
                    val e = assertFailsWith<QuicException.ConnectionLost> { client.connect(serverAddr, config) }
                    assertTrue(e is QuicException.ConnectionLost.Timeout, "got $e")
                    assertTrue(net.dropped > 0)
                    net.restore(serverAddr)
                    val c = client.connect(serverAddr, quicClientConfig(clientTls))
                    val s = server.accept()
                    echo(c, s, 1024)
                    c.close()
                    s.close()
                }
            } finally {
                client.close()
                server.close()
            }
        }

    /** The block `guide:quic:memory-network` of docs/guide/quic.md. */
    @Test fun guideSample() =
        runBlocking {
            withTimeout(30.seconds) {
                val serverConfig = quicServerConfig(serverTls)
                val tlsClientConfig = clientTls
                // guide:quic:memory-network
                val network = MemoryNetwork()
                val wifi = InetSocketAddress("10.0.0.1", 50000)
                val server =
                    QuicEndpoint.bind(
                        InetSocketAddress("10.0.0.2", 443),
                        quicEndpointConfig {
                            this.server = serverConfig
                            io =
                                { network.open(it) }
                        },
                    )
                val client = QuicEndpoint.bind(wifi, quicEndpointConfig { io = { network.open(it) } })
                val connection = client.connect(server.localAddress, quicClientConfig(tlsClientConfig))
                val accepted = server.accept()
                echo(connection, accepted, 1024) // ... the application talks
                network.cut(wifi) // the Wi-Fi goes dark
                connection.migrate(network.open(InetSocketAddress("10.0.0.3", 50000))) // and the client moves to LTE
                echo(connection, accepted, 1024)
                connection.close()
                client.close()
                server.close()
            }
        }

    @Test fun openTwiceOnSameAddressFails() {
        val net = MemoryNetwork()
        val io = net.open(clientAddr)
        assertFailsWith<IllegalStateException> { net.open(clientAddr) }
        io.close()
        net.open(clientAddr).close() // the address is free again
    }
}
