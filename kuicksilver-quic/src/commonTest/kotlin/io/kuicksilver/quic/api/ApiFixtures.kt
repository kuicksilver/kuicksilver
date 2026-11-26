// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.MemoryDatagramIo
import io.kuicksilver.quic.MemoryNetwork
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.QuicCrypto
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

/** Two endpoints over an in-memory datagram pair (all platforms). */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
internal class ApiPair private constructor(
    val server: QuicEndpoint,
    val client: QuicEndpoint,
    val net: MemoryNetwork,
    val clientIo: MemoryDatagramIo,
    val serverIo: MemoryDatagramIo,
) : AutoCloseable {
    override fun close() {
        client.close()
        server.close()
    }

    companion object {
        suspend fun open(
            serverQuic: QuicConfig = QuicConfig.Default,
            crypto: QuicCrypto = NullCryptoProvider,
            serverAnswers: Boolean = true,
            df: Boolean = false,
            serverEarlyData: Boolean = false,
            serverLogger: KuicksilverLogger? = null,
            serverTls: io.kuicksilver.tls.TlsConfig = CoreFixtures.server(),
            clientListener: io.kuicksilver.quic.ConnectionListener? = null,
            serverConfigure: QuicEndpointConfig.Builder.() -> Unit = {},
            admission: io.kuicksilver.quic.ConnectionAdmission? = null,
        ): ApiPair {
            val net = MemoryNetwork()
            val a = net.open(InetSocketAddress("10.0.0.1", 1111), df = df)
            val b = net.open(InetSocketAddress("10.0.0.2", 2222), deaf = !serverAnswers, df = df)
            val server =
                QuicEndpoint.bind(
                    b.localAddress,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig
                                    .Builder(serverTls)
                                    .apply {
                                        quic = serverQuic
                                        acceptEarlyData = serverEarlyData
                                    }.build()
                            ; runtime { this.crypto = crypto }
                            runtime { io = { b } }
                            serverLogger?.let { observability { logger = it } }
                            serverConfigure()
                            admission?.let { this.admission = it }
                        }.build(),
                )
            val client =
                QuicEndpoint.bind(
                    a.localAddress,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            runtime { this.crypto = crypto }
                            runtime { io = { a } }
                            clientListener?.let { observability { connectionListener = it } }
                        }.build(),
                )
            return ApiPair(server, client, net, a, b)
        }
    }

    /**
     * Closes [server] and binds a new server endpoint (its own ticket keys and early-data context, from [serverQuic]) at the
     * same address: a server restarted with another configuration, which refuses earlier tickets' 0-RTT. The caller closes it.
     */
    suspend fun restartServer(
        serverQuic: QuicConfig,
        crypto: QuicCrypto,
        configure: QuicEndpointConfig.Builder.() -> Unit = {},
        admission: io.kuicksilver.quic.ConnectionAdmission? = null,
    ): QuicEndpoint {
        server.closeAndJoin()
        val io = net.open(serverIo.localAddress)
        return QuicEndpoint.bind(
            io.localAddress,
            QuicEndpointConfig
                .Builder()
                .apply {
                    this.server =
                        QuicServerConfig
                            .Builder(CoreFixtures.server())
                            .apply {
                                quic = serverQuic
                                acceptEarlyData = true
                            }.build()
                    runtime { this.crypto = crypto }
                    runtime { this.io = { io } }
                    configure()
                    admission?.let { this.admission = it }
                }.build(),
        )
    }

    suspend fun connect(quic: QuicConfig = QuicConfig.Default): Pair<QuicConnection, QuicConnection> =
        coroutineScope {
            val accepted = async { server.accept() }
            val c = client.connect(server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).apply { this.quic = quic }.build())
            c to accepted.await()
        }
}

/** ktor-io reports a cancelled channel as EOF and keeps the cause in [ByteReadChannel.closedCause]: surface it. */
internal suspend fun ByteReadChannel.readExactly(n: Int): ByteArray {
    val out = ByteArray(n)
    var off = 0
    while (off <
        n
    ) {
        val r = readAvailable(out, off, n - off)
        if (r <
            0
        ) {
            throw closedCause ?: IllegalStateException("EOF after $off of $n")
        }
        off += r
    }
    return out
}

/**
 * Waits until the client [c] can move: its handshake is confirmed (RFC 9000 section 9; `connect` returns at completion, one
 * round trip earlier, and a socket lost in between ends the connection) and it holds an unused connection ID of its peer (a
 * migration before that cannot send, RFC 9000 section 9.5).
 */
internal suspend fun awaitSpareConnectionId(c: io.kuicksilver.quic.QuicConnection) {
    kotlinx.coroutines.withTimeout(10_000) {
        while (!c.core.cids.hasSparePeerForTest || c.core.state != io.kuicksilver.quic.ConnectionState.Confirmed) kotlinx.coroutines.yield()
    }
}
