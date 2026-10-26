// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.incomingConnections
import io.kuicksilver.quic.incomingStreams
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.io.readByteArray

/**
 * The raw QUIC side of the simulator host-interop harness (`iosHostInteropTest`), shared by the host peer (JVM) and the
 * simulator tests: an echo server and a one-shot echo client over ALPN [ECHO_ALPN], with the test CA's server certificate,
 * whose names cover `server.test`, 127.0.0.1 and ::1.
 */
internal object HostInterop {
    const val ECHO_ALPN = "ksl-echo"

    /** The control port of the host peer, in the simulator process (`SIMCTL_CHILD_KSL_PEER_PORT` on the host). */
    const val PORT_ENV = "KSL_PEER_PORT"

    /** Binds an echo server at [local]: every stream gets back what it sent, then its end. Runs in [scope] until closed. */
    suspend fun echoServer(
        local: InetSocketAddress,
        scope: CoroutineScope,
    ): QuicEndpoint {
        val server =
            QuicEndpoint.bind(
                local,
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        this.server =
                            QuicServerConfig
                                .Builder(
                                    tlsConfig(TlsRole.Server) {
                                        alpn = listOf(ECHO_ALPN)
                                        identity = ClientFixtures.identity()
                                    },
                                ).build()
                    }.build(),
            )
        scope.launch {
            server.incomingConnections().collect { c ->
                launch {
                    c.incomingStreams().collect { st ->
                        launch {
                            val bytes = st.input.readBuffer().readByteArray()
                            st.output.writeFully(bytes, 0, bytes.size)
                            st.output.flushAndClose()
                        }
                    }
                }
            }
        }
        return server
    }

    /** Connects to the echo server at [remote] (trusting the test CA), sends [payload] on one stream and returns the echo. */
    suspend fun echo(
        remote: InetSocketAddress,
        payload: ByteArray,
    ): ByteArray {
        val local = InetSocketAddress(if (remote.hostname.contains(':')) "::" else "0.0.0.0", 0)
        val endpoint = QuicEndpoint.bind(local, QuicEndpointConfig.Builder().build())
        try {
            val c =
                endpoint.connect(
                    remote,
                    QuicClientConfig
                        .Builder(
                            tlsConfig(TlsRole.Client) {
                                alpn = listOf(ECHO_ALPN)
                                serverName = "server.test"
                                trust = ClientFixtures.trust
                            },
                        ).build(),
                )
            try {
                val st = c.openBidi()
                st.output.writeFully(payload, 0, payload.size)
                st.output.flushAndClose()
                return st.input.readBuffer().readByteArray()
            } finally {
                c.close()
            }
        } finally {
            endpoint.close()
        }
    }
}
