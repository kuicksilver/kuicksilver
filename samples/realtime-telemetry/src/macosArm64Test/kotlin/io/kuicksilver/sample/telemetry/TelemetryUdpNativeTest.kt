// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.telemetry

import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.IoPreference
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.quicEndpointConfig
import io.kuicksilver.quic.quicServerConfig
import io.ktor.network.sockets.InetSocketAddress
import kotlinx.coroutines.runBlocking
import kotlin.test.Test

/**
 * The whole session over real UDP on macOS. Kuicksilver v1 has no QUIC server on Apple platforms (bind with a server
 * throws UnsupportedOperationException); this test opts the server into the portable client socket explicitly, which is
 * fine for a loopback test and not meant for production.
 */
class TelemetryUdpNativeTest {
    @Test fun fullSessionOverUdp() = runBlocking {
        val server = QuicEndpoint.bind(InetSocketAddress("127.0.0.1", 0), quicEndpointConfig {
            this.server = quicServerConfig(TelemetryTls.server())
            io = { DatagramIo.open(it, IoPreference.Portable) }
        })
        val client = QuicEndpoint.bind(InetSocketAddress("127.0.0.1", 0))
        playSession(server, client, server.localAddress) { DatagramIo.open(InetSocketAddress("127.0.0.1", 0)) }
    }
}
