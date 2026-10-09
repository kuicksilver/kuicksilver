// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.telemetry

import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.quicEndpointConfig
import io.kuicksilver.quic.quicServerConfig
import io.ktor.network.sockets.InetSocketAddress
import kotlinx.coroutines.runBlocking
import kotlin.test.Test

/** The whole session over real UDP on loopback, with the client switching to a second socket mid-session. */
class TelemetryUdpTest {
    @Test fun fullSessionOverUdp() = runBlocking {
        val server = QuicEndpoint.bind(InetSocketAddress("127.0.0.1", 0), quicEndpointConfig { this.server = quicServerConfig(TelemetryTls.server()) })
        val client = QuicEndpoint.bind(InetSocketAddress("127.0.0.1", 0))
        playSession(server, client, server.localAddress) { DatagramIo.open(InetSocketAddress("127.0.0.1", 0)) }
    }
}
