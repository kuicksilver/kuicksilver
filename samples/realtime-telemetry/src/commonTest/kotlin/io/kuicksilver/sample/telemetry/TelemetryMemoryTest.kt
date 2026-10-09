// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.telemetry

import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.quicClientConfig
import io.kuicksilver.quic.quicEndpointConfig
import io.kuicksilver.quic.quicServerConfig
import io.kuicksilver.testing.MemoryNetwork
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.delay
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The whole session over an in-memory network: real TLS and QUIC, no sockets, the same on JVM and macOS. */
class TelemetryMemoryTest {
    private val serverAddress = InetSocketAddress("192.0.2.10", 4433)

    @Test fun fullSessionOverMemoryNetwork() = runBlocking {
        val network = MemoryNetwork()
        val server = QuicEndpoint.bind(serverAddress, quicEndpointConfig { this.server = quicServerConfig(TelemetryTls.server()); io = { network.open(it) } })
        val wifi = InetSocketAddress("10.1.0.2", 50000)
        val client = QuicEndpoint.bind(wifi, quicEndpointConfig { io = { network.open(it) } })
        playSession(server, client, serverAddress) { network.cut(wifi); network.open(InetSocketAddress("100.64.0.9", 50000)) }
    }

    /** A client that vanishes mid-stream (no BYE, a reset media stream) must not take the server down for the others. */
    @Test fun abruptClientDoesNotStopTheServer() = runBlocking {
        val network = MemoryNetwork()
        val server = QuicEndpoint.bind(serverAddress, quicEndpointConfig { this.server = quicServerConfig(TelemetryTls.server()); io = { network.open(it) } })
        val telemetry = TelemetryServer(server)
        val serving = launch { telemetry.run() }
        val rude = QuicEndpoint.bind(InetSocketAddress("10.1.0.3", 50000), quicEndpointConfig { io = { network.open(it) } })
        withTimeout(30.seconds) {
            val connection = rude.connect(serverAddress, quicClientConfig(TelemetryTls.client()))
            TelemetryClient(connection).hello("rude")
            val media = connection.openUni(); media.output.writeFully(ByteArray(4096)); media.output.flush()
            media.reset(7)
            val control = connection.openBidi(); control.output.writeStringUtf8("HELLO again\n"); control.output.flush()
            connection.close(code = 99, reason = "gone")   // no BYE, and the server's WELCOME has nowhere to go
            delay(500.milliseconds)
        }
        rude.close()
        val polite = QuicEndpoint.bind(InetSocketAddress("10.1.0.4", 50000), quicEndpointConfig { io = { network.open(it) } })
        withTimeout(30.seconds) {
            val app = TelemetryClient(polite.connect(serverAddress, quicClientConfig(TelemetryTls.client())))
            assertEquals("WELCOME polite", app.hello("polite"))
            assertEquals("BYE", app.bye())
        }
        assertTrue(serving.isActive, "the server still runs")
        server.close(); serving.join(); polite.close()
    }
}
