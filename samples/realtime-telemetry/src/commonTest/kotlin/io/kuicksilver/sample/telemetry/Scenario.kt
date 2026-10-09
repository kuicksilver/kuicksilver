// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.telemetry

import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.PathChangeReason
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.activePath
import io.kuicksilver.quic.quicClientConfig
import io.ktor.network.sockets.InetSocketAddress
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * The session every test plays, the way the application would: hello on the control stream, readings as datagrams
 * (latest wins per key), 256 KiB of media on a uni stream, a network switch, more readings, bye.
 */
suspend fun playSession(server: QuicEndpoint, client: QuicEndpoint, serverAddress: InetSocketAddress, secondNetwork: suspend () -> DatagramIo) = coroutineScope {
    val telemetry = TelemetryServer(server)
    val serving = launch { telemetry.run() }
    withTimeout(60.seconds) {
        val connection = client.connect(serverAddress, quicClientConfig(TelemetryTls.client()))
        val app = TelemetryClient(connection)
        assertEquals("WELCOME probe-7", app.hello("probe-7"))

        for (i in 1..100) { app.sendReading("temperature", 20.0 + i / 10.0); app.sendReading("humidity", 40.0 + i) }
        telemetry.report.first { it.latestReadings["temperature"] == 30.0 && it.latestReadings["humidity"] == 140.0 }

        app.streamMedia(256 * 1024)
        telemetry.report.first { it.mediaBytes == 256L * 1024 }

        val change = app.switchNetwork(secondNetwork())
        assertEquals(PathChangeReason.ActiveMigration, change.reason)
        assertEquals(change.new.localAddress, connection.activePath?.localAddress)
        app.sendReading("temperature", -1.5)
        telemetry.report.first { it.latestReadings["temperature"] == -1.5 && it.pathChanges >= 1 }

        assertEquals("BYE", app.bye())
        assertEquals(listOf("probe-7"), telemetry.report.value.clients)
    }
    server.close(); serving.join()   // incomingConnections() completes once the endpoint closes
    client.close()
}
