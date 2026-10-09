// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.telemetry

import io.kuicksilver.quic.PathEvent
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.incomingConnections
import io.kuicksilver.quic.incomingStreams
import io.kuicksilver.quic.isUnidirectional
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** What the server has seen so far, over all connections. */
data class ServerReport(
    val clients: List<String> = emptyList(),
    val latestReadings: Map<String, Double> = emptyMap(),
    val readings: Long = 0,
    val mediaBytes: Long = 0,
    val pathChanges: Int = 0,
)

/** Serves the telemetry protocol on [endpoint] (which must have a server config) until the endpoint closes. */
class TelemetryServer(private val endpoint: QuicEndpoint) {
    private val state = MutableStateFlow(ServerReport())
    val report: StateFlow<ServerReport> get() = state

    /** Returns once the endpoint is closed and every connection is done. */
    suspend fun run(): Unit = supervisorScope {
        endpoint.incomingConnections().collect { connection -> launch { serve(connection) } }
    }

    /** One connection; whatever happens to it (a vanished client, a reset stream) stays inside this connection. */
    private suspend fun serve(connection: QuicConnection) = supervisorScope {
        val readings = launch {
            try {
                connection.datagrams.collect { d -> Protocol.decodeReading(d.data)?.let { (k, v) -> state.update { it.copy(latestReadings = it.latestReadings + (k to v), readings = it.readings + 1) } } }
            } catch (e: QuicException.ConnectionLost) { /* the flow ends with the connection, a normal close included */ }
        }
        val paths = launch { connection.pathEvents.collect { e -> if (e is PathEvent.Changed) state.update { it.copy(pathChanges = it.pathChanges + 1) } } }
        connection.incomingStreams().collect { stream ->
            launch {
                try { if (stream.isUnidirectional) media(stream) else control(stream, connection) }
                catch (e: CancellationException) { throw e }
                catch (e: Exception) { /* the peer reset the stream or left: QuicException, or ktor-io's ClosedWriteChannelException on a late write */ }
            }
        }
        readings.cancel(); paths.cancel()
    }

    private suspend fun control(stream: QuicStream, connection: QuicConnection) {
        while (true) {
            val line = stream.input.readLine() ?: break
            when {
                line.startsWith("HELLO ") -> {
                    val name = line.removePrefix("HELLO ").trim()
                    state.update { it.copy(clients = it.clients + name) }
                    stream.output.writeStringUtf8("WELCOME $name\n"); stream.output.flush()
                }
                line == "BYE" -> { stream.output.writeStringUtf8("BYE\n"); stream.output.flushAndClose(); return }
                else -> { connection.close(code = 1, reason = "unknown command"); return }
            }
        }
    }

    private suspend fun media(stream: QuicStream) {
        val buf = ByteArray(16 * 1024)
        while (true) {
            val n = stream.input.readAvailable(buf, 0, buf.size)
            if (n <= 0) break
            state.update { it.copy(mediaBytes = it.mediaBytes + n) }
        }
    }
}
