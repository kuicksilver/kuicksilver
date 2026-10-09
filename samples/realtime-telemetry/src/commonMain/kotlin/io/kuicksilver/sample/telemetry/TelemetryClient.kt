// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.telemetry

import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.DatagramPolicy
import io.kuicksilver.quic.DatagramSendResult
import io.kuicksilver.quic.PathEvent
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.StreamPriority
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.flow.first

/** The device side of the protocol over one established [connection]. */
class TelemetryClient(private val connection: QuicConnection) {
    private var control: QuicStream? = null

    /** Opens the control stream above everything else (urgency 0) and greets; returns the server's answer. */
    suspend fun hello(name: String): String {
        val stream = connection.openBidi(StreamPriority(urgency = 0)); control = stream
        stream.output.writeStringUtf8("HELLO $name\n"); stream.output.flush()
        return stream.input.readLine() ?: error("server closed the control stream")
    }

    /**
     * Sends one reading as a datagram; a queued, not yet sent reading of the same key is replaced (latest wins), so a
     * slow network never delivers stale values. Waits until the peer's datagram limit is known.
     */
    suspend fun sendReading(key: String, value: Double): DatagramSendResult {
        connection.maxDatagramSize.first { it > 0 }
        return connection.trySendDatagram(Protocol.encodeReading(key, value), DatagramPolicy.LatestWins(key))
    }

    /** Streams [bytes] of media on its own unidirectional stream, below the control stream (urgency 5, incremental). */
    suspend fun streamMedia(bytes: Int) {
        val stream = connection.openUni(StreamPriority(urgency = 5, incremental = true))
        val chunk = ByteArray(8 * 1024) { it.toByte() }; var left = bytes
        while (left > 0) { val n = minOf(left, chunk.size); stream.output.writeFully(chunk, 0, n); left -= n }
        stream.output.flushAndClose()
    }

    /** The phone left Wi-Fi: move the connection to [io] (a socket on the new network) without a new handshake. */
    suspend fun switchNetwork(io: DatagramIo): PathEvent.Changed = connection.migrate(io)

    /** Says goodbye on the control stream, waits for the answer and closes the connection with [Protocol.CLOSE_OK]. */
    suspend fun bye(): String {
        val stream = control ?: error("hello first")
        stream.output.writeStringUtf8("BYE\n"); stream.output.flushAndClose()
        val answer = stream.input.readLine() ?: error("server closed the control stream")
        connection.close(code = Protocol.CLOSE_OK, reason = "bye")
        return answer
    }
}
