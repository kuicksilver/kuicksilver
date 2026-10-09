// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.qlog

import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.ConnectionStats
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.recovery.SentFrames
import io.kuicksilver.quic.recovery.SpaceId
import io.kuicksilver.tls.TlsRole

/**
 * qlog JSON-SEQ writer (docs/guide/quic.md, "qlog"): schema `0.3` with the event names qvis opens; one record per line prefixed
 * by RS (0x1e). Writing stops silently once [maxBytes] were produced; the connection is never affected.
 *
 * The trace is opened lazily, at the first event: a server connection created for an Initial that does not decrypt emits
 * none, so a forged Initial costs no file. A sink whose `open` or `write` throws (EMFILE, ENOSPC) disables tracing for
 * this connection only; [close] runs when the connection releases its resources. Records are written
 * on the loop thread: a [QlogSink] should buffer (DirectoryQlogSink does).
 */
internal class QlogWriter(
    private val sink: QlogSink,
    private val maxBytes: Long,
    private val start: TimeMark,
    private val role: TlsRole,
    private val odcidHex: String,
) {
    private var written = 0L
    private var closed = false
    private var trace: QlogTrace? = null
    private val sb = StringBuilder(256)

    private fun emit(json: String) {
        if (closed) return
        val t = trace ?: open() ?: return
        val record = "\u001e$json\n"
        written += record.length
        try {
            t.write(record)
        } catch (e: Exception) {
            close()
            return
        }
        if (written >= maxBytes) close()
    }

    private fun open(): QlogTrace? {
        val t =
            try {
                sink.open(odcidHex, role)
            } catch (e: Exception) {
                null
            }
        if (t == null) {
            closed = true
            return null
        }
        trace = t
        val header =
            "\u001e{\"qlog_format\":\"JSON-SEQ\",\"qlog_version\":\"0.3\",\"title\":\"kuicksilver\"," +
                "\"trace\":{\"vantage_point\":{\"type\":\"${role.name.lowercase()}\"}," +
                "\"common_fields\":{\"ODCID\":\"$odcidHex\",\"time_format\":\"relative\"}}}\n"
        written += header.length
        try {
            t.write(header)
        } catch (e: Exception) {
            close()
            return null
        }
        return t
    }

    private fun time(now: TimeMark): String {
        val us = (now - start).inWholeMicroseconds
        return "${us / 1000}.${(us % 1000).toString().padStart(3, '0')}"
    }

    private fun event(
        now: TimeMark,
        name: String,
        data: String,
    ) = emit("{\"time\":${time(now)},\"name\":\"$name\",\"data\":{$data}}")

    private fun packetType(space: SpaceId) =
        when (space) {
            SpaceId.Initial -> "initial"
            SpaceId.Handshake -> "handshake"
            SpaceId.Application -> "1RTT"
        }

    fun packetSent(
        space: SpaceId,
        pn: Long,
        size: Int,
        frames: SentFrames?,
        now: TimeMark,
    ) = event(
        now,
        "transport:packet_sent",
        "\"header\":{\"packet_type\":\"${packetType(
            space,
        )}\",\"packet_number\":$pn},\"raw\":{\"length\":$size},\"frames\":[${frameSummary(frames)}]",
    )

    fun packetReceived(
        space: SpaceId,
        pn: Long,
        size: Int,
        now: TimeMark,
    ) = event(
        now,
        "transport:packet_received",
        "\"header\":{\"packet_type\":\"${packetType(space)}\",\"packet_number\":$pn},\"raw\":{\"length\":$size}",
    )

    fun packetLost(
        space: SpaceId,
        pn: Long,
        trigger: String,
        now: TimeMark,
    ) = event(
        now,
        "recovery:packet_lost",
        "\"header\":{\"packet_type\":\"${packetType(space)}\",\"packet_number\":$pn},\"trigger\":\"$trigger\"",
    )

    fun metricsUpdated(
        stats: ConnectionStats,
        now: TimeMark,
    ) = event(
        now,
        "recovery:metrics_updated",
        "\"min_rtt\":${stats.minRtt.inWholeMicroseconds / 1000.0},\"smoothed_rtt\":${stats.smoothedRtt.inWholeMicroseconds / 1000.0},\"rtt_variance\":${stats.rttVar.inWholeMicroseconds / 1000.0},\"congestion_window\":${stats.cwnd},\"bytes_in_flight\":${stats.bytesInFlight},\"pto_count\":${stats.ptoCount}",
    )

    fun connectionStateUpdated(
        state: ConnectionState,
        now: TimeMark,
    ) = event(now, "connectivity:connection_state_updated", "\"new\":\"${state.name.lowercase()}\"")

    fun connectionClosed(
        reason: QuicException.ConnectionLost,
        now: TimeMark,
    ) {
        val d =
            when (reason) {
                is QuicException.ConnectionLost.TransportClosed -> {
                    "\"owner\":\"${reason.initiator.name.lowercase()}\",\"connection_code\":${reason.code}," +
                        "\"reason\":\"${escape(
                            reason.reason,
                        )}\""
                }

                is QuicException.ConnectionLost.ApplicationClosed -> {
                    "\"owner\":\"${reason.initiator.name.lowercase()}\",\"application_code\":${reason.code}," +
                        "\"reason\":\"${escape(
                            reason.reason,
                        )}\""
                }

                is QuicException.ConnectionLost.Timeout -> {
                    "\"owner\":\"local\",\"trigger\":\"${reason.kind.name.lowercase()}_timeout\""
                }

                else -> {
                    "\"owner\":\"local\",\"trigger\":\"${escape(reason.message ?: "")}\""
                }
            }
        event(now, "connectivity:connection_closed", d)
        close()
    }

    /** Ends the trace (idempotent); a sink whose close throws is ignored. */
    fun close() {
        closed = true
        val t = trace ?: return
        trace = null
        try {
            t.close()
        } catch (e: Exception) {
        }
    }

    private fun frameSummary(f: SentFrames?): String {
        if (f == null) return ""
        sb.setLength(0)

        fun add(type: String) {
            if (sb.isNotEmpty()) sb.append(',')
            sb.append("{\"frame_type\":\"").append(type).append("\"}")
        }
        if (f.ackLargest >= 0) add("ack")
        for (i in 0 until f.cryptoCount) add("crypto")
        for (i in 0 until f.streamCount) add("stream")
        if (f.flags and SentFrames.PING !=
            0
        ) {
            add("ping")
        }
        if (f.flags and SentFrames.HANDSHAKE_DONE !=
            0
        ) {
            add("handshake_done")
        }
        if (f.flags and SentFrames.MAX_DATA != 0) add("max_data")
        if (f.flags and SentFrames.MAX_STREAMS_BIDI != 0 ||
            f.flags and SentFrames.MAX_STREAMS_UNI != 0
        ) {
            add("max_streams")
        }
        if (f.flags and SentFrames.DATA_BLOCKED !=
            0
        ) {
            add("data_blocked")
        }
        if (f.flags and SentFrames.PATH_RESPONSE != 0) add("path_response")
        for (i in 0 until f.idCount) {
            add(
                when (f.idKind[i]) {
                    SentFrames.ID_MAX_STREAM_DATA -> "max_stream_data"
                    SentFrames.ID_RESET_STREAM -> "reset_stream"
                    SentFrames.ID_STOP_SENDING -> "stop_sending"
                    SentFrames.ID_NEW_CONNECTION_ID -> "new_connection_id"
                    SentFrames.ID_RETIRE_CONNECTION_ID -> "retire_connection_id"
                    else -> "stream_data_blocked"
                },
            )
        }
        return sb.toString()
    }

    private fun escape(s: String): String {
        val o = StringBuilder(s.length + 8)
        for (ch in s) {
            when (ch) {
                '"' -> {
                    o.append("\\\"")
                }

                '\\' -> {
                    o.append("\\\\")
                }

                '\n' -> {
                    o.append("\\n")
                }

                '\r' -> {
                    o.append("\\r")
                }

                '\t' -> {
                    o.append("\\t")
                }

                else -> {
                    if (ch <
                        ' '
                    ) {
                        o.append("\\u").append(ch.code.toString(16).padStart(4, '0'))
                    } else {
                        o.append(ch)
                    }
                }
            }
        }
        return o.toString()
    }
}
