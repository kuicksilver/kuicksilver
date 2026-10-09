// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.qlog

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.quic.QuicLimits
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.TlsRole
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

@OptIn(ExperimentalKuicksilverApi::class)
class QlogWriterTest {
    /** Collects every record of every trace in memory. */
    private class MemorySink : QlogSink {
        val traces = LinkedHashMap<String, ArrayList<String>>()

        override fun open(
            odcidHex: String,
            role: TlsRole,
        ): QlogTrace {
            val l = ArrayList<String>()
            traces["${odcidHex}_${role.name.lowercase()}"] =
                l
            return object : QlogTrace {
                override fun write(record: String) {
                    l += record
                }

                override fun close() {}
            }
        }
    }

    private fun pair(
        sink: MemorySink,
        limits: QuicLimits = QuicLimits(),
    ) = CorePair(
        clientQuic =
            quicConfig {
                qlog = sink
                this.limits =
                    limits
            },
        serverQuic = quicConfig { qlog = sink },
    )

    private fun records(
        sink: MemorySink,
        role: String,
    ) = sink.traces.entries
        .first { it.key.endsWith(role) }
        .value

    private fun transfer(
        p: CorePair,
        bytes: Int,
    ) {
        val id = p.client.openStream(true, StreamPriority.Default)
        var written = 0
        var read = 0
        val buf = ByteArray(16384)
        assertTrue(
            p.runUntil(limit = 20_000.milliseconds) {
                if (written <
                    bytes
                ) {
                    written +=
                        p.client.writeStream(
                            id,
                            buf,
                            0,
                            minOf(buf.size, bytes - written),
                            written + minOf(buf.size, bytes - written) == bytes,
                        )
                }
                while (true) {
                    val n = p.server!!.readStream(id, buf, 0, buf.size)
                    if (n > 0) read += n else break
                }
                read == bytes
            },
        )
    }

    @Test fun firstRecordIsHeader() {
        val sink = MemorySink()
        val p = pair(sink)
        try {
            assertTrue(p.handshake())
            val h = records(sink, "client").first()
            assertEquals(0x1e, h[0].code)
            assertTrue(
                h.contains("\"qlog_format\":\"JSON-SEQ\"") && h.contains("\"qlog_version\":\"0.3\"") &&
                    h.contains("\"vantage_point\":{\"type\":\"client\"}"),
                h,
            )
            assertTrue(records(sink, "server").first().contains("\"type\":\"server\""))
        } finally {
            p.close()
        }
    }

    @Test fun eventsUseRelativeMillis() {
        val sink = MemorySink()
        val p = pair(sink)
        try {
            assertTrue(p.handshake())
            val e = records(sink, "client").drop(1)
            assertTrue(e.all { it.startsWith("\u001e{\"time\":") }, e.firstOrNull() ?: "no events")
            val first =
                e
                    .first()
                    .substringAfter("\"time\":")
                    .substringBefore(",")
                    .toDouble()
            assertTrue(first >= 0.0 && first < 1000.0, "relative time $first")
        } finally {
            p.close()
        }
    }

    @Test fun packetSentFields() {
        val sink = MemorySink()
        val p = pair(sink)
        try {
            assertTrue(p.handshake())
            val s = records(sink, "client").first { it.contains("\"name\":\"transport:packet_sent\"") }
            assertTrue(
                s.contains("\"packet_type\":\"initial\"") && s.contains("\"packet_number\":0") && s.contains("\"raw\":{\"length\":1200}") &&
                    s.contains("\"frames\":[") &&
                    s.contains("\"frame_type\":\"crypto\""),
                s,
            )
        } finally {
            p.close()
        }
    }

    @Test fun lossAndMetricsEvents() {
        val sink = MemorySink()
        val p = pair(sink)
        p.filterToServer = { i, _ -> i != 12 }
        try {
            assertTrue(p.handshake())
            transfer(p, 300_000)
            val r = records(sink, "client")
            assertTrue(r.any { it.contains("\"name\":\"recovery:packet_lost\"") }, "packet_lost")
            val m = r.last { it.contains("\"name\":\"recovery:metrics_updated\"") }
            assertTrue(m.contains("\"smoothed_rtt\":") && m.contains("\"congestion_window\":") && m.contains("\"bytes_in_flight\":"), m)
        } finally {
            p.close()
        }
    }

    @Test fun stopsAtCapWithoutError() {
        val sink = MemorySink()
        val p = pair(sink, QuicLimits(qlogBytes = 1024))
        try {
            assertTrue(p.handshake())
            transfer(p, 200_000)
            val r = records(sink, "client")
            val total = r.sumOf { it.encodeToByteArray().size }
            assertTrue(total <= 1024 + r.last().encodeToByteArray().size, "$total")
            assertNull(p.closedReason(p.clientEvents))
        } finally {
            p.close()
        }
    }

    @Test fun filePerConnectionNamedByOdcid() {
        val sink = MemorySink()
        val p = pair(sink)
        try {
            assertTrue(p.handshake())
            val names = sink.traces.keys.toList()
            assertEquals(2, names.size)
            val odcid = p.client.odcid.toString()
            assertTrue(names.contains("${odcid}_client") && names.contains("${odcid}_server"), "$names")
        } finally {
            p.close()
        }
    }
}
