// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.qlog

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.core.failInternal
import io.kuicksilver.quic.endpoint.EndpointPair
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.TlsRole
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

/** A traced connection's life in its trace: its states, its one close, the frames it still processes, and the trace's end. */
@OptIn(ExperimentalKuicksilverApi::class)
class QlogLifecycleTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Every trace in memory, with whether it was closed. */
    internal class Traces : QlogSink {
        class Trace(
            val role: TlsRole,
        ) {
            val records = ArrayList<String>()
            var closed = 0
        }

        val all = ArrayList<Trace>()

        fun of(role: TlsRole) = all.single { it.role == role }

        override fun open(
            odcidHex: String,
            role: TlsRole,
        ): QlogTrace {
            val t = Trace(role)
            all += t
            return object : QlogTrace {
                override fun write(record: String) {
                    t.records += record
                }

                override fun close() {
                    t.closed++
                }
            }
        }
    }

    private fun events(t: Traces.Trace): List<Map<*, *>> =
        t.records.drop(1).map { StrictJson.parse(it.trim('\u001e', '\n')) as Map<*, *> }.onEach {
            QuicQlogSchema.event(it["name"] as String, it["data"] as Map<*, *>)
        }

    private fun states(t: Traces.Trace) =
        events(t).filter { it["name"] == "connectivity:connection_state_updated" }.map { (it["data"] as Map<*, *>)["new"] }

    /**
     * quic-events-04 sections 4.3 and 4.6: the client that closes and the server that drains each log one
     * connection_closed, every state they pass through (`old` and `new`), and keep tracing through the closing and
     * draining periods until the connection is released, which ends the trace.
     */
    @Test fun aCloseIsLoggedOnceAndEveryStateUntilTheTraceEnds() {
        val traces = Traces()
        val p = CorePair(clientQuic = quicConfig { qlog = traces }, serverQuic = quicConfig { qlog = traces })
        try {
            assertTrue(p.handshake())
            p.runUntil(limit = 500.milliseconds) { false }
            p.client.close(0, "bye", p.now)
            p.runUntil(limit = 5_000.milliseconds) { traces.all.all { it.closed > 0 } }
            for (t in traces.all) {
                assertEquals(1, t.closed, "${t.role}: the trace ended once")
                assertEquals(1, events(t).count { it["name"] == "connectivity:connection_closed" }, "${t.role}: one connection_closed")
            }
            assertEquals(listOf("handshake_complete", "handshake_confirmed", "closing", "closed"), states(traces.of(TlsRole.Client)))
            assertEquals(listOf("handshake_complete", "handshake_confirmed", "draining", "closed"), states(traces.of(TlsRole.Server)))
            val received = events(traces.of(TlsRole.Server)).filter { it["name"] == "transport:packet_received" }
            assertTrue(
                received.any { e ->
                    ((e["data"] as Map<*, *>)["frames"] as List<*>?).orEmpty().any {
                        (it as Map<*, *>)["frame_type"] ==
                            "connection_close"
                    }
                },
                "the server's trace shows the CONNECTION_CLOSE it drained on",
            )
        } finally {
            p.close()
        }
    }

    /**
     * A connection that ends a second way while it closes (an internal failure during the closing period) keeps the one
     * connection_closed of its first reason: the trace never shows two ends of one connection.
     */
    @Test fun aSecondEndWhileClosingLogsNoSecondClose() {
        val traces = Traces()
        val p = CorePair(clientQuic = quicConfig { qlog = traces })
        try {
            assertTrue(p.handshake())
            p.client.close(0, "bye", p.now)
            p.client.failInternal(IllegalStateException("late"))
            p.runUntil(limit = 2_000.milliseconds) { traces.of(TlsRole.Client).closed > 0 }
            val closes = events(traces.of(TlsRole.Client)).filter { it["name"] == "connectivity:connection_closed" }
            assertEquals(1, closes.size, "$closes")
            assertEquals("local", (closes.single()["data"] as Map<*, *>)["owner"])
        } finally {
            p.close()
        }
    }

    /**
     * A failure while formatting a received frame for the trace (none is expected) drops that packet's frames from the
     * trace and nothing else: the frame still reaches the connection, which goes on.
     */
    @Test fun negative_aFrameThatFailsToFormatLeavesTheConnectionAlone() {
        val traces = Traces()
        val p = CorePair(clientQuic = quicConfig { qlog = traces }, serverQuic = quicConfig { qlog = traces })
        try {
            assertTrue(p.handshake())
            p.client.qlog!!
                .receivedFrames.failFormattingForTest = true
            val id = p.client.openStream(true, StreamPriority.Default)
            p.client.writeStream(id, ByteArray(10), 0, 10, true)
            val buf = ByteArray(65536)
            var read = 0
            assertTrue(
                p.runUntil(limit = 5_000.milliseconds) {
                    p.server!!.readStream(id, buf, 0, buf.size).let { if (it > 0) read += it }
                    read == 10
                },
            )
            p.server!!.writeStream(id, ByteArray(30000), 0, 30000, true)
            var got = 0
            assertTrue(
                p.runUntil(limit = 5_000.milliseconds) {
                    while (true) {
                        val n = p.client.readStream(id, buf, 0, buf.size)
                        if (n > 0) got += n else break
                    }
                    got == 30000
                },
                "the client still reads what the server sent",
            )
            assertNull(p.closedReason(p.clientEvents), "the client's connection goes on")
            val late = events(traces.of(TlsRole.Client)).filter { it["name"] == "transport:packet_received" }.takeLast(3)
            assertTrue(late.all { "frames" !in (it["data"] as Map<*, *>) }, "packets whose frames failed to format are logged without them")
        } finally {
            p.close()
        }
    }

    /** Closing the endpoint releases its connections, and with them their traces. */
    @Test fun anEndpointCloseEndsTheTraces() {
        val traces = Traces()
        val p = EndpointPair(serverQuic = quicConfig { qlog = traces })
        p.use { _ ->
            val c = p.connect(quicConfig { qlog = traces })
            assertTrue(p.confirmed(c))
            assertEquals(2, traces.all.size)
            assertTrue(traces.all.none { it.closed > 0 })
            p.client.close()
            p.server.close()
            for (t in traces.all) {
                assertEquals(1, t.closed, "${t.role}: released with its endpoint")
                events(t) // what it holds still follows the draft
            }
        }
    }
}
