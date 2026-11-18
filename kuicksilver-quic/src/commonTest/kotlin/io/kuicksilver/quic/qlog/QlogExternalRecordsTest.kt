// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.qlog

import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Events a layer above QUIC (HTTP/3) adds to a connection's trace ([QlogWriter.enqueue]): queued from any thread, written
 * whole by the loop before its next transport event, bounded, and never written once the trace ended.
 */
class QlogExternalRecordsTest {
    private class Sink(
        val failWrite: Boolean = false,
    ) : QlogSink {
        val records = ArrayList<String>()
        var closed = 0

        override fun open(
            odcidHex: String,
            role: TlsRole,
        ): QlogTrace =
            object : QlogTrace {
                override fun write(record: String) {
                    if (failWrite && "http:" in record) throw IllegalStateException("disk full")
                    records += record
                }

                override fun close() {
                    closed++
                }
            }
    }

    private fun writer(
        sink: QlogSink,
        maxBytes: Long = 1L shl 20,
        http3: Boolean = true,
    ) = QlogWriter(sink, maxBytes, TimeMark(1_000_000_000L), TlsRole.Client, "0a0b", http3)

    /**
     * draft-ietf-quic-qlog-main-schema-05 section 3.4.4 and 3.4.7: `protocol_type` in `common_fields` names the stacks of
     * the trace; quic-events-04 section 2 requires "QUIC", h3-events-04 section 2 "HTTP3" once one of its events is in
     * the trace. Section 3.4.1: a relative trace gives its `reference_time` (here the trace's start: 0 ms).
     */
    @Test fun theHeaderNamesTheProtocolsAndTheReferenceTime() {
        val h3 = Sink()
        writer(h3).connectionStateUpdated(ConnectionState.Handshaking, TimeMark(1_000_000_000L))
        assertTrue(
            h3.records[0].contains(
                "\"common_fields\":{\"ODCID\":\"0a0b\",\"protocol_type\":[\"QUIC\",\"HTTP3\"],\"time_format\":\"relative\"," +
                    "\"reference_time\":0.0}",
            ),
            h3.records[0],
        )
        val quic = Sink()
        writer(quic, http3 = false).connectionStateUpdated(ConnectionState.Handshaking, TimeMark(1_000_000_000L))
        assertTrue(quic.records[0].contains("\"protocol_type\":[\"QUIC\"],"), quic.records[0])
    }

    /**
     * The transport events' enumerations are those of draft-ietf-quic-qlog-quic-events-04: connection states of section
     * 4.6 (Figure 7), packet_dropped triggers of section 5.7 (Figure 15), connection_closed triggers of section 4.3
     * (Figure 4); a packet_lost trigger is left out, as section 7.5 has none for "time or packet threshold".
     */
    @Test fun transportEnumerationsAreTheDrafts() {
        val sink = Sink()
        val w = writer(sink)
        val t = TimeMark(1_000_000_000L)
        for (st in ConnectionState.entries) w.connectionStateUpdated(st, t)
        w.packetDropped(io.kuicksilver.quic.recovery.SpaceId.Application, 3, 50, "rejected", "left_address", t)
        w.packetLost(io.kuicksilver.quic.recovery.SpaceId.Application, 4, t)
        w.connectionClosed(
            io.kuicksilver.quic.QuicException.ConnectionLost
                .StatelessReset(),
            t,
        )
        val states = sink.records.mapNotNull { Regex("\"new\":\"([a-z_]+)\"").find(it)?.groupValues?.get(1) }
        val drafts =
            setOf(
                "attempted",
                "peer_validated",
                "handshake_started",
                "early_write",
                "handshake_complete",
                "handshake_confirmed",
                "closing",
                "draining",
                "closed",
            )
        assertEquals(ConnectionState.entries.size, states.size)
        assertTrue(drafts.containsAll(states), "$states")
        assertTrue(sink.records.any { "\"trigger\":\"rejected\"" in it && "packet_dropped" in it })
        assertTrue(sink.records.single { "packet_lost" in it }.let { "trigger" !in it })
        assertTrue(sink.records.single { "connection_closed" in it }.contains("\"trigger\":\"stateless_reset\""))
    }

    /** A trace whose header does not name HTTP3 takes no HTTP/3 event: h3-events-04 section 2 would be broken. */
    @Test fun negative_aTraceWithoutHttp3TakesNoHttp3Event() {
        val sink = Sink()
        val w = writer(sink, http3 = false)
        assertFalse(w.takesHttp3Events)
        assertFalse(w.enqueue("http:frame_created", "\"stream_id\":0", TimeMark(1_000_000_000L)))
        w.drainExternal()
        assertTrue(sink.records.none { "http:" in it })
    }

    /**
     * main-schema-05 section 3.4.1: "Events in each individual trace SHOULD be logged in strictly ascending timestamp
     * order". An event of the layer above stamped on its own thread after a transport event the loop writes later gets
     * no earlier time than that one: times never go back in the file.
     */
    @Test fun timesNeverGoBackInTheFile() {
        val sink = Sink()
        val w = writer(sink)
        assertTrue(w.enqueue("http:frame_created", "\"stream_id\":0", TimeMark(1_005_000_000L)))
        w.connectionStateUpdated(ConnectionState.Established, TimeMark(1_003_000_000L)) // the loop's older clock reading
        w.connectionStateUpdated(ConnectionState.Established, TimeMark(1_007_000_000L))
        val times = sink.records.drop(1).map { it.substringAfter("\"time\":").substringBefore(",").toDouble() }
        assertEquals(listOf(5.0, 5.0, 7.0), times)
    }

    @Test fun queuedEventsPrecedeTheNextTransportEvent() {
        val sink = Sink()
        val w = writer(sink)
        w.connectionStateUpdated(ConnectionState.Handshaking, TimeMark(1_000_000_000L))
        assertTrue(w.enqueue("http:frame_created", "\"stream_id\":0", TimeMark(1_002_500_000L)))
        assertEquals(2, sink.records.size, "queued, not written by the caller")
        w.connectionStateUpdated(ConnectionState.Established, TimeMark(1_003_000_000L))
        assertEquals(4, sink.records.size)
        assertEquals("\u001e{\"time\":2.500,\"name\":\"http:frame_created\",\"data\":{\"stream_id\":0}}\n", sink.records[2])
        assertTrue("connection_state_updated" in sink.records[3], sink.records[3])
    }

    @Test fun drainWritesWhatWasQueued() {
        val sink = Sink()
        val w = writer(sink)
        w.enqueue("http:parameters_set", "\"owner\":\"local\"", TimeMark(1_000_000_000L))
        w.drainExternal()
        assertEquals(2, sink.records.size, "the header, then the event")
        assertTrue(sink.records[0].contains("\"qlog_version\":\"0.3\""))
        assertTrue(sink.records[1].contains("\"name\":\"http:parameters_set\""))
    }

    /** Many threads at once: every record arrives whole, as one line, none lost, none interleaved with another. */
    @Test fun recordsFromManyThreadsNeverInterleave() {
        val sink = Sink()
        val w = writer(sink)
        val threads = 8
        val each = 500
        runBlocking {
            (0 until threads)
                .map { t ->
                    async(Dispatchers.Default) {
                        repeat(each) { i ->
                            val pad = "x".repeat(i % 64)
                            check(w.enqueue("http:frame_parsed", "\"stream_id\":$t,\"n\":$i,\"pad\":\"$pad\"", TimeMark(1_000_000_000L)))
                        }
                    }
                }.awaitAll()
        }
        w.drainExternal()
        val events = sink.records.drop(1)
        assertEquals(threads * each, events.size)
        val seen = HashSet<Pair<Int, Int>>()
        val re =
            Regex(
                "^\u001e\\{\"time\":0\\.000,\"name\":\"http:frame_parsed\",\"data\":\\{\"stream_id\":(\\d+),\"n\":(\\d+),\"pad\":\"x*\"}}\n$",
            )
        for (r in events) {
            val m = re.matchEntire(r) ?: error("corrupt record: $r")
            seen += m.groupValues[1].toInt() to m.groupValues[2].toInt()
        }
        assertEquals(threads * each, seen.size, "every record once")
        // per producer, in the order it recorded them
        for (t in 0 until threads) {
            val order = events.filter { "\"stream_id\":$t," in it }.map { it.substringAfter("\"n\":").substringBefore(",").toInt() }
            assertEquals((0 until each).toList(), order)
        }
    }

    @Test fun negative_queueIsBounded() {
        val sink = Sink()
        val w = writer(sink)
        var accepted = 0
        repeat(QlogWriter.MAX_QUEUED + 100) { if (w.enqueue("http:frame_created", "\"i\":$it", TimeMark(1_000_000_000L))) accepted++ }
        assertEquals(QlogWriter.MAX_QUEUED, accepted, "events beyond the queue are dropped, not waited for")
        assertEquals(100L, w.externalDropped)
        w.drainExternal()
        assertTrue(w.enqueue("http:frame_created", "\"after\":1", TimeMark(1_000_000_000L)), "room again once drained")
    }

    @Test fun nothingIsTakenOnceTheTraceEnded() {
        val sink = Sink()
        val w = writer(sink)
        w.enqueue("http:frame_created", "\"before\":1", TimeMark(1_000_000_000L))
        assertTrue(w.enabled)
        w.close()
        assertFalse(w.enabled)
        assertFalse(w.enqueue("http:frame_created", "\"after\":1", TimeMark(1_000_000_000L)))
        assertTrue(sink.records.any { "\"before\":1" in it }, "queued before the end: written at the end")
        assertTrue(sink.records.none { "\"after\":1" in it })
        assertEquals(1, sink.closed)
    }

    @Test fun theSizeCapEndsQueuedEventsToo() {
        val sink = Sink()
        val w = writer(sink, maxBytes = 400)
        repeat(20) { w.enqueue("http:frame_created", "\"pad\":\"${"y".repeat(40)}\"", TimeMark(1_000_000_000L)) }
        w.drainExternal()
        assertFalse(w.enabled, "past the cap the trace is over")
        val total = sink.records.sumOf { it.length }
        assertTrue(total < 400 + 120, "$total")
        assertFalse(w.enqueue("http:frame_created", "\"x\":1", TimeMark(1_000_000_000L)))
    }

    /** A sink that throws on an event of the layer above stops the trace, never the caller. */
    @Test fun negative_aThrowingSinkStopsTracingNotTheCaller() {
        val sink = Sink(failWrite = true)
        val w = writer(sink)
        var failure: Throwable? = null
        w.onFailure = { failure = it }
        w.enqueue("http:frame_created", "\"x\":1", TimeMark(1_000_000_000L))
        w.drainExternal()
        assertTrue(failure is IllegalStateException, "$failure")
        assertFalse(w.enabled)
        assertEquals(1, sink.closed)
        assertFalse(w.enqueue("http:frame_created", "\"x\":2", TimeMark(1_000_000_000L)))
    }

    @Test fun anEventBeforeTheTraceStartGetsTimeZero() {
        val sink = Sink()
        val w = writer(sink)
        w.enqueue("http:frame_created", "\"x\":1", TimeMark(999_000_000L))
        w.drainExternal()
        assertTrue(sink.records[1].startsWith("\u001e{\"time\":0.000,"), sink.records[1])
    }
}
