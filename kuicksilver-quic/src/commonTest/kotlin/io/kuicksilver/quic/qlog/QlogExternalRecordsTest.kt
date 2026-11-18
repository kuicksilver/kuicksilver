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
    ) = QlogWriter(sink, maxBytes, TimeMark(1_000_000_000L), TlsRole.Client, "0a0b")

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
