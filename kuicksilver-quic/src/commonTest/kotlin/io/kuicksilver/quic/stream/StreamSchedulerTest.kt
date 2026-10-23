// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.quic.StreamPriority
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class StreamSchedulerTest {
    private fun stream(
        id: Long,
        urgency: Int = 3,
        incremental: Boolean = false,
        retransmit: Boolean = false,
        critical: Boolean = false,
    ): SendStream =
        SendStream(id, if (critical) StreamPriority.Critical else StreamPriority(urgency, incremental)).also {
            it.enqueue(ByteArray(100), 0, 100, false)
            if (retransmit) {
                it.markSent(0, 100)
                it.onLost(0, 100)
            }
        }

    private fun order(vararg s: SendStream): List<Long> {
        val sch = StreamScheduler()
        s.forEach { sch.add(it) }
        return List(s.size) { sch.next()!!.also { st -> sch.remove(st) }.id }
    }

    @Test fun urgencyStrict() =
        assertEquals(
            listOf(8L, 4L, 0L),
            order(stream(0, urgency = 7), stream(4, urgency = 3), stream(8, urgency = 0)),
        )

    @Test fun nonIncrementalByIdAscending() = assertEquals(listOf(0L, 4L, 12L), order(stream(12), stream(0), stream(4)))

    @Test fun incrementalRoundRobin() {
        val a = stream(0, incremental = true)
        val b = stream(4, incremental = true)
        val sch = StreamScheduler()
        sch.add(a)
        sch.add(b)
        assertEquals(listOf(0L, 4L, 0L, 4L), List(4) { sch.next()!!.also { s -> sch.rotate(s) }.id })
    }

    @Test fun retransmissionsBeforeNewDataOnSameLevel() =
        assertEquals(listOf(8L, 0L, 4L), order(stream(0), stream(4), stream(8, retransmit = true)))

    /**
     * Streams opened with [StreamPriority.Critical] (the HTTP/3 control and QPACK streams) go before every other stream, a
     * peer's u=0 with a lower id included: a peer must not hold back our SETTINGS or QPACK instructions with its own signal.
     */
    @Test fun criticalStreamsBeforeEveryUrgency() =
        assertEquals(
            listOf(11L, 3L, 7L, 4L, 0L, 8L),
            order(
                stream(0, urgency = 0),
                stream(4, urgency = 0, retransmit = true),
                stream(8, urgency = 0, incremental = true),
                stream(7, critical = true),
                stream(3, critical = true),
                stream(11, critical = true, retransmit = true),
            ),
        )

    @Test fun addIsLogarithmicAtTenThousandStreams() {
        // RFC 9000 section 21.6: the peer's stream limit sets how many streams can be live; scheduling one must not cost a pass over all of them
        val sch = StreamScheduler()
        val streams = List(10_000) { stream(4L * it) }
        for (s in streams.asReversed()) sch.add(s) // descending ids: the worst case for an ordered insert
        assertTrue(sch.comparisonsForTest < 20L * 10_000, "comparisons for 10 000 adds: ${sch.comparisonsForTest}")
        assertEquals(0L, sch.next()!!.id)
        for (s in streams) sch.add(s) // already scheduled: a no-op
        assertTrue(sch.comparisonsForTest < 40L * 10_000, "comparisons after 10 000 repeated adds: ${sch.comparisonsForTest}")
    }

    @Test fun streamWithNewLossOrPriorityIsRefiled() {
        // the queues are keyed by state that changes while a stream is queued: a loss and a priority change must move it
        val a = stream(0)
        val b = stream(4)
        val sch = StreamScheduler()
        sch.add(a)
        sch.add(b)
        b.markSent(0, 100)
        b.onLost(0, 100)
        sch.reschedule(b)
        assertEquals(4L, sch.next()!!.id, "a retransmission goes first")
        a.priority = StreamPriority(0)
        sch.reschedule(a)
        assertEquals(0L, sch.next()!!.id, "a more urgent stream goes before the retransmission")
        sch.remove(a)
        sch.remove(b)
        assertTrue(sch.isEmpty)
    }

    @Test fun urgencyOutOfRangeRejected() {
        assertFailsWith<IllegalArgumentException> { StreamPriority(8) }
        assertFailsWith<IllegalArgumentException> { StreamPriority(-1) }
    }
}
