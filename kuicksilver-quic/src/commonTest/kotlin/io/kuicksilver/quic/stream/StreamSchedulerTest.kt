// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.quic.StreamPriority
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class StreamSchedulerTest {
    private fun stream(
        id: Long,
        urgency: Int = 3,
        incremental: Boolean = false,
        retransmit: Boolean = false,
    ): SendStream =
        SendStream(id, StreamPriority(urgency, incremental)).also {
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

    @Test fun urgencyOutOfRangeRejected() {
        assertFailsWith<IllegalArgumentException> { StreamPriority(8) }
        assertFailsWith<IllegalArgumentException> { StreamPriority(-1) }
    }
}
