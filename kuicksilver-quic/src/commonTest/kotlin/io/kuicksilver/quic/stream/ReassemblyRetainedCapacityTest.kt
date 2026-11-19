// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.flow.RecvFlowController
import io.kuicksilver.quic.flow.SendFlowController
import io.kuicksilver.quic.flow.StreamLimits
import io.kuicksilver.tls.TlsRole
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The class of picoquic #2333 (a receive-side memory bound that stops holding once the peer moved the window): the flow-control
 * windows and the reassembly range limits are fixed ceilings here, but a reassembly buffer kept its allocation after the reads.
 * Flow control bounds what is unread at any one time, never what stays allocated: a peer that pushed one stream window through
 * each of `max_streams` streams left the connection holding the sum of its stream windows (100 x 512 KiB against a 15 MiB
 * connection window), drained (up to 1 MiB kept each) or left with a 1-byte gap and nothing readable (the whole stream window
 * kept, up to 6 MiB once auto-tuning grew it, and never read again).
 */
class ReassemblyRetainedCapacityTest {
    private val config = QuicConfig.Default

    private fun manager(): StreamManager =
        StreamManager(
            TlsRole.Server,
            config,
            RecvFlowController(config.initialConnectionWindow, config.maxConnectionWindow),
            SendFlowController(1L shl 40),
            StreamLimits(TlsRole.Server, 100, 100),
        ).also { it.applyPeerParameters(1L shl 20, 1L shl 20, 1L shl 20, 100, 100) }

    private fun send(
        m: StreamManager,
        id: Long,
        offset: Long,
        len: Int,
        fin: Boolean = false,
    ) {
        val b = PacketBuffer.allocate(maxOf(len, 1))
        try {
            m.onStream(id, offset, b, 0, len, fin)
        } finally {
            b.close()
        }
    }

    private fun drain(
        m: StreamManager,
        id: Long,
    ): Long {
        val buf = ByteArray(65_536)
        var total = 0L
        while (true) {
            val n = m.read(id, buf, 0, buf.size)
            if (n <= 0) return total
            total += n
        }
    }

    @Test fun negative_drainedStreamWindowsDoNotStayAllocatedPastTheConnectionWindow() {
        val m = manager()
        val window = config.initialStreamWindow
        for (s in 0 until 100) {
            val id = 4L * s
            // one byte at the end of the stream window sizes the buffer to the whole window, the rest fills the hole
            send(m, id, window - 1, 1)
            send(m, id, 0, (window - 1).toInt())
            assertEquals(window, drain(m, id), "stream $id")
        }
        val held = m.receiveCapacityForTest()
        assertTrue(
            held <= config.maxConnectionWindow,
            "${held / 1024} KiB of reassembly buffers held by 100 drained streams, above the ${config.maxConnectionWindow / 1024} KiB " +
                "connection window",
        )
        assertEquals(null, m.invariantViolationForTest())
    }

    @Test fun negative_streamsLeftWithAGapDoNotKeepTheirWindowsAllocated() {
        val m = manager()
        val window = config.initialStreamWindow
        for (s in 0 until 100) {
            val id = 4L * s
            // the last byte of the window, then all but the byte before it: everything up to the gap is read, one range stays
            send(m, id, window - 1, 1)
            send(m, id, 0, (window - 2).toInt())
            assertEquals(window - 2, drain(m, id), "stream $id")
        }
        val held = m.receiveCapacityForTest()
        assertTrue(
            held <= config.maxConnectionWindow + 100L * Reassembler.MIN_WINDOW,
            "${held / 1024} KiB of reassembly buffers held by 100 streams with 2 bytes buffered each, above the " +
                "${config.maxConnectionWindow / 1024} KiB connection window",
        )
        assertEquals(null, m.invariantViolationForTest())
        // the gaps still fill and the data still arrives
        for (s in 0 until 100) {
            send(m, 4L * s, window - 2, 1)
            assertEquals(2L, drain(m, 4L * s), "stream ${4L * s}")
        }
        assertEquals(null, m.invariantViolationForTest())
    }

    @Test fun aDrainedStreamStillKeepsItsBufferWithinTheBudget() {
        // the cap must not cost a bulk stream its buffer: one stream that drains keeps its allocation for the next burst
        val m = manager()
        send(m, 0, 0, 200_000)
        assertEquals(200_000L, drain(m, 0))
        val kept = m.receiveCapacityForTest()
        assertTrue(kept >= 200_000, "a drained stream within the budget keeps its buffer: $kept")
    }

    @Test fun finishedStreamsReturnTheirShareOfTheBudget() {
        // streams that end give back what they counted: after many finished streams a drained one still keeps its buffer
        // (unidirectional peer streams: they close as soon as they are read to the end)
        val m = manager()
        for (s in 0 until 400) {
            val id = 4L * s + 2
            send(m, id, 0, 100_000, fin = true)
            assertEquals(100_000L, drain(m, id), "stream $id")
        }
        send(m, 4L * 400 + 2, 0, 200_000)
        assertEquals(200_000L, drain(m, 4L * 400 + 2))
        assertTrue(m.receiveCapacityForTest() >= 200_000, "the budget leaked: ${m.receiveCapacityForTest()}")
    }
}
