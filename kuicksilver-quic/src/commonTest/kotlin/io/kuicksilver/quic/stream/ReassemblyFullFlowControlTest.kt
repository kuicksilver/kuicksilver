// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.flow.RecvFlowController
import io.kuicksilver.quic.flow.SendFlowController
import io.kuicksilver.quic.flow.StreamLimits
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.tls.TlsRole
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.fail

/**
 * Review h-quic: RecvStream.onData raises the stream's highest offset before Reassembler.insert may refuse the frame with
 * ReassemblyFull, and the exception skips StreamManager's connection-level charge. The packet is dropped, but the bytes up to the
 * new highest offset are never charged to the connection: data later sent below that offset merges into a buffered range, is
 * stored, and advances nothing. A peer fills each stream's reassembly ranges, sends one byte at the end of the stream window, then
 * the whole window: every stream holds a full stream window (512 KiB) while the connection window (768 KiB) is barely touched.
 */
class ReassemblyFullFlowControlTest {
    private fun send(
        m: StreamManager,
        id: Long,
        offset: Long,
        len: Int,
    ) {
        val b = PacketBuffer.allocate(maxOf(len, 1) + 1)
        try {
            m.onStream(id, offset, b, 0, len, false)
        } catch (_: ReassemblyFull) {
            // PacketReceiver drops the packet unacknowledged
        } finally {
            b.close()
        }
    }

    @Test fun negative_refusedFrameStillChargesTheConnectionWindow() {
        val config = QuicConfig.Default
        val m =
            StreamManager(
                TlsRole.Server,
                config,
                RecvFlowController(config.initialConnectionWindow, config.maxConnectionWindow),
                SendFlowController(1L shl 40),
                StreamLimits(TlsRole.Server, 100, 100),
            )
        m.applyPeerParameters(1L shl 20, 1L shl 20, 1L shl 20, 100, 100)
        val window = config.initialStreamWindow // 512 KiB per stream, 768 KiB for the connection
        try {
            for (s in 0 until 3) {
                val id = 4L * s
                for (k in 0 until 256) send(m, id, 2L * k, 1) // 256 one-byte ranges: the stream's reassembly limit
                send(m, id, window - 1, 1) // a new range: ReassemblyFull, after highest moved to the window's end
                send(m, id, 1, (window - 2).toInt()) // merges into [0, 1): stored, charges nothing
            }
        } catch (e: QuicWireException) {
            assertEquals(TransportError.FLOW_CONTROL_ERROR, e.code)
            return
        }
        var held = 0L
        val buf = ByteArray(65_536)
        for (s in 0 until 3) {
            while (true) {
                val n = m.read(4L * s, buf, 0, buf.size)
                if (n <= 0) break
                held += n
            }
        }
        fail(
            "$held bytes held by 3 streams (3 x ${window / 1024} KiB buffered on 3 streams without a FLOW_CONTROL_ERROR; the connection window is ${config.initialConnectionWindow / 1024} KiB",
        )
    }

    @Test fun negative_aRefusedFrameChangesNothing() {
        // the refused frame leaves no trace: highest, the final size and the connection charge stay where they were, and the
        // connection credit returned when the stream is abandoned covers only bytes that were charged
        val config = QuicConfig.Default
        val m =
            StreamManager(
                TlsRole.Server,
                config,
                RecvFlowController(config.initialConnectionWindow, config.maxConnectionWindow),
                SendFlowController(1L shl 40),
                StreamLimits(TlsRole.Server, 100, 100),
            )
        m.applyPeerParameters(1L shl 20, 1L shl 20, 1L shl 20, 100, 100)
        for (k in 0 until 256) send(m, 0, 2L * k, 1)
        assertNull(m.invariantViolationForTest())
        val b = PacketBuffer.allocate(2)
        try {
            assertFailsWith<ReassemblyFull> { m.onStream(0, 100_000, b, 0, 1, true) }
        } finally {
            b.close()
        }
        assertNull(m.invariantViolationForTest(), "after a refused frame")
        // a FIN below the refused frame's offset is still accepted: the refused frame did not fix the final size at 100 001
        val fin = PacketBuffer.allocate(2)
        try {
            m.onStream(0, 511, fin, 0, 1, true)
        } finally {
            fin.close()
        }
        assertNull(m.invariantViolationForTest(), "after the FIN")
    }
}
