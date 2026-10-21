// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.flow.RecvFlowController
import io.kuicksilver.quic.flow.SendFlowController
import io.kuicksilver.quic.flow.StreamLimits
import io.kuicksilver.quic.recovery.SentFrames
import io.kuicksilver.quic.wire.WireWriter
import io.kuicksilver.tls.TlsRole
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Review h-quic: a client that downloads a large response, acknowledges every other packet and never the rest leaves the server's
 * send half with ~N/2 acknowledged ranges and ~N/2 lost ranges waiting for congestion window. `SendStream.pruneLost` checked every
 * lost range against every acknowledged one (O(L x A)), and `hasPending` ran it for every received MAX_STREAM_DATA, even one that
 * raises nothing and so spends no glitch token: one 1452-byte packet of ~300 such frames cost the endpoint loop ~250 ms.
 *
 * The work is counted in range comparisons (`rangeStepsForTest`), not timed: an acknowledgement removes its bytes from the lost
 * queue when it arrives, so a MAX_STREAM_DATA costs no range work at all and an acknowledgement or a loss costs O(log n).
 */
class SendStreamComplexityTest {
    @Test fun negative_maxStreamDataFloodStaysCheapWithAlternatingAcks() {
        val m =
            StreamManager(
                TlsRole.Server,
                QuicConfig.Default,
                RecvFlowController(786_432, 15_728_640),
                SendFlowController(1L shl 40),
                StreamLimits(TlsRole.Server, 100, 100),
            )
        m.applyPeerParameters(1L shl 40, 1L shl 40, 1L shl 40, 100, 100)
        // the client opens bidi stream 0 with its request
        val req = PacketBuffer.of(ByteArray(2))
        try {
            m.onStream(0, 0, req, 0, 1, true)
        } finally {
            req.close()
        }
        val total = 4 shl 20 // QuicConfig.maxSendBuffer default
        var written = 0
        while (written < total) written += m.write(0, ByteArray(total - written), 0, total - written, false).also { check(it > 0) }
        val packets = ArrayList<SentFrames>()
        val b = PacketBuffer.allocate(1200)
        try {
            while (true) {
                val f = SentFrames()
                if (!m.writeStreamFrame(WireWriter(b, 0, 1200), f)) break
                packets += f
            }
        } finally {
            b.close()
        }
        val beforeAcks = m.sendRangeStepsForTest(0)
        for ((k, f) in packets.withIndex()) if (k % 2 == 0) m.onFramesAcked(f) else m.onFramesLost(f)
        val ackWork = m.sendRangeStepsForTest(0) - beforeAcks
        // each acknowledgement or loss costs a binary search over ~n/2 ranges plus the ranges it touches, not a pass over them
        assertTrue(ackWork <= packets.size * 32L, "${packets.size} acks/losses cost $ackWork range steps")
        val before = m.sendRangeStepsForTest(0)
        repeat(300) { m.onMaxStreamData(0, 1L shl 40) } // one 1452-byte packet: ~300 MAX_STREAM_DATA frames that raise nothing
        repeat(300) { m.onMaxStreamData(0, (1L shl 40) + it + 1) } // and ~300 that raise the limit by one byte each
        val flood = m.sendRangeStepsForTest(0) - before
        assertTrue(flood <= 300, "600 MAX_STREAM_DATA frames cost $flood range steps with ${packets.size / 2} lost and acked ranges")
        // building packets of retransmissions does not walk the queue either
        val beforeResend = m.sendRangeStepsForTest(0)
        val r = PacketBuffer.allocate(1200)
        try {
            repeat(100) { check(m.writeStreamFrame(WireWriter(r, 0, 1200), SentFrames())) }
        } finally {
            r.close()
        }
        val resend = m.sendRangeStepsForTest(0) - beforeResend
        assertTrue(resend <= 100, "100 retransmitted frames cost $resend range steps")
    }
}
