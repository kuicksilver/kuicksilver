// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.flow.RecvFlowController
import io.kuicksilver.quic.flow.SendFlowController
import io.kuicksilver.quic.flow.StreamLimits
import io.kuicksilver.quic.recovery.SentFrames
import io.kuicksilver.tls.TlsRole
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * A stream whose sending half ended with our RESET_STREAM is finished for the application (StreamFinished, which HTTP/3's
 * graceful close waits for) only once that frame is acknowledged: RFC 9000 section 3.1, "Reset Recvd". It is retired
 * and its stream credit counted at once, as before; only the report waits, as it does for a FIN until all data is
 * acknowledged.
 */
class ResetAckTest {
    private fun manager(role: TlsRole): StreamManager =
        StreamManager(
            role,
            QuicConfig.Default,
            RecvFlowController(786_432, 15_728_640),
            SendFlowController(1L shl 40),
            StreamLimits(role, 100, 100),
        ).also { it.applyPeerParameters(1L shl 30, 1L shl 30, 1L shl 30, 100, 100) }

    private fun StreamManager.finished(id: Long): Boolean = events.any { it is ConnectionEvent.StreamFinished && it.id == id }

    private fun ack(id: Long) = SentFrames().also { it.addId(SentFrames.ID_RESET_STREAM, id, 0x10c, 0) }

    @Test fun negative_resetStreamIsFinishedOnlyOnceItsResetIsAcknowledged() {
        val m = manager(TlsRole.Client)
        val id = m.open(bidi = false, StreamPriority.Default)
        m.reset(id, 0x10c)
        assertFalse(m.isOpen(id), "retired at once")
        assertFalse(m.finished(id), "not finished before the RESET_STREAM is acknowledged")
        assertContentEquals(intArrayOf(1, 1), m.resetAcksPendingForTest())
        m.onFramesLost(ack(id)) // lost: queued again, still not finished
        assertFalse(m.finished(id))
        m.onFramesAcked(ack(id))
        assertTrue(m.finished(id))
        assertContentEquals(intArrayOf(0, 0), m.resetAcksPendingForTest())
        m.events.clear()
        m.onFramesAcked(ack(id)) // a second acknowledgment reports nothing more
        assertFalse(m.finished(id))
    }

    /** A STOP_SENDING answered with RESET_STREAM (section 3.5) waits for that frame's acknowledgment the same way. */
    @Test fun resetAnsweringStopSendingWaitsForItsAcknowledgment() {
        val m = manager(TlsRole.Server)
        m.onResetStream(0, 0x10c, 0)
        m.read(0, ByteArray(1), 0, 1) // the peer's reset surfaced
        m.onStopSending(0, 0x10c)
        assertFalse(m.finished(0))
        m.onFramesAcked(ack(0))
        assertTrue(m.finished(0))
    }

    /** A stream finished with a FIN is reported at once, as before (no RESET_STREAM to wait for). */
    @Test fun streamWithoutResetIsReportedAsBefore() {
        val m = manager(TlsRole.Server)
        m.onResetStream(0, 0x10c, 0)
        m.read(0, ByteArray(1), 0, 1)
        m.write(0, ByteArray(0), 0, 0, fin = true)
        val f = SentFrames()
        val b =
            io.kuicksilver.native.PacketBuffer
                .allocate(1200)
        try {
            m.writeStreamFrame(
                io.kuicksilver.quic.wire
                    .WireWriter(b, 0, 1200),
                f,
            )
        } finally {
            b.close()
        }
        m.onFramesAcked(f)
        assertTrue(m.finished(0))
    }

    /**
     * 0-RTT rejected: the client drops every stream it opened (RFC 9001 section 4.6.2), with the RESET_STREAM of one it had
     * reset; nothing of it stays pending and no late acknowledgment reports it finished.
     */
    @Test fun rejectedZeroRttDropsAPendingResetAcknowledgment() {
        val m = manager(TlsRole.Client)
        val id = m.open(bidi = false, StreamPriority.Default)
        m.reset(id, 0x10c)
        assertContentEquals(intArrayOf(1, 1), m.resetAcksPendingForTest())
        m.resetForRejectedZeroRtt(1L shl 40, 100, 100)
        assertContentEquals(intArrayOf(0, 0), m.resetAcksPendingForTest())
        m.events.clear()
        m.onFramesAcked(ack(id))
        assertFalse(m.finished(id))
        assertEquals(0, m.events.count { it is ConnectionEvent.StreamFinished })
    }
}
