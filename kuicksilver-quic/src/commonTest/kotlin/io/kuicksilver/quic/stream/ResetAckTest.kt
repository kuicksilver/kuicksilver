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

    /**
     * The reset-tracking sets are made by a reset and let go once it is acknowledged and its stream reported: an idle
     * connection that once reset a stream holds none of them (IdleFootprintTest varied by up to 912 B with them).
     */
    @Test fun negative_theResetSetsAreLetGoOnceEmpty() {
        val m = manager(TlsRole.Client)
        assertEquals(0, m.resetSetsHeldForTest())
        val id = m.open(bidi = false, StreamPriority.Default)
        m.reset(id, 0x10c)
        assertEquals(3, m.resetSetsHeldForTest(), "unacknowledged, retired, offered to the runtime")
        assertEquals(listOf(id), m.takeRetiredAwaitingAck())
        assertEquals(2, m.resetSetsHeldForTest(), "the offered list goes with its taking")
        m.onFramesAcked(ack(id))
        assertTrue(m.finished(id))
        assertEquals(0, m.resetSetsHeldForTest(), "nothing pending: no set kept")
    }

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

    /**
     * A peer that STOP_SENDINGs its streams and leaves our answering RESET_STREAMs unacknowledged gets no stream credit
     * for them: a peer stream that ended with our reset counts as closed at the acknowledgment, so such streams never
     * outnumber the limit (and the runtime's state for them with it).
     */
    @Test fun negative_peerWithholdingResetAcksStaysWithinTheStreamLimit() {
        val m =
            StreamManager(
                TlsRole.Server,
                QuicConfig.Default,
                RecvFlowController(786_432, 15_728_640),
                SendFlowController(1L shl 40),
                StreamLimits(TlsRole.Server, 2, 2),
            ).also { it.applyPeerParameters(1L shl 30, 1L shl 30, 1L shl 30, 100, 100) }
        for (id in listOf(0L, 4L)) {
            m.onStopSending(id, 0x10c) // we answer with RESET_STREAM
            m.onResetStream(id, 0x10c, 0)
            m.read(id, ByteArray(1), 0, 1)
        }
        assertEquals(listOf(0L, 4L), m.takeRetiredAwaitingAck(), "retired, the report waiting")
        assertTrue(generateSequence { m.takeControlFrame() }.none { it.kind == ControlKind.MaxStreamsBidi }, "no credit back yet")
        kotlin.test.assertFailsWith<io.kuicksilver.quic.wire.QuicWireException> { m.onResetStream(8, 0, 0) } // beyond the limit
        m.onFramesAcked(ack(0))
        assertTrue(m.finished(0))
        assertEquals(
            listOf(3L),
            generateSequence { m.takeControlFrame() }.filter { it.kind == ControlKind.MaxStreamsBidi }.map { it.a }.toList(),
        )
    }

    /** RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset) is waited for like RESET_STREAM. */
    @Test fun resetStreamAtIsFinishedOnlyOnceAcknowledged() {
        val m = manager(TlsRole.Client)
        m.forceResetStreamAtForTest = true
        val id = m.open(bidi = false, StreamPriority.Default)
        m.resetAt(id, 0x10c, 0)
        assertFalse(m.isOpen(id), "retired: nothing reliable was left to send")
        assertFalse(m.finished(id))
        m.onFramesAcked(SentFrames().also { it.addId(SentFrames.ID_RESET_STREAM_AT, id, 0x10c, 0, 0) })
        assertTrue(m.finished(id))
    }

    private fun limited(limit: Long): StreamManager =
        StreamManager(
            TlsRole.Server,
            QuicConfig.Default,
            RecvFlowController(786_432, 15_728_640),
            SendFlowController(1L shl 40),
            StreamLimits(TlsRole.Server, limit, limit),
        ).also { it.applyPeerParameters(1L shl 30, 1L shl 30, 1L shl 30, 100, 100) }

    private fun StreamManager.maxStreamsBidi(): List<Long> =
        generateSequence { takeControlFrame() }.filter { it.kind == ControlKind.MaxStreamsBidi }.map { it.a }.toList()

    /**
     * STREAMS_BLOCKED at the limit we granted before the acknowledgment of our reset returns a stream's credit: the peer
     * reports each limit once, so the credit the acknowledgment frees is announced at once, below the half window.
     */
    @Test fun negative_streamsBlockedBeforeTheResetAcknowledgmentIsAnsweredAtTheAcknowledgment() {
        val m = limited(4)
        for (k in 0 until 4) {
            val id = 4L * k
            m.onStopSending(id, 0x10c)
            m.onResetStream(id, 0x10c, 0)
            m.read(id, ByteArray(1), 0, 1)
        }
        m.onStreamsBlocked(true, 4) // nothing counted closed yet: remembered
        assertEquals(emptyList(), m.maxStreamsBidi())
        m.onFramesAcked(ack(0)) // one stream's credit: below the half window of 2
        assertEquals(listOf(5L), m.maxStreamsBidi(), "announced at once")
        m.onFramesAcked(ack(4)) // the report was answered: back to the half window
        assertEquals(emptyList(), m.maxStreamsBidi())
    }

    /** The same with held credit (an HTTP/3 request whose handler ends after the peer reported STREAMS_BLOCKED). */
    @Test fun negative_streamsBlockedBeforeACreditReleaseIsAnsweredAtTheRelease() {
        val m = limited(4)
        m.holdPeerBidiCredit()
        for (k in 0 until 4) {
            val id = 4L * k
            m.onResetStream(id, 0x10c, 0)
            m.read(id, ByteArray(1), 0, 1)
            m.write(id, ByteArray(0), 0, 0, fin = true)
        }
        val f = SentFrames()
        val b =
            io.kuicksilver.native.PacketBuffer
                .allocate(1200)
        try {
            while (m.writeStreamFrame(
                    io.kuicksilver.quic.wire
                        .WireWriter(b, 0, 1200),
                    f,
                )
            ) {
                continue
            }
        } finally {
            b.close()
        }
        m.onFramesAcked(f) // every stream finished, all four held
        m.onStreamsBlocked(true, 4)
        assertEquals(emptyList(), m.maxStreamsBidi())
        m.releasePeerCredit(0)
        assertEquals(listOf(5L), m.maxStreamsBidi(), "announced at once")
    }
}
