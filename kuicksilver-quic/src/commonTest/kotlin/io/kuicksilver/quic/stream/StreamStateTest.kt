// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.flow.RecvFlowController
import io.kuicksilver.quic.flow.SendFlowController
import io.kuicksilver.quic.flow.StreamLimits
import io.kuicksilver.quic.recovery.SentFrames
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.quic.wire.WireWriter
import io.kuicksilver.tls.TlsRole
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

class StreamStateTest {
    @Test fun connectionWindowFollowsStreamWindow() {
        // the connection window is kept at least 1.5x the stream window (K2 review leftover: ensureWindowAtLeast was never wired)
        val m =
            StreamManager(
                TlsRole.Server,
                io.kuicksilver.quic.quicConfig {
                    initialStreamWindow = 1_000_000
                    maxStreamWindow = 6_291_456
                },
                RecvFlowController(786_432, 15_728_640),
                SendFlowController(1L shl 40),
                StreamLimits(TlsRole.Server, 100, 100),
            )
        m.applyPeerParameters(1L shl 30, 1L shl 30, 1L shl 30, 100, 100)
        recv(m, 0, 0, ByteArray(300_000))
        val buf = ByteArray(300_000)
        assertEquals(300_000, m.read(0, buf, 0, 300_000))
        val limits = generateSequence { m.takeControlFrame() }.filter { it.kind == ControlKind.MaxData }.map { it.a }.toList()
        assertTrue(limits.contains(300_000L + 1_500_000L), "connection limit raised to consumed + 1.5 x stream window: $limits")
    }

    private fun manager(
        role: TlsRole = TlsRole.Client,
        peerMaxData: Long = 1L shl 40,
        maxStreams: Long = 100,
        streamWindow: Long = 1L shl 30,
    ): StreamManager {
        val m =
            StreamManager(
                role,
                QuicConfig.Default,
                RecvFlowController(786_432, 15_728_640),
                SendFlowController(peerMaxData),
                StreamLimits(role, maxStreams, maxStreams),
            )
        m.applyPeerParameters(
            initialMaxStreamDataBidiLocal = streamWindow,
            initialMaxStreamDataBidiRemote = streamWindow,
            initialMaxStreamDataUni = streamWindow,
            maxStreamsBidi = maxStreams,
            maxStreamsUni = maxStreams,
        )
        return m
    }

    @Test fun maxDataWithoutGrowthTouchesNoStream() {
        // RFC 9000 section 21.6: a MAX_DATA that raises nothing costs the peer one frame; it must not cost us a pass over every stream
        val m = manager(peerMaxData = 1L shl 20, maxStreams = 1000)
        repeat(1000) {
            val id = m.open(bidi = true, StreamPriority.Default)
            assertTrue(id >= 0)
            m.write(id, ByteArray(10), 0, 10, false)
        }
        val before = m.schedulerTouchesForTest
        assertTrue(!m.onMaxData(1L shl 20), "the same limit again grows nothing")
        assertEquals(0L, m.schedulerTouchesForTest - before, "no stream was touched")
    }

    private fun recv(
        m: StreamManager,
        id: Long,
        offset: Long,
        bytes: ByteArray,
        fin: Boolean = false,
    ) {
        val b =
            PacketBuffer.of(bytes + ByteArray(1))
        ; try {
            m.onStream(id, offset, b, 0, bytes.size, fin)
        } finally {
            b.close()
        }
    }

    private fun code(block: () -> Unit): Long = assertFailsWith<QuicWireException>(block = block).code

    /** Writes one STREAM frame into a throwaway buffer and returns what it recorded. */
    private fun sendOnce(
        m: StreamManager,
        max: Int = 1200,
    ): SentFrames? {
        val b = PacketBuffer.allocate(max)
        try {
            val f = SentFrames()
            return if (m.writeStreamFrame(WireWriter(b, 0, max), f)) f else null
        } finally {
            b.close()
        }
    }

    @Test fun finalSizeChangeIsFinalSizeError() {
        val m = manager(TlsRole.Server)
        recv(m, 0, 0, ByteArray(100), fin = true)
        assertEquals(0x06L, code { recv(m, 0, 50, ByteArray(10), fin = true) })
    }

    @Test fun dataBeyondFinalSizeIsFinalSizeError() {
        val m = manager(TlsRole.Server)
        recv(m, 0, 0, ByteArray(100), fin = true)
        assertEquals(0x06L, code { recv(m, 0, 100, ByteArray(1)) })
    }

    @Test fun resetFinalSizeBelowReceivedIsFinalSizeError() {
        val m = manager(TlsRole.Server)
        recv(m, 0, 0, ByteArray(100))
        assertEquals(0x06L, code { m.onResetStream(0, 1, 50) })
    }

    /**
     * Fuzzing finding (connectionNull): RESET_STREAM's final size was checked against the connection window only, so a peer
     * could claim more than the stream window allowed (RFC 9000 sections 4.1, 4.5, 19.10: FLOW_CONTROL_ERROR).
     */
    @Test fun negative_resetFinalSizeBeyondStreamWindowIsFlowControlError() {
        val m = manager(TlsRole.Server)
        assertEquals(0x03L, code { m.onResetStream(0, 1, QuicConfig.Default.initialStreamWindow + 1) })
        assertNull(m.invariantViolationForTest())
    }

    /** Fuzzing finding (connectionNull): a flow-control error left the connection's received total above the advertised limit. */
    @Test fun negative_flowControlErrorKeepsReceivedWithinLimit() {
        val m = manager(TlsRole.Server)
        assertEquals(0x03L, code { m.onResetStream(0, 1, 1L shl 48) })
        assertNull(m.invariantViolationForTest())
        recv(m, 4, 0, ByteArray(500_000))
        assertEquals(0x03L, code { recv(m, 8, 0, ByteArray(500_000)) })
        assertNull(m.invariantViolationForTest())
    }

    @Test fun streamFrameOnLocalSendOnlyUniIsStreamStateError() {
        val m = manager(TlsRole.Client)
        val id = m.open(bidi = false, StreamPriority.Default)
        assertEquals(2L, id)
        assertEquals(0x05L, code { recv(m, id, 0, ByteArray(1)) })
    }

    @Test fun maxStreamDataOnReceiveOnlyIsStreamStateError() {
        val m = manager(TlsRole.Server)
        recv(m, 2, 0, ByteArray(1))
        assertEquals(0x05L, code { m.onMaxStreamData(2, 1000) })
    }

    @Test fun stopSendingTriggersResetWithSameCode() {
        val m = manager(TlsRole.Client)
        val id = m.open(bidi = true, StreamPriority.Default)
        m.write(id, ByteArray(10), 0, 10, fin = false)
        m.onStopSending(id, 77)
        val c = m.takeControlFrame()
        assertNotNull(c)
        assertEquals(ControlKind.ResetStream, c.kind)
        assertEquals(id, c.id)
        assertEquals(77L, c.a)
        assertNull(sendOnce(m), "no more stream data after a reset")
    }

    @Test fun peerOpeningHigherIdOpensLowerOnes() {
        val m = manager(TlsRole.Server)
        recv(m, 8, 0, ByteArray(1))
        assertTrue(m.isOpen(0) && m.isOpen(4) && m.isOpen(8))
        assertEquals(listOf(0L, 4L, 8L), m.events.filterIsInstance<ConnectionEvent.StreamOpened>().map { it.id })
    }

    /**
     * Soak regression (0.2.0, Linux arm64 Native heap creep): every peer-opened stream was also appended to a list nothing
     * drained, so a long-lived connection (the soak's one server HTTP/3 connection) kept a boxed id per request forever. Once
     * its streams are done and the events and control frames are taken, the manager must hold nothing per stream.
     */
    @Test fun finishedPeerStreamsLeaveNothingBehind() {
        val m = manager(TlsRole.Server, maxStreams = 1000)
        val buf = ByteArray(64)
        repeat(3000) { i ->
            val id = 4L * i + 2 // client-initiated unidirectional
            recv(m, id, 0, ByteArray(10), fin = true)
            while (m.read(id, buf, 0, buf.size) >= 0) {
                // drain to the end: the stream finishes and is forgotten
            }
            assertTrue(!m.isOpen(id), "stream $id finished")
            m.events.clear()
            while (m.takeControlFrame() != null) {
                // MAX_STREAMS credit, as the connection would send it
            }
        }
        val sizes = m.sizesForTest()
        assertTrue(sizes.all { it == 0 }, "per-stream state left after 3000 finished peer streams: ${sizes.toList()}")
    }

    @Test fun sendBufferCap4MiB() {
        val m = manager()
        val id = m.open(bidi = true, StreamPriority.Default)
        val chunk = ByteArray(1 shl 20)
        var total = 0
        repeat(6) { total += m.write(id, chunk, 0, chunk.size, false) }
        assertEquals(4_194_304, total)
        assertEquals(4_194_304L, m.sendBufferedBytes)
        assertEquals(0, m.write(id, chunk, 0, 1, false))
    }

    @Test fun ackedDataReleasesSendBuffer() {
        val m = manager()
        val id = m.open(bidi = true, StreamPriority.Default)
        m.write(id, ByteArray(3000), 0, 3000, false)
        val f1 = sendOnce(m, 2000)!!
        val f2 = sendOnce(m, 2000)!!
        assertEquals(3000L, m.sendBufferedBytes)
        assertEquals(
            3000,
            f1.streamLength[0] + f2.streamLength[0],
        )
        m.onFramesAcked(f1)
        assertEquals(3000L - f1.streamLength[0], m.sendBufferedBytes)
        m.onFramesAcked(f2)
        assertEquals(0L, m.sendBufferedBytes)
    }

    @Test fun lostRangesRequeuedForRetransmission() {
        val m = manager()
        val id = m.open(bidi = true, StreamPriority.Default)
        m.write(id, ByteArray(3000) { it.toByte() }, 0, 3000, true)
        val f1 = sendOnce(m)!!
        sendOnce(m)!!
        sendOnce(m)!!
        assertNull(sendOnce(m))
        m.onFramesLost(f1)
        val again = sendOnce(m)!!
        assertEquals(f1.streamOffset[0], again.streamOffset[0])
        assertEquals(f1.streamLength[0], again.streamLength[0])
    }

    @Test fun readReturnsMinusOneAtFin() {
        val m = manager(TlsRole.Server)
        recv(m, 0, 0, byteArrayOf(1, 2, 3), fin = true)
        val buf = ByteArray(10)
        assertEquals(3, m.read(0, buf, 0, 10))
        assertEquals(-1, m.read(0, buf, 0, 10))
    }

    @Test fun writeBlockedByPeerFlowControlReportsBlocked() {
        val m = manager(peerMaxData = 500)
        val id = m.open(bidi = true, StreamPriority.Default)
        m.write(id, ByteArray(1000), 0, 1000, false)
        val f = sendOnce(m)!!
        assertEquals(500, f.streamLength[0])
        assertNull(sendOnce(m))
        val c = m.takeControlFrame()
        assertNotNull(c)
        assertEquals(ControlKind.DataBlocked, c.kind)
        assertEquals(500L, c.a)
    }

    @Test fun maxStreamDataRaisesStreamWritable() {
        // RFC 9000 section 4.1: credit from MAX_STREAM_DATA lets data that was waiting go out; the stream learns it without polling
        val m = manager(streamWindow = 500)
        val id = m.open(bidi = true, StreamPriority.Default)
        m.write(id, ByteArray(1000), 0, 1000, false)
        assertEquals(500, sendOnce(m)!!.streamLength[0])
        assertNull(sendOnce(m))
        m.events.clear()
        assertTrue(m.onMaxStreamData(id, 2000))
        assertTrue(m.events.any { it is ConnectionEvent.StreamWritable && it.id == id }, "events: ${m.events}")
    }

    @Test fun maxStreamsRaisesStreamsAvailable() {
        // RFC 9000 section 4.6: an open refused at the peer's limit can be retried once MAX_STREAMS raises it
        val m = manager(maxStreams = 1)
        assertTrue(m.open(bidi = true, StreamPriority.Default) >= 0)
        assertEquals(-1L, m.open(bidi = true, StreamPriority.Default))
        m.events.clear()
        assertTrue(m.onMaxStreams(true, 2))
        assertTrue(m.events.any { it is ConnectionEvent.StreamsAvailable && it.bidi }, "events: ${m.events}")
        assertTrue(m.open(bidi = true, StreamPriority.Default) >= 0)
    }

    // ---- final review fix pass ----
    @Test fun lateFrameForRetiredPeerStreamIgnored() {
        val m = manager(TlsRole.Server)
        recv(m, 2, 0, ByteArray(10), fin = true)
        val buf = ByteArray(10)
        assertEquals(10, m.read(2, buf, 0, 10))
        assertEquals(-1, m.read(2, buf, 0, 10))
        assertTrue(!m.isOpen(2), "uni peer stream retired after it was read")
        recv(m, 2, 0, ByteArray(10), fin = true) // a spurious retransmit: ignored, no exception, no new stream (RFC 9000 section 3)
        m.onResetStream(2, 1, 10)
        assertTrue(!m.isOpen(2))
        assertNull(m.takeControlFrame())
    }

    @Test fun lateFrameForRetiredLocalStreamIgnored() {
        val m = manager(TlsRole.Client)
        val id = m.open(bidi = false, StreamPriority.Default)
        m.write(id, ByteArray(10), 0, 10, fin = true)
        val f = sendOnce(m)!!
        m.onFramesAcked(f)
        assertTrue(!m.isOpen(id), "uni send stream retired once FIN was acknowledged")
        m.onStopSending(id, 7)
        m.onMaxStreamData(id, 5000) // late frames for a closed stream are ignored
        assertNull(m.takeControlFrame())
        assertEquals(0x05L, code { m.onMaxStreamData(id + 4, 5000) }) // a local stream we never opened is still STREAM_STATE_ERROR
    }

    /**
     * Review finding 12, RFC 9000 sections 19.4, 19.5, 19.8, 19.10 and 19.13: a frame for the missing half of a unidirectional stream
     * is STREAM_STATE_ERROR also after the stream was closed and retired (it used to be ignored like a late retransmission).
     */
    @Test fun wrongDirectionFrameOnRetiredUniStreamIsStreamStateError() {
        val server = manager(TlsRole.Server)
        recv(server, 2, 0, ByteArray(10), fin = true)
        assertEquals(10, server.read(2, ByteArray(10), 0, 10))
        assertEquals(-1, server.read(2, ByteArray(10), 0, 10))
        assertTrue(!server.isOpen(2), "the client's uni stream is retired")
        val e1 = assertFailsWith<QuicWireException> { server.onMaxStreamData(2, 5000) }
        assertEquals(0x05L, e1.code)
        assertEquals(0x11L, e1.frameType)
        val e2 = assertFailsWith<QuicWireException> { server.onStopSending(2, 7) }
        assertEquals(0x05L, e2.code)
        assertEquals(0x05L, e2.frameType)

        val client = manager(TlsRole.Client)
        val id = client.open(bidi = false, StreamPriority.Default)
        client.write(id, ByteArray(10), 0, 10, fin = true)
        client.onFramesAcked(sendOnce(client)!!)
        assertTrue(!client.isOpen(id), "our uni stream is retired")
        assertEquals(0x05L, code { recv(client, id, 0, ByteArray(1)) })
        val e3 = assertFailsWith<QuicWireException> { client.onResetStream(id, 1, 10) }
        assertEquals(0x05L, e3.code)
        assertEquals(0x04L, e3.frameType)
        val e4 = assertFailsWith<QuicWireException> { client.onStreamDataBlocked(id, 10, client.now, client.smoothedRtt) }
        assertEquals(0x05L, e4.code)
        assertEquals(0x15L, e4.frameType)
    }

    /** Review finding 21, RFC 9000 section 19.19: the Frame Type of a stream error names the frame that caused it. */
    @Test fun unopenedLocalStreamErrorNamesItsFrame() {
        val m = manager(TlsRole.Client)
        assertEquals(0x11L, assertFailsWith<QuicWireException> { m.onMaxStreamData(4, 5000) }.frameType)
        assertEquals(0x05L, assertFailsWith<QuicWireException> { m.onStopSending(4, 1) }.frameType)
        assertEquals(0x04L, assertFailsWith<QuicWireException> { m.onResetStream(4, 1, 0) }.frameType)
    }

    private fun controlKinds(m: StreamManager): List<ControlKind> = generateSequence { m.takeControlFrame() }.map { it.kind }.toList()

    /**
     * Review finding 20, RFC 9000 section 13.3: "An endpoint SHOULD stop sending MAX_STREAM_DATA frames when the receiving part of
     * the stream enters a "Size Known" or "Reset Recvd" state." Reading a stream whose FIN had arrived still raised its window.
     */
    @Test fun noMaxStreamDataOnceFinalSizeIsKnown() {
        val size = QuicConfig.Default.initialStreamWindow.toInt()
        for (fin in listOf(false, true)) {
            val m = manager(TlsRole.Server)
            recv(m, 0, 0, ByteArray(size), fin = fin)
            val buf = ByteArray(size)
            var n = 0
            while (n < size) n += m.read(0, buf, n, size - n).also { check(it > 0) }
            val kinds = controlKinds(m)
            if (fin) {
                assertTrue(ControlKind.MaxStreamData !in kinds, "FIN received: no MAX_STREAM_DATA, got $kinds")
            } else {
                assertTrue(ControlKind.MaxStreamData in kinds, "control: an open stream gets more credit, got $kinds")
            }
        }
    }

    /**
     * Review finding 20, RFC 9000 section 3.2: STOP_SENDING may be sent "in any state where it has not received a RESET_STREAM
     * frame", and has little value once all data arrived; nor is a lost one resent then.
     */
    @Test fun noStopSendingAfterResetOrAllData() {
        val reset = manager(TlsRole.Server)
        recv(reset, 0, 0, ByteArray(10))
        reset.onResetStream(0, 1, 10)
        reset.stopSending(0, 5)
        assertTrue(ControlKind.StopSending !in controlKinds(reset), "after RESET_STREAM")

        val all = manager(TlsRole.Server)
        recv(all, 0, 0, ByteArray(10), fin = true)
        all.stopSending(0, 5)
        assertTrue(ControlKind.StopSending !in controlKinds(all), "after all data arrived")

        val lost = manager(TlsRole.Server)
        recv(lost, 0, 0, ByteArray(10))
        lost.stopSending(0, 5)
        assertTrue(ControlKind.StopSending in controlKinds(lost))
        lost.onResetStream(0, 5, 10) // the peer answers before our STOP_SENDING is declared lost
        lost.onFramesLost(SentFrames().apply { addId(SentFrames.ID_STOP_SENDING, 0, 5) })
        assertTrue(ControlKind.StopSending !in controlKinds(lost), "a lost STOP_SENDING is not resent after RESET_STREAM")
    }

    @Test fun resetByPeerReturnsConnectionCredit() {
        val m = manager(TlsRole.Server)
        recv(m, 0, 0, ByteArray(400_000))
        m.onResetStream(0, 1, 400_000)
        val frames = generateSequence { m.takeControlFrame() }.toList()
        val maxData = frames.firstOrNull { it.kind == ControlKind.MaxData }
        assertNotNull(maxData, "abandoned bytes are credited back to the connection window: $frames")
        // 400 000 > half the window at once doubles it (quic-go's auto-tuning): the limit is 400 000 + 786 432 or + 1 572 864
        assertTrue(maxData.a == 786_432L + 400_000L || maxData.a == 1_572_864L + 400_000L, "limit ${maxData.a}")
    }

    @Test fun stopSendingReturnsConnectionCredit() {
        val m = manager(TlsRole.Server)
        recv(m, 0, 0, ByteArray(400_000))
        m.stopSending(0, 9)
        val frames = generateSequence { m.takeControlFrame() }.toList()
        val maxData = frames.firstOrNull { it.kind == ControlKind.MaxData }
        assertNotNull(maxData, "bytes we will never read are credited back: $frames")
        // 400 000 > half the window at once doubles it (quic-go's auto-tuning): the limit is 400 000 + 786 432 or + 1 572 864
        assertTrue(maxData.a == 786_432L + 400_000L || maxData.a == 1_572_864L + 400_000L, "limit ${maxData.a}")
        recv(m, 0, 400_000, ByteArray(1000)) // later data on the stopped stream is credited as it arrives (no exception, no readable event)
        recv(m, 4, 0, ByteArray(400_000))
        m.stopSending(4, 9) // a second abandoned stream pushes the connection past the next quarter of the (doubled) window
        val later = generateSequence { m.takeControlFrame() }.toList().firstOrNull { it.kind == ControlKind.MaxData }
        assertNotNull(later)
        assertTrue(later.a >= 786_432L + 801_000L, "limit covers every abandoned byte (the window may also have doubled): ${later.a}")
    }

    @Test fun bidiPeerStreamCountsClosedWhenBothHalvesConsumed() {
        val m = manager(TlsRole.Server, peerMaxData = 1L shl 40)
        val m2 =
            StreamManager(
                TlsRole.Server,
                QuicConfig.Default,
                RecvFlowController(786_432, 15_728_640),
                SendFlowController(1L shl 40),
                StreamLimits(TlsRole.Server, 2, 2),
            ).also {
                it.applyPeerParameters(1L shl 30, 1L shl 30, 1L shl 30, 100, 100)
            }
        recv(m2, 0, 0, ByteArray(1))
        m2.write(0, ByteArray(0), 0, 0, fin = true)
        val f = sendOnce(m2)!!
        val buf = ByteArray(4)
        assertEquals(1, m2.read(0, buf, 0, 4))
        recv(m2, 0, 1, ByteArray(0), fin = true)
        assertEquals(-1, m2.read(0, buf, 0, 4))
        assertNull(
            generateSequence {
                m2.takeControlFrame()
            }.toList().firstOrNull { it.kind == ControlKind.MaxStreamsBidi },
            "our FIN is not acknowledged yet",
        )
        m2.onFramesAcked(f)
        val ms = generateSequence { m2.takeControlFrame() }.toList().firstOrNull { it.kind == ControlKind.MaxStreamsBidi }
        assertNotNull(ms, "both halves done: the stream counts as closed")
        assertEquals(3L, ms.a)
        assertTrue(!m2.isOpen(0))
        assertTrue(m.isOpen(0).not())
    }

    @Test fun ackAfterResetDoesNotDoubleCountSendBuffer() {
        val m = manager(TlsRole.Client)
        val id = m.open(bidi = false, StreamPriority.Default)
        m.write(id, ByteArray(1000), 0, 1000, fin = false)
        val f = sendOnce(m)!!
        assertEquals(1000L, m.sendBufferedBytes)
        m.reset(id, 1)
        assertEquals(0L, m.sendBufferedBytes)
        m.onFramesAcked(f)
        assertEquals(0L, m.sendBufferedBytes, "an ACK for a frame of a reset stream must not be subtracted again")
        assertTrue(!m.isOpen(id), "a reset uni send stream is retired")
    }

    @Test fun retransmittedResetStreamKeepsFinalSize() {
        val m = manager(TlsRole.Client)
        val id = m.open(bidi = false, StreamPriority.Default)
        m.write(id, ByteArray(1000), 0, 1000, fin = false)
        sendOnce(m)
        m.reset(id, 3)
        val c = m.takeControlFrame()!!
        assertEquals(ControlKind.ResetStream, c.kind)
        assertEquals(1000L, c.b)
        val lost = SentFrames()
        lost.addId(SentFrames.ID_RESET_STREAM, c.id, c.a, c.b)
        m.releaseControlFrame(c)
        m.onFramesLost(lost)
        val again = m.takeControlFrame()!!
        assertEquals(ControlKind.ResetStream, again.kind)
        assertEquals(3L, again.a)
        assertEquals(1000L, again.b, "final size survives the stream being retired")
    }

    @Test fun peerStreamCountsClosedOnlyWhenConsumed() {
        val m = manager(TlsRole.Server)
        for (k in 0 until 50) recv(m, 2 + 4L * k, 0, ByteArray(1), fin = true) // 50 client uni streams, all data arrived, none read
        assertNull(
            generateSequence {
                m.takeControlFrame()
            }.toList().firstOrNull { it.kind == ControlKind.MaxStreamsUni },
            "unread streams still count against the concurrency limit",
        )
        val buf = ByteArray(8)
        for (k in 0 until 50) {
            val id = 2 + 4L * k
            m.read(id, buf, 0, 8)
            m.read(id, buf, 0, 8)
        }
        val ms = generateSequence { m.takeControlFrame() }.toList().firstOrNull { it.kind == ControlKind.MaxStreamsUni }
        assertNotNull(ms, "MAX_STREAMS once the application consumed them")
        assertEquals(150L, ms.a)
    }
    /** A lost MAX_STREAMS goes out again; a STREAMS_BLOCKED below the limit we granted repeats it. */

    /** A receive half we stopped never reaches a read-to-end state, so the stream was never retired and its MAX_STREAMS credit never returned. Once its final size is known it counts as finished. */
    @Test fun stoppedStreamRetiresOnceFinalSizeIsKnown() {
        val m =
            StreamManager(
                TlsRole.Server,
                QuicConfig.Default,
                RecvFlowController(786_432, 15_728_640),
                SendFlowController(1L shl 40),
                StreamLimits(TlsRole.Server, 2, 2),
            )
        m.applyPeerParameters(1L shl 30, 1L shl 30, 1L shl 30, 100, 100)
        val buf =
            io.kuicksilver.native.PacketBuffer
                .allocate(100)
        try {
            m.onStream(2, 0, buf, 0, 100, false) // client uni stream 2: a body we will not read
            m.stopSending(2, 0x100)
            assertNotNull(m.takeControlFrame(), "STOP_SENDING queued")
            m.onStream(2, 100, buf, 0, 0, true) // the peer's FIN: final size known
            val credit = generateSequence { m.takeControlFrame() }.firstOrNull { it.kind == ControlKind.MaxStreamsUni }
            assertNotNull(credit, "the stopped stream is retired and its credit returned")
            assertEquals(3L, credit.a)
            assertTrue(m.events.any { it is io.kuicksilver.quic.ConnectionEvent.StreamFinished && it.id == 2L }, "StreamFinished(2)")
        } finally {
            buf.close()
        }
    }

    @Test fun lostMaxStreamsIsQueuedAgain() {
        val m =
            StreamManager(
                TlsRole.Server,
                QuicConfig.Default,
                RecvFlowController(786_432, 15_728_640),
                SendFlowController(1L shl 40),
                StreamLimits(TlsRole.Server, 2, 2),
            )
        m.applyPeerParameters(1L shl 30, 1L shl 30, 1L shl 30, 100, 100)
        val f = SentFrames()
        f.flags = SentFrames.MAX_STREAMS_BIDI
        m.onFramesLost(f)
        val c = m.takeControlFrame()
        assertNotNull(c, "MAX_STREAMS queued again")
        assertEquals(ControlKind.MaxStreamsBidi, c.kind)
        assertEquals(2L, c.a, "with the current limit")
        m.onStreamsBlocked(true, 2)
        assertNull(m.takeControlFrame(), "blocked at the limit we granted: nothing new to say")
        m.onStreamsBlocked(true, 1)
        val again = m.takeControlFrame()
        assertNotNull(again)
        assertEquals(ControlKind.MaxStreamsBidi, again.kind)
        assertEquals(2L, again.a)
    }

    @Test fun lostMaxStreamsDoesNotDeadlockLongLivedStreams() {
        // maxBidiStreams = 2: one stream closes, one stays open; the MAX_STREAMS(3) that would let the client open a third is lost
        val p = io.kuicksilver.quic.CorePair(serverQuic = io.kuicksilver.quic.quicConfig { maxBidiStreams = 2 })
        try {
            assertTrue(p.handshake())
            p.runUntil(200.milliseconds) { false }
            val c = p.client
            val a = c.openStream(true)
            val b = c.openStream(true)
            assertEquals(-1L, c.openStream(true), "two streams at most")
            c.writeStream(a, ByteArray(10), 0, 10, true)
            c.writeStream(b, ByteArray(10), 0, 10, false)
            var dropped = false
            p.filterToClient =
                { _, bytes ->
                    val lose =
                        !dropped &&
                            io.kuicksilver.quic
                                .nullOneRttFrames(bytes)
                                ?.any { it is io.kuicksilver.quic.TestFrame.MaxStreams && it.bidi } ==
                            true
                    if (lose) dropped = true
                    !lose
                }
            val buf = ByteArray(64)
            var answered = false
            assertTrue(
                p.runUntil(2.seconds) {
                    val s = p.server!!
                    while (s.readStream(a, buf, 0, buf.size) >
                        0
                    ) {}
                    if (!answered &&
                        s.isStreamOpenForTest(a)
                    ) {
                        s.writeStream(a, ByteArray(0), 0, 0, true)
                        answered = true
                    }
                    dropped
                },
                "the MAX_STREAMS frame was sent and dropped",
            )
            var third = -1L
            val t0 = p.now
            assertTrue(
                p.runUntil(1.seconds) {
                    third = c.openStream(true)
                    third >= 0
                },
                "the client opens a third stream within 1 s of the loss (took ${p.now - t0})",
            )
            assertEquals(8L, third)
        } finally {
            p.close()
        }
    }
}
