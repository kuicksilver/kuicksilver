// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.stream

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.flow.RecvFlowController
import io.kuicksilver.quic.flow.SendFlowController
import io.kuicksilver.quic.flow.StreamLimits
import io.kuicksilver.quic.recovery.SentFrames
import io.kuicksilver.quic.wire.FrameEncoder
import io.kuicksilver.quic.wire.WireWriter
import io.kuicksilver.tls.TlsRole
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

/** Stream manager behaviour the mutation run found untested (each test names the mutated decision it pins). */
class StreamManagerGapsTest {
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
        m.applyPeerParameters(streamWindow, streamWindow, streamWindow, maxStreams, maxStreams)
        return m
    }

    private fun recv(
        m: StreamManager,
        id: Long,
        offset: Long,
        bytes: ByteArray,
        fin: Boolean = false,
    ) {
        val b = PacketBuffer.of(bytes + ByteArray(1))
        try {
            m.onStream(id, offset, b, 0, bytes.size, fin)
        } finally {
            b.close()
        }
    }

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

    private fun controlKinds(m: StreamManager): List<ControlFrame> =
        generateSequence { m.takeControlFrame() }
            .map {
                ControlFrame().also { c ->
                    c.kind = it.kind
                    c.id = it.id
                    c.a = it.a
                    c.b = it.b
                }
            }.toList()

    private fun writables(m: StreamManager) = m.events.filterIsInstance<ConnectionEvent.StreamWritable>().size

    private fun readables(m: StreamManager) = m.events.filterIsInstance<ConnectionEvent.StreamReadable>().size

    /** Released send-buffer bytes raise StreamWritable only for a watched stream, once until the runtime reads the count. */
    @Test fun negative_sendReleaseRaisesOneWritableOnlyForAWatchedStream() {
        for (watched in listOf(false, true)) {
            val m = manager()
            val id = m.open(bidi = false, StreamPriority.Default)
            if (watched) m.watchSend(id)
            m.write(id, ByteArray(100), 0, 100, fin = false)
            val f1 = sendOnce(m)!!
            m.write(id, ByteArray(100), 0, 100, fin = false)
            val f2 = sendOnce(m)!!
            m.write(id, ByteArray(100), 0, 100, fin = false)
            val f3 = sendOnce(m)!!
            m.events.clear()
            m.onFramesAcked(f1)
            m.onFramesAcked(f2)
            assertEquals(if (watched) 1 else 0, writables(m), "watched=$watched: one event until the count is read")
            if (!watched) continue
            assertEquals(200L, m.sendReleased(id))
            m.onFramesAcked(f3)
            assertEquals(2, writables(m), "the count was read: the next release raises it again")
        }
    }

    /**
     * draft-ietf-quic-reliable-stream-reset-11 section 3: "An endpoint MUST NOT send a RESET_STREAM_AT frame unless the peer
     * advertised support using the reset_stream_at transport parameter."
     */
    @Test fun negative_resetAtWithoutThePeersSupportIsAPlainReset() {
        val m = manager()
        val id = m.open(bidi = false, StreamPriority.Default)
        m.write(id, ByteArray(100), 0, 100, fin = false)
        sendOnce(m)
        m.resetAt(id, 7, 50)
        val c = controlKinds(m).single()
        assertEquals(ControlKind.ResetStream, c.kind)
        assertEquals(7L, c.a)
    }

    /** RFC 9000 section 3.2: "Data Recvd" and "Data Read" both mean every byte up to the FIN is (or was) held; "Recv" does not. */
    @Test fun receivedAllIsExactlyDataRecvdOrDataRead() {
        val m = manager(TlsRole.Server)
        recv(m, 0, 0, ByteArray(10), fin = true)
        recv(m, 4, 0, ByteArray(10))
        assertTrue(m.receivedAll(0), "Data Recvd")
        assertFalse(m.receivedAll(4), "Recv")
        assertEquals(10, m.read(0, ByteArray(10), 0, 10))
        assertTrue(m.receivedAll(0), "Data Read")
    }

    /** RFC 9000 section 7.4.1: after an accepted 0-RTT our streams take the server's new limits; the server's streams keep theirs. */
    @Test fun negative_acceptedZeroRttRaisesOnlyOurStreamsLimits() {
        val m = manager(streamWindow = 100)
        val ours = m.open(bidi = true, StreamPriority.Default)
        recv(m, 1, 0, ByteArray(1)) // the server's bidirectional stream 1
        m.raiseLocalSendLimits(1000, 1000)
        assertEquals(1000L, m.sendCredit(ours))
        assertEquals(100L, m.sendCredit(1))
    }

    /** RFC 9000 section 4.1: a stream's send credit is the peer's initial limit for its type and initiator. */
    @Test fun newStreamsTakeTheLimitOfTheirKind() {
        val m = manager()
        m.applyPeerParameters(111, 222, 333, 100, 100)
        assertEquals(222L, m.sendCredit(m.open(bidi = true, StreamPriority.Default)), "initial_max_stream_data_bidi_remote")
        assertEquals(333L, m.sendCredit(m.open(bidi = false, StreamPriority.Default)), "initial_max_stream_data_uni")
        recv(m, 1, 0, ByteArray(1))
        assertEquals(111L, m.sendCredit(1), "initial_max_stream_data_bidi_local for the server's stream")
    }

    /**
     * RFC 9000 section 19.14: "A sender SHOULD send a STREAMS_BLOCKED frame (type=0x16 or 0x17) when it wishes to open a stream but
     * is unable to do so due to the maximum stream limit set by its peer", also when that limit is 0.
     */
    @Test fun streamsBlockedIsSentAtALimitOfZero() {
        val m = manager(maxStreams = 0)
        assertEquals(-1L, m.open(bidi = true, StreamPriority.Default))
        val c = controlKinds(m).single()
        assertEquals(ControlKind.StreamsBlockedBidi, c.kind)
        assertEquals(0L, c.a)
    }

    /**
     * RFC 9001 section 4.6.2: after a rejected 0-RTT the client "MUST reset the state of all streams": every stream of ours is dropped
     * with its buffered and reassembled data, the counts start again from the server's new limits (RFC 9000 section 7.4.1), no
     * earlier refusal to open survives, and the server's streams keep their state (a refused write still learns of room).
     */
    @Test fun negative_rejectedZeroRttResetsEveryStreamOfOursAndNothingElse() {
        val m = manager(maxStreams = 1)
        val a = m.open(bidi = true, StreamPriority.Default)
        val b = m.open(bidi = false, StreamPriority.Default)
        assertEquals(-1L, m.open(bidi = true, StreamPriority.Default))
        assertEquals(-1L, m.open(bidi = false, StreamPriority.Default))
        m.write(a, ByteArray(1000), 0, 1000, fin = false)
        m.write(b, ByteArray(10), 0, 10, fin = false)
        recv(m, 1, 0, ByteArray(1)) // the server's stream survives
        val serverRanges = m.reassemblyRanges
        recv(m, a, 10, ByteArray(5)) // beyond a gap: a reassembly range
        val big = QuicConfig.Default.maxSendBuffer.toInt()
        val accepted = m.write(1, ByteArray(big), 0, big, fin = false)
        assertTrue(accepted < big, "the send buffer refused part of the server stream's write")
        assertTrue(m.reassemblyRanges > serverRanges)
        assertEquals(2, m.resetForRejectedZeroRtt(maxData = 1L shl 40, maxStreamsBidi = 3, maxStreamsUni = 3))
        assertEquals(1, m.zeroRttResets)
        assertEquals(serverRanges, m.reassemblyRanges, "the dropped stream's reassembly ranges went back to the budget")
        assertEquals(accepted.toLong(), m.sendBufferedBytes, "only the server stream's bytes are still buffered")
        m.events.clear()
        val f = sendOnce(m)!!
        assertEquals(listOf(1L), f.streamId.take(f.streamCount), "nothing of a dropped stream is sent")
        m.onFramesAcked(f)
        assertTrue(m.events.any { it is ConnectionEvent.StreamWritable && it.id == 1L }, "the server stream's refused write is woken")
        repeat(3) { assertTrue(m.open(bidi = false, StreamPriority.Default) >= 0, "uni stream ${it + 1} of the new limit") }
        assertTrue(m.onMaxStreams(true, 5))
        assertTrue(m.onMaxStreams(false, 5))
        assertTrue(m.events.none { it is ConnectionEvent.StreamsAvailable }, "no open was refused since the reset")
    }

    /** RFC 9001 section 4.6.2: the dropped streams' unsent bytes never go out after the rejection (the server never saw the streams). */
    @Test fun negative_rejectedZeroRttLeavesNoDroppedStreamScheduled() {
        val m = manager()
        val a = m.open(bidi = true, StreamPriority.Default)
        m.write(a, ByteArray(100), 0, 100, fin = true)
        assertTrue(m.hasStreamData())
        m.resetForRejectedZeroRtt(maxData = 1L shl 40, maxStreamsBidi = 3, maxStreamsUni = 3)
        assertFalse(m.hasStreamData())
        assertEquals(null, sendOnce(m))
    }

    /** A duplicate STREAM frame (also with its FIN) changes nothing a reader can see: no StreamReadable. */
    @Test fun negative_duplicateStreamFrameRaisesNoReadable() {
        val m = manager(TlsRole.Server)
        recv(m, 0, 0, ByteArray(10), fin = true)
        m.events.clear()
        recv(m, 0, 0, ByteArray(10), fin = true)
        recv(m, 0, 0, ByteArray(5))
        assertEquals(0, readables(m))
    }

    /** Each change a reader can act on raises StreamReadable: a filled gap, a FIN beyond a gap, a FIN alone completing unread data. */
    @Test fun readableForGapFillFinBeyondGapAndBareFin() {
        val gap = manager(TlsRole.Server)
        recv(gap, 0, 5, ByteArray(5))
        gap.events.clear()
        recv(gap, 0, 0, ByteArray(5))
        assertEquals(1, readables(gap), "the gap below the highest offset was filled")

        val finBeyondGap = manager(TlsRole.Server)
        recv(finBeyondGap, 0, 5, ByteArray(5))
        finBeyondGap.events.clear()
        recv(finBeyondGap, 0, 10, ByteArray(0), fin = true)
        assertEquals(1, readables(finBeyondGap), "a FIN with nothing readable")

        val bareFin = manager(TlsRole.Server)
        recv(bareFin, 0, 0, ByteArray(10))
        bareFin.events.clear()
        recv(bareFin, 0, 10, ByteArray(0), fin = true)
        assertEquals(1, readables(bareFin), "the FIN alone makes the unread stream whole")
    }

    /**
     * RFC 9000 section 3.5: after STOP_SENDING nothing reads the stream, so the bytes that still arrive go straight back to the
     * connection window (MAX_DATA follows), and a duplicate of them raises no StreamReadable.
     */
    @Test fun bytesForAStoppedStreamReturnConnectionCredit() {
        val m = manager(TlsRole.Server)
        recv(m, 0, 0, ByteArray(1))
        m.stopSending(0, 3)
        controlKinds(m)
        m.events.clear()
        recv(m, 0, 1, ByteArray(300_000))
        assertTrue(controlKinds(m).any { it.kind == ControlKind.MaxData }, "300 000 abandoned bytes credit the connection")
        m.events.clear()
        recv(m, 0, 1, ByteArray(300_000))
        assertEquals(0, readables(m), "a duplicate on a stopped stream")
    }

    /**
     * draft-ietf-quic-reliable-stream-reset-11 section 5.1: once the reliable bytes were delivered the reset reaches the
     * application, and the rest of the final size goes back to the connection window; with nothing readable yet no
     * StreamReadable is raised.
     */
    @Test fun resetStreamAtSurfacesOnceTheReliableBytesWereRead() {
        val m = manager(TlsRole.Server)
        recv(m, 0, 0, ByteArray(100))
        assertEquals(100, m.read(0, ByteArray(100), 0, 100))
        controlKinds(m)
        m.events.clear()
        m.onResetStreamAt(0, 9, 400_000, 100)
        val reset = m.events.filterIsInstance<ConnectionEvent.StreamReset>().single()
        assertEquals(9L, reset.code)
        assertTrue(reset.afterData)
        assertTrue(controlKinds(m).any { it.kind == ControlKind.MaxData }, "the 399 900 bytes past the reliable size credit the connection")

        val nothingYet = manager(TlsRole.Server)
        nothingYet.onResetStreamAt(0, 9, 1000, 500)
        assertEquals(0, readables(nothingYet), "no reliable byte arrived yet")
    }

    private val t0 = TimeMark(1_000_000_000L)
    private val srtt = 10.milliseconds
    private val bufferSize = QuicConfig.Default.maxSendBuffer.toInt()

    private fun writablesOf(
        m: StreamManager,
        id: Long,
    ) = m.events.count { it is ConnectionEvent.StreamWritable && it.id == id }

    /** Room freed in the shared send buffer by STOP_SENDING, a reset or RESET_STREAM_AT wakes a writer the buffer refused. */
    @Test fun freedSendBufferWakesRefusedWriters() {
        for (how in listOf("stop", "reset", "resetAt")) {
            val m = manager()
            m.peerResetStreamAt = true
            val a = m.open(bidi = true, StreamPriority.Default)
            val b = m.open(bidi = true, StreamPriority.Default)
            m.write(b, ByteArray(1000), 0, 1000, fin = false)
            assertTrue(m.write(a, ByteArray(bufferSize), 0, bufferSize, fin = false) < bufferSize)
            m.events.clear()
            when (how) {
                "stop" -> m.onStopSending(b, 1)
                "reset" -> m.reset(b, 1)
                else -> m.resetAt(b, 1, 0)
            }
            assertEquals(1, writablesOf(m, a), how)
        }
    }

    /**
     * A write takes no byte past the peer's credit for the stream or the connection (RFC 9000 section 4.1), as quinn's
     * `write_limit`: a stream whose peer stops reading it without STOP_SENDING (Firefox 161 after a WebTransport
     * `reader.cancel`) holds only bytes the peer may take, never the shared send buffer the other streams need. Before, its
     * writer filled the whole buffer and no other stream of the connection could write until that stream ended. The refused
     * writer says it is blocked (STREAM_DATA_BLOCKED once its credit went out, section 19.13) and wakes on MAX_STREAM_DATA.
     */
    @Test fun negative_aStreamWithoutCreditTakesNoRoomFromTheOthers() {
        val m = manager(streamWindow = 1000)
        val a = m.open(bidi = true, StreamPriority.Default)
        val b = m.open(bidi = true, StreamPriority.Default)
        assertEquals(1000, m.write(a, ByteArray(bufferSize), 0, bufferSize, fin = false), "its credit, not the buffer")
        assertEquals(1000L, m.sendBufferedBytes)
        assertEquals(0, m.write(a, ByteArray(10), 0, 10, fin = false))
        assertEquals(1000, m.write(b, ByteArray(bufferSize), 0, bufferSize, fin = false), "another stream writes its credit")
        assertTrue(
            generateSequence { m.takeControlFrame() }.none { it.kind == ControlKind.StreamDataBlocked },
            "nothing blocked yet: the credit has not gone out",
        )
        @Suppress("ControlFlowWithEmptyBody")
        while (sendOnce(m) != null) {
        }
        val blocked = generateSequence { m.takeControlFrame() }.filter { it.kind == ControlKind.StreamDataBlocked }.map { it.id }.toSet()
        assertEquals(setOf(a, b), blocked, "STREAM_DATA_BLOCKED once each stream's credit went out")
        m.events.clear()
        assertTrue(m.onMaxStreamData(a, 5000))
        assertEquals(1, writablesOf(m, a), "the refused writer learns of the credit")
        assertEquals(0, writablesOf(m, b))
        assertEquals(4000, m.write(a, ByteArray(bufferSize), 0, bufferSize, fin = false))
        // a FIN alone always goes
        assertEquals(0, m.write(b, ByteArray(0), 0, 0, fin = true))
        assertNull(m.invariantViolationForTest())
    }

    /**
     * The connection's credit counts too (quinn's `write_limit`): what the streams hold unsent never goes past MAX_DATA, so a
     * stream within its own credit cannot fill the buffer while the connection is blocked. The writer refused for it gets
     * DATA_BLOCKED once the credit went out, and MAX_DATA wakes every refused writer, the most urgent first (RFC 9218).
     */
    @Test fun negative_writesTakeNoBytePastTheConnectionsCredit() {
        val m = manager(peerMaxData = 1500, streamWindow = 100_000)
        val low = m.open(bidi = true, StreamPriority(urgency = 6, incremental = false))
        val high = m.open(bidi = true, StreamPriority(urgency = 1, incremental = false))
        assertEquals(1000, m.write(low, ByteArray(1000), 0, 1000, fin = false))
        assertEquals(500, m.write(high, ByteArray(1000), 0, 1000, fin = false), "the connection's 1500, less the 1000 unsent")
        assertEquals(0, m.write(low, ByteArray(1000), 0, 1000, fin = false))
        @Suppress("ControlFlowWithEmptyBody")
        while (sendOnce(m) != null) {
        }
        assertEquals(
            listOf(1500L),
            generateSequence { m.takeControlFrame() }.filter { it.kind == ControlKind.DataBlocked }.map { it.a }.toList(),
        )
        m.events.clear()
        assertTrue(m.onMaxData(10_000))
        val woken = m.events.filterIsInstance<ConnectionEvent.StreamWritable>().map { it.id }
        assertEquals(listOf(high, low), woken, "each refused writer once, the most urgent first")
        assertNull(m.invariantViolationForTest())
    }

    /** RESET_STREAM_AT keeps its reliable bytes unsent within the stream's and the connection's credit: they stay counted. */
    @Test fun resetAtKeepsItsReliableBytesCounted() {
        val m = manager(peerMaxData = 1000, streamWindow = 100_000)
        m.peerResetStreamAt = true
        val a = m.open(bidi = false, StreamPriority.Default)
        val b = m.open(bidi = false, StreamPriority.Default)
        assertEquals(1000, m.write(a, ByteArray(5000), 0, 5000, fin = false))
        m.resetAt(a, 1, 600)
        assertEquals(400, m.write(b, ByteArray(5000), 0, 5000, fin = false), "the 600 reliable bytes still take the connection's credit")
        assertNull(m.invariantViolationForTest())
    }

    /** A group leaves nothing behind once its streams retired: the manager drops it with the last one (review 3). */
    @Test fun negative_groupsLeaveNothingBehind() {
        val m = manager()
        val ids = List(3) { m.open(bidi = false, StreamPriority.Default) }
        m.setGroup(ids[0], 100)
        m.setGroup(ids[1], 100)
        m.setGroup(ids[2], 200)
        for (id in ids) m.write(id, ByteArray(2400), 0, 2400, fin = true)
        val sent = generateSequence { sendOnce(m) }.toList()
        for (f in sent) m.onFramesAcked(f)
        assertEquals(0, m.groupCountForTest)
        assertNull(m.invariantViolationForTest())
    }

    /**
     * A group whose members are both incremental and non-incremental is still one participant of its level: one turn per
     * round, its two kinds of members taking turns within it (review 3: it had one token per kind, so two turns).
     */
    @Test fun negative_aMixedGroupTakesOneTurnPerRound() {
        val m = manager()
        val a1 = m.open(bidi = false, StreamPriority.Default)
        val a2 = m.open(bidi = false, StreamPriority.Default)
        val b = m.open(bidi = false, StreamPriority.Default)
        m.setGroup(a1, 100)
        m.setGroup(a2, 100)
        m.setGroup(b, 200)
        for (id in listOf(a1, a2, b)) m.write(id, ByteArray(4800), 0, 4800, fin = false)
        m.setPriority(a2, StreamPriority(3, true))
        val order = generateSequence { sendOnce(m) }.map { it.streamId[0] }.toList()
        assertEquals(listOf(b, b, b, b), order.take(8).filterIndexed { k, _ -> k % 2 == 1 }, "$order")
        assertEquals(setOf(a1, a2), order.take(8).filterIndexed { k, _ -> k % 2 == 0 }.toSet(), "$order")
        assertEquals(15, order.size) // 4800 bytes are five frames of a 1200-byte packet each
    }

    /** A tunnel keeps its own turn: it never joins a group, and one marked while in a group leaves it. */
    @Test fun negative_aTunnelNeverJoinsAGroup() {
        val m = manager()
        val t = m.open(bidi = false, StreamPriority.Default)
        val u = m.open(bidi = false, StreamPriority.Default)
        m.markTunnel(t)
        m.setGroup(t, 100)
        assertEquals(0, m.groupCountForTest)
        m.setGroup(u, 100)
        m.write(u, ByteArray(2400), 0, 2400, fin = false)
        m.markTunnel(u)
        assertEquals(0, m.groupCountForTest)
        assertEquals(3, generateSequence { sendOnce(m) }.count())
        assertNull(m.invariantViolationForTest())
    }

    /**
     * Scheduling groups (WebTransport sessions; draft-ietf-webtrans-http3-16 section 8, unchanged in -17 per the project's
     * notes): the groups of one urgency take turns frame by frame however their streams' ids lie, a chosen deviation from
     * RFC 9218 section 10's id order between sessions, and RFC 9218's order holds within a group (non-incremental streams
     * by ascending id). Without groups the three streams went strictly by id: a1, a1, a1, a2, ..., b1 last.
     */
    @Test fun negative_groupsOfOneUrgencyTakeTurnsAndKeepTheirOrderWithin() {
        val m = manager()
        val a1 = m.open(bidi = false, StreamPriority.Default)
        val a2 = m.open(bidi = false, StreamPriority.Default)
        val b1 = m.open(bidi = false, StreamPriority.Default)
        m.setGroup(a1, 100)
        m.setGroup(a2, 100)
        m.setGroup(b1, 200)
        for (id in listOf(a1, a2, b1)) assertEquals(2400, m.write(id, ByteArray(2400), 0, 2400, fin = false))
        val order = generateSequence { sendOnce(m) }.map { it.streamId[0] }.toList()
        assertEquals(listOf(a1, b1, a1, b1, a1, b1, a2, a2, a2), order)
        // a stream that retires leaves its group, and the last one takes the group with it
        assertEquals(2, m.groupCountForTest)
        for (id in listOf(a1, a2, b1)) m.reset(id, 0)
        assertNull(m.invariantViolationForTest())
    }

    /** RFC 9000 section 3.1: STOP_SENDING moves our send-only stream to "Reset Sent", where nothing is left of it: it is retired. */
    @Test fun stopSendingRetiresOurSendOnlyStream() {
        val m = manager()
        val id = m.open(bidi = false, StreamPriority.Default)
        m.write(id, ByteArray(10), 0, 10, fin = false)
        sendOnce(m)
        m.onStopSending(id, 3)
        assertFalse(m.isOpen(id))
    }

    /** MAX_STREAM_DATA: true when it raised the limit or names a retired stream, false when it changed nothing (a glitch). */
    @Test fun maxStreamDataReportsWhetherItChangedAnything() {
        val m = manager(streamWindow = 100)
        val id = m.open(bidi = false, StreamPriority.Default)
        m.events.clear()
        assertFalse(m.onMaxStreamData(id, 50))
        assertTrue(m.onMaxStreamData(id, 200))
        assertEquals(0, writables(m), "nothing was waiting for the credit")
        val gone = m.open(bidi = false, StreamPriority.Default)
        m.reset(gone, 1)
        assertFalse(m.isOpen(gone))
        assertTrue(m.onMaxStreamData(gone, 10), "a frame for a retired stream is no glitch")
    }

    /** MAX_DATA wakes each stream that waited for connection credit once, and only those still waiting for it. */
    @Test fun maxDataWakesConnectionBlockedStreamsOnce() {
        val m = manager(peerMaxData = 100, streamWindow = 150)
        val a = m.open(bidi = false, StreamPriority.Default)
        assertEquals(100, m.write(a, ByteArray(300), 0, 300, fin = false), "the connection's credit, no more")
        assertEquals(100, sendOnce(m)!!.streamLength[0])
        assertEquals(null, sendOnce(m))
        assertEquals(0, m.write(a, ByteArray(1), 0, 1, fin = false))
        assertEquals(null, sendOnce(m))
        m.events.clear()
        assertTrue(m.onMaxData(1000))
        assertEquals(1, writablesOf(m, a), "one wake-up however often it found the connection blocked")
        assertEquals(50, m.write(a, ByteArray(300), 0, 300, fin = false), "now its own 150")
        assertEquals(50, sendOnce(m)!!.streamLength[0])
        assertEquals(null, sendOnce(m), "now blocked by its own limit")
        m.events.clear()
        assertTrue(m.onMaxData(2000))
        assertEquals(0, writablesOf(m, a), "not waiting for connection credit any more")
    }

    /** StreamsAvailable follows a refused open, once, and only for a MAX_STREAMS that raised the limit. */
    @Test fun negative_streamsAvailableOnlyAfterARefusalAndOnlyOnce() {
        val m = manager(maxStreams = 1)
        m.open(bidi = true, StreamPriority.Default)
        assertEquals(-1L, m.open(bidi = true, StreamPriority.Default))
        m.events.clear()
        assertFalse(m.onMaxStreams(true, 1))
        assertEquals(0, m.events.count { it is ConnectionEvent.StreamsAvailable }, "the limit did not grow")
        assertTrue(m.onMaxStreams(true, 2))
        assertTrue(m.onMaxStreams(true, 3))
        assertEquals(1, m.events.count { it is ConnectionEvent.StreamsAvailable })
    }

    /**
     * RFC 9000 section 4.6 (13.3): "An endpoint SHOULD stop sending MAX_STREAM_DATA frames when the receiving part of the stream
     * enters a "Size Known" or "Reset Recvd" state", also for a final size of 0.
     */
    @Test fun negative_noMaxStreamDataForAStreamWithFinalSizeZero() {
        val m = manager(TlsRole.Server)
        recv(m, 0, 0, ByteArray(0), fin = true)
        controlKinds(m)
        m.onStreamDataBlocked(0, 0, t0, srtt)
        assertTrue(controlKinds(m).none { it.kind == ControlKind.MaxStreamData })
    }

    /** A DATA_BLOCKED repeat is answered again once a full RTT passed since the last one (one answer per RTT, RFC 9000 section 4.1). */
    @Test fun dataBlockedIsAnsweredAgainAfterOneRtt() {
        val m = manager(TlsRole.Server)
        m.onDataBlocked(0, t0, srtt)
        assertEquals(1, controlKinds(m).count { it.kind == ControlKind.MaxData })
        m.onDataBlocked(0, t0 + srtt, srtt)
        assertEquals(1, controlKinds(m).count { it.kind == ControlKind.MaxData }, "one RTT later")
    }

    /** A MAX_STREAMS queued again leaves the other queued control frames as they are. */
    @Test fun negative_maxStreamsRequeueTouchesNoOtherFrame() {
        val m = manager(TlsRole.Server)
        m.onDataBlocked(0, t0, srtt)
        m.onStreamsBlocked(true, 0)
        val frames = controlKinds(m)
        assertEquals(786_432L, frames.single { it.kind == ControlKind.MaxData }.a)
        assertEquals(100L, frames.single { it.kind == ControlKind.MaxStreamsBidi }.a)
    }

    /** RFC 9000 section 3.1: after RESET_STREAM the application cannot write to the stream again. */
    @Test fun negative_writeAfterResetFails() {
        val m = manager()
        m.peerResetStreamAt = true
        val a = m.open(bidi = true, StreamPriority.Default)
        m.reset(a, 1)
        assertFailsWith<IllegalStateException> { m.write(a, ByteArray(1), 0, 1, fin = false) }
        val b = m.open(bidi = true, StreamPriority.Default)
        m.write(b, ByteArray(10), 0, 10, fin = false)
        m.resetAt(b, 1, 5)
        assertFailsWith<IllegalStateException> { m.write(b, ByteArray(1), 0, 1, fin = false) }
    }

    /** A write the shared send buffer cut short gets exactly one StreamWritable once acknowledgements free room; a full write none. */
    @Test fun refusedWriterGetsOneWritablePerRefusal() {
        val m = manager()
        val a = m.open(bidi = true, StreamPriority.Default)
        m.write(a, ByteArray(100), 0, 100, fin = false)
        m.onFramesAcked(sendOnce(m)!!)
        assertEquals(0, writablesOf(m, a), "nothing was refused")
        assertEquals(bufferSize, m.write(a, ByteArray(bufferSize + 1), 0, bufferSize + 1, fin = false))
        assertEquals(0, m.write(a, ByteArray(10), 0, 10, fin = true), "a full buffer refuses the rest, FIN included")
        val f1 = sendOnce(m)!!
        val f2 = sendOnce(m)!!
        m.events.clear()
        m.onFramesAcked(f2)
        assertEquals(0, writablesOf(m, a), "the out-of-order ACK released nothing")
        m.onFramesAcked(f1)
        assertEquals(1, writablesOf(m, a))
        assertTrue(m.write(a, ByteArray(bufferSize), 0, bufferSize, fin = false) < bufferSize)
        m.onFramesAcked(sendOnce(m)!!)
        assertEquals(2, writablesOf(m, a), "the second refusal is woken too")
        m.onFramesAcked(sendOnce(m)!!)
        assertEquals(2, writablesOf(m, a), "and only once")

        val r = manager()
        val c = r.open(bidi = true, StreamPriority.Default)
        assertTrue(r.write(c, ByteArray(bufferSize + 1), 0, bufferSize + 1, fin = false) < bufferSize + 1)
        r.events.clear()
        r.reset(c, 1)
        assertEquals(0, writablesOf(r, c), "a reset stream is not woken")
    }

    /** RFC 9000 section 4.5: each half's final size is reported once, also a final size of 0. */
    @Test fun negative_finalSizeZeroIsReportedOnce() {
        val m = manager()
        val id = m.open(bidi = false, StreamPriority.Default)
        m.write(id, ByteArray(0), 0, 0, fin = true)
        sendOnce(m)
        m.onStopSending(id, 1)
        assertEquals(1, m.events.count { it is ConnectionEvent.StreamFinalSize && it.sending })
        val r = manager(TlsRole.Server)
        recv(r, 0, 0, ByteArray(0), fin = true)
        r.onResetStream(0, 1, 0)
        assertEquals(1, r.events.count { it is ConnectionEvent.StreamFinalSize && !it.sending })
    }

    /** RFC 9000 section 3.1: "A sender MUST NOT send a STREAM or STREAM_DATA_BLOCKED frame for a stream in the "Reset Sent" state". */
    @Test fun negative_noStreamFrameAfterReset() {
        val m = manager()
        val a = m.open(bidi = true, StreamPriority.Default)
        m.write(a, ByteArray(100), 0, 100, fin = false)
        m.reset(a, 1)
        assertTrue(m.isOpen(a), "the receiving half keeps the stream")
        assertEquals(null, sendOnce(m))
    }

    /**
     * draft-ietf-quic-reliable-stream-reset-11 section 5.2: "the initiator MUST NOT change the Application Error Code in subsequent
     * RESET_STREAM_AT or RESET_STREAM frames": a second resetAt is ignored, and a later RESET_STREAM carries the first code.
     */
    @Test fun negative_secondResetAtKeepsTheFirstCode() {
        val m = manager()
        m.peerResetStreamAt = true
        val id = m.open(bidi = false, StreamPriority.Default)
        m.write(id, ByteArray(100), 0, 100, fin = false)
        sendOnce(m)
        m.resetAt(id, 5, 80)
        m.resetAt(id, 6, 40)
        m.reset(id, 9)
        val frames = controlKinds(m)
        assertEquals(listOf(5L), frames.filter { it.kind == ControlKind.ResetStreamAt }.map { it.a })
        assertEquals(listOf(5L), frames.filter { it.kind == ControlKind.ResetStream }.map { it.a })
    }

    /** Bytes RESET_STREAM_AT drops from the buffer count as released for a watched stream. */
    @Test fun resetAtReleaseRaisesWritableForAWatchedStream() {
        val m = manager()
        m.peerResetStreamAt = true
        val id = m.open(bidi = false, StreamPriority.Default)
        m.watchSend(id)
        m.write(id, ByteArray(100), 0, 100, fin = false)
        sendOnce(m)
        m.events.clear()
        m.resetAt(id, 5, 0)
        assertEquals(1, writablesOf(m, id))
    }

    /** RESET_STREAM_AT whose reliable bytes were all acknowledged already ends the stream at once ("Reset Sent", retired). */
    @Test fun resetAtAfterTheReliableBytesWereAcknowledgedRetiresTheStream() {
        val m = manager()
        m.peerResetStreamAt = true
        val id = m.open(bidi = false, StreamPriority.Default)
        m.write(id, ByteArray(100), 0, 100, fin = false)
        m.onFramesAcked(sendOnce(m)!!)
        m.resetAt(id, 5, 100)
        assertEquals(listOf(ControlKind.ResetStreamAt), controlKinds(m).map { it.kind })
        assertFalse(m.isOpen(id))
    }

    /** RFC 9000 section 3.5: after STOP_SENDING nothing reads the stream: its buffered bytes are dropped (reassembly budget back). */
    @Test fun stopSendingDropsBufferedBytes() {
        val m = manager(TlsRole.Server)
        recv(m, 0, 5, ByteArray(10))
        assertTrue(m.reassemblyRanges > 0)
        m.stopSending(0, 1)
        assertEquals(0, m.reassemblyRanges)
    }

    /** RFC 9218 section 4: a stream made less urgent waits behind the more urgent ones, also when it was the most urgent. */
    @Test fun priorityChangeOfTheMostUrgentStreamTakesEffect() {
        val m = manager()
        val a = m.open(bidi = true, StreamPriority.Critical)
        val b = m.open(bidi = true, StreamPriority.Default)
        m.write(a, ByteArray(100), 0, 100, fin = false)
        m.write(b, ByteArray(100), 0, 100, fin = false)
        m.setPriority(a, StreamPriority(7))
        assertEquals(b, sendOnce(m)!!.streamId[0])
    }

    /** RFC 9218 section 4: incremental streams of one urgency share the frames in turn. */
    @Test fun incrementalStreamsTakeTurns() {
        val m = manager()
        val p = StreamPriority(3, incremental = true)
        val a = m.open(bidi = true, p)
        val b = m.open(bidi = true, p)
        m.write(a, ByteArray(5000), 0, 5000, fin = false)
        m.write(b, ByteArray(5000), 0, 5000, fin = false)
        val ids = List(4) { sendOnce(m)!!.streamId[0] }
        assertEquals(setOf(a, b), ids.toSet(), "frames $ids")
    }

    /** A packet without room for a STREAM frame's bytes sends nothing and keeps the stream scheduled for the next one. */
    @Test fun noRoomForBytesKeepsTheStreamScheduled() {
        val m = manager()
        val id = m.open(bidi = false, StreamPriority.Default)
        m.write(id, ByteArray(100), 0, 100, fin = false)
        val n = FrameEncoder.streamOverhead(id, 0, 3)
        assertEquals(3, n, "the frame header alone fills 3 bytes")
        val b = PacketBuffer.allocate(n)
        try {
            assertFalse(m.writeStreamFrame(WireWriter(b, 0, n), SentFrames()))
        } finally {
            b.close()
        }
        assertEquals(100, sendOnce(m)!!.streamLength[0])
        assertTrue(controlKinds(m).isEmpty(), "no blocked report")
    }

    /**
     * RFC 9000 sections 19.12/19.13: "A sender SHOULD send a STREAM_DATA_BLOCKED frame (type=0x15) when it wishes to send data but
     * is unable to do so due to stream-level flow control" (and DATA_BLOCKED likewise), also at a limit of 0.
     */
    @Test fun blockedFramesAreSentAtALimitOfZero() {
        val s = manager(streamWindow = 0)
        val a = s.open(bidi = false, StreamPriority.Default)
        s.write(a, ByteArray(10), 0, 10, fin = false)
        assertEquals(null, sendOnce(s))
        assertEquals(listOf(ControlKind.StreamDataBlocked to 0L), controlKinds(s).map { it.kind to it.a })
        val c = manager(peerMaxData = 0)
        val b = c.open(bidi = false, StreamPriority.Default)
        c.write(b, ByteArray(10), 0, 10, fin = false)
        assertEquals(null, sendOnce(c))
        assertEquals(listOf(ControlKind.DataBlocked to 0L), controlKinds(c).map { it.kind to it.a })
    }

    /** A stream whose unsent bytes RESET_STREAM_AT dropped no longer counts as blocked (no STREAM_DATA_BLOCKED is repeated for it). */
    @Test fun negative_streamBlockedEndsWhenNothingIsLeftToSend() {
        val m = manager(streamWindow = 100)
        m.peerResetStreamAt = true
        val id = m.open(bidi = false, StreamPriority.Default)
        m.write(id, ByteArray(150), 0, 150, fin = false)
        sendOnce(m)
        assertEquals(null, sendOnce(m))
        assertTrue(m.flowBlocked())
        m.resetAt(id, 5, 100)
        assertFalse(m.flowBlocked())
    }

    /** An ACK that releases no buffered bytes (the bytes below it are still unacknowledged) raises no StreamWritable. */
    @Test fun negative_ackReleasingNothingRaisesNoWritable() {
        val m = manager()
        val id = m.open(bidi = false, StreamPriority.Default)
        m.watchSend(id)
        m.write(id, ByteArray(3000), 0, 3000, fin = false)
        val f1 = sendOnce(m)!!
        val f2 = sendOnce(m)!!
        m.events.clear()
        m.onFramesAcked(f2)
        assertEquals(0, writablesOf(m, id))
        m.onFramesAcked(f1)
        assertEquals(1, writablesOf(m, id))
    }

    /** RFC 9000 section 4.6: closing a stream we opened never raises the peer's stream limit (only peer streams count). */
    @Test fun negative_closingOurStreamGrantsThePeerNoStreams() {
        val m = manager(maxStreams = 1)
        val id = m.open(bidi = true, StreamPriority.Default)
        m.write(id, ByteArray(10), 0, 10, fin = true)
        m.onFramesAcked(sendOnce(m)!!)
        recv(m, id, 0, ByteArray(5), fin = true)
        assertEquals(5, m.read(id, ByteArray(5), 0, 5))
        assertEquals(-1, m.read(id, ByteArray(5), 0, 5))
        assertFalse(m.isOpen(id))
        assertEquals(1L, m.peerMaxStreamsGranted(true))
        assertTrue(controlKinds(m).none { it.kind == ControlKind.MaxStreamsBidi })
    }

    /** A control frame pushed back (it did not fit the packet) is the next one taken. */
    @Test fun pushedBackControlFrameComesFirst() {
        val m = manager(TlsRole.Server)
        m.onDataBlocked(0, t0, srtt)
        m.onStreamsBlocked(true, 0)
        val c = m.takeControlFrame()!!
        val kind = c.kind
        m.pushBackControlFrame(c)
        assertEquals(kind, m.takeControlFrame()!!.kind)
    }

    /**
     * RFC 9000 section 13.3: "a request to cancel stream transmission, as encoded in a STOP_SENDING frame, is sent until the
     * receiving part of the stream enters either a "Data Recvd" or "Reset Recvd" state"; MAX_STREAM_DATA stops once the final
     * size is known (section 4.5: also when it is 0).
     */
    @Test fun negative_lostStopSendingAndMaxStreamDataGoAgainOnlyWhileUseful() {
        val m = manager(TlsRole.Server)
        recv(m, 0, 0, ByteArray(1))
        m.stopSending(0, 4)
        assertEquals(listOf(ControlKind.StopSending), controlKinds(m).map { it.kind })
        val lost = SentFrames()
        lost.addId(SentFrames.ID_STOP_SENDING, 0, 4)
        m.onFramesLost(lost)
        assertEquals(listOf(ControlKind.StopSending to 4L), controlKinds(m).map { it.kind to it.a })

        recv(m, 4, 0, ByteArray(0), fin = true)
        controlKinds(m)
        val lostMax = SentFrames()
        lostMax.addId(SentFrames.ID_MAX_STREAM_DATA, 4, 1000)
        m.onFramesLost(lostMax)
        assertTrue(controlKinds(m).isEmpty(), "final size 0 is known: no MAX_STREAM_DATA")
    }

    /** A lost STREAM_DATA_BLOCKED goes again only while data still waits at that limit (RFC 9000 section 3.1 after a reset). */
    @Test fun negative_lostStreamDataBlockedWithNothingLeftToSendIsDropped() {
        val m = manager(streamWindow = 100)
        m.peerResetStreamAt = true
        val id = m.open(bidi = false, StreamPriority.Default)
        m.write(id, ByteArray(150), 0, 150, fin = false)
        sendOnce(m)
        assertEquals(null, sendOnce(m))
        assertEquals(listOf(ControlKind.StreamDataBlocked), controlKinds(m).map { it.kind })
        m.resetAt(id, 5, 100)
        controlKinds(m)
        val lost = SentFrames()
        lost.addId(SentFrames.ID_STREAM_DATA_BLOCKED, id, 100)
        m.onFramesLost(lost)
        assertTrue(controlKinds(m).none { it.kind == ControlKind.StreamDataBlocked })
    }

    /** DATA_BLOCKED and STREAMS_BLOCKED go again only when the lost packet carried them, and at a limit of 0 too. */
    @Test fun negative_lostConnectionBlockedFramesGoAgainOnlyWhenTheyWereLost() {
        val m = manager(peerMaxData = 0, maxStreams = 0)
        assertEquals(-1L, m.open(bidi = true, StreamPriority.Default))
        assertEquals(-1L, m.open(bidi = false, StreamPriority.Default))
        val c = manager(peerMaxData = 0)
        val id = c.open(bidi = false, StreamPriority.Default)
        c.write(id, ByteArray(10), 0, 10, fin = false)
        assertEquals(null, sendOnce(c))
        controlKinds(m)
        controlKinds(c)
        m.onConnectionFramesLost(SentFrames())
        c.onConnectionFramesLost(SentFrames())
        assertTrue(controlKinds(m).isEmpty())
        assertTrue(controlKinds(c).isEmpty(), "nothing blocked-related was lost")
        val bidiLost = SentFrames().also { it.flags = SentFrames.STREAMS_BLOCKED_BIDI }
        m.onConnectionFramesLost(bidiLost)
        assertEquals(listOf(ControlKind.StreamsBlockedBidi to 0L), controlKinds(m).map { it.kind to it.a })
        val uniLost = SentFrames().also { it.flags = SentFrames.STREAMS_BLOCKED_UNI }
        m.onConnectionFramesLost(uniLost)
        assertEquals(listOf(ControlKind.StreamsBlockedUni to 0L), controlKinds(m).map { it.kind to it.a })
        c.onConnectionFramesLost(SentFrames().also { it.flags = SentFrames.DATA_BLOCKED })
        assertEquals(listOf(ControlKind.DataBlocked to 0L), controlKinds(c).map { it.kind to it.a })
    }

    /** The size the packet builder reserves for a stream control frame is the size the frame is written with (never less). */
    @Test fun controlOverheadIsTheWrittenSize() {
        val m = manager()
        val b = PacketBuffer.allocate(64)
        try {
            fun size(write: (WireWriter) -> Unit): Int = WireWriter(b, 0, 64).also(write).pos

            fun frame(
                kind: ControlKind,
                id: Long,
                a: Long,
                bb: Long = 0,
                cc: Long = 0,
            ) = ControlFrame().also {
                it.kind = kind
                it.id = id
                it.a = a
                it.b = bb
                it.c = cc
            }
            val id = 1L shl 20
            val big = 1L shl 40
            assertEquals(size { FrameEncoder.maxStreamData(it, id, big) }, m.controlOverhead(frame(ControlKind.MaxStreamData, id, big)))
            assertEquals(size { FrameEncoder.stopSending(it, id, big) }, m.controlOverhead(frame(ControlKind.StopSending, id, big)))
            assertEquals(size { FrameEncoder.resetStream(it, id, 70, big) }, m.controlOverhead(frame(ControlKind.ResetStream, id, 70, big)))
            assertEquals(
                size { FrameEncoder.resetStreamAt(it, id, 70, big, 20_000) },
                m.controlOverhead(frame(ControlKind.ResetStreamAt, id, 70, big, 20_000)),
            )
        } finally {
            b.close()
        }
    }
}
