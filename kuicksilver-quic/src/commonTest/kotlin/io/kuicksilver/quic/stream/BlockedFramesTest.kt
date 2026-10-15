// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.flow.RecvFlowController
import io.kuicksilver.quic.flow.SendFlowController
import io.kuicksilver.quic.flow.StreamLimits
import io.kuicksilver.quic.recovery.SentFrames
import io.kuicksilver.quic.wire.WireWriter
import io.kuicksilver.tls.TlsRole
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

/**
 * DATA_BLOCKED / STREAM_DATA_BLOCKED / STREAMS_BLOCKED (RFC 9000 sections 4.1, 4.6, 19.12–19.14): a blocked sender reports each
 * limit once and again when that report is lost; a receiver that already granted more answers a stale report with the current
 * MAX_DATA / MAX_STREAM_DATA at once, at most once per RTT per connection or stream.
 */
class BlockedFramesTest {
    private fun manager(
        role: TlsRole = TlsRole.Client,
        peerMaxData: Long = 1L shl 40,
        streamWindow: Long = 1L shl 30,
        maxStreams: Long = 100,
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
        m.now = TimeMark(1_000_000_000L)
        m.smoothedRtt = 40.milliseconds
        return m
    }

    private fun sendOnce(m: StreamManager): SentFrames? {
        val b = PacketBuffer.allocate(1200)
        try {
            val f = SentFrames()
            return if (m.writeStreamFrame(WireWriter(b, 0, 1200), f)) f else null
        } finally {
            b.close()
        }
    }

    private fun drain(m: StreamManager): List<ControlFrame> =
        generateSequence { m.takeControlFrame() }
            .map { c ->
                ControlFrame().also {
                    it.kind = c.kind
                    it.id = c.id
                    it.a = c.a
                }
            }.toList()

    private fun List<ControlFrame>.of(kind: ControlKind) = filter { it.kind == kind }

    @Test fun blockedSenderReportsDataBlockedOncePerLimit() {
        val m = manager(peerMaxData = 500)
        val id = m.open(bidi = true, StreamPriority.Default)
        m.write(id, ByteArray(3000), 0, 3000, false)
        assertEquals(500, sendOnce(m)!!.streamLength[0])
        repeat(3) { sendOnce(m) }
        assertEquals(listOf(500L), drain(m).of(ControlKind.DataBlocked).map { it.a }, "one DATA_BLOCKED at 500")
        assertTrue(m.onMaxData(1000))
        assertEquals(500, sendOnce(m)!!.streamLength[0])
        repeat(3) { sendOnce(m) }
        assertEquals(listOf(1000L), drain(m).of(ControlKind.DataBlocked).map { it.a }, "and one at the next limit")
    }

    @Test fun lostDataBlockedIsSentAgainWhileStillBlocked() {
        val m = manager(peerMaxData = 500)
        val id = m.open(bidi = true, StreamPriority.Default)
        m.write(id, ByteArray(3000), 0, 3000, false)
        sendOnce(m)
        sendOnce(m)
        drain(m)
        val lost = SentFrames().also { it.flags = SentFrames.DATA_BLOCKED }
        m.onFramesLost(lost)
        assertEquals(listOf(500L), drain(m).of(ControlKind.DataBlocked).map { it.a }, "the lost report goes out again")
        m.onFramesLost(lost)
        m.onFramesLost(lost)
        assertEquals(1, drain(m).of(ControlKind.DataBlocked).size, "one at a time")
        assertTrue(m.onMaxData(10_000))
        m.onFramesLost(lost)
        assertTrue(drain(m).of(ControlKind.DataBlocked).isEmpty(), "no longer blocked at 500: nothing to repeat")
    }

    @Test fun lostStreamDataBlockedIsSentAgainWhileStillBlocked() {
        val m = manager(streamWindow = 500)
        val id = m.open(bidi = true, StreamPriority.Default)
        m.write(id, ByteArray(3000), 0, 3000, false)
        sendOnce(m)
        sendOnce(m)
        sendOnce(m)
        val first = drain(m).of(ControlKind.StreamDataBlocked)
        assertEquals(listOf(id to 500L), first.map { it.id to it.a }, "one STREAM_DATA_BLOCKED at 500")
        val lost = SentFrames().also { it.addId(SentFrames.ID_STREAM_DATA_BLOCKED, id, 500) }
        m.onFramesLost(lost)
        assertEquals(listOf(id to 500L), drain(m).of(ControlKind.StreamDataBlocked).map { it.id to it.a }, "sent again")
        assertTrue(m.onMaxStreamData(id, 2000))
        m.onFramesLost(lost)
        assertTrue(drain(m).of(ControlKind.StreamDataBlocked).isEmpty(), "the limit moved on: the old report is not repeated")
    }

    @Test fun blockedReportsAreRepeatedOnlyWhileTheyHold() {
        val m = manager(peerMaxData = 400, streamWindow = 500)
        val a = m.open(bidi = true, StreamPriority.Default)
        m.write(a, ByteArray(3000), 0, 3000, false)
        repeat(3) { sendOnce(m) }
        drain(m)
        assertTrue(m.flowBlocked())
        m.repeatBlockedReports()
        assertEquals(listOf(400L), drain(m).of(ControlKind.DataBlocked).map { it.a }, "connection-blocked at 400")
        assertTrue(m.onMaxData(10_000))
        repeat(3) { sendOnce(m) }
        assertEquals(listOf(a to 500L), drain(m).of(ControlKind.StreamDataBlocked).map { it.id to it.a })
        m.repeatBlockedReports()
        val again = drain(m)
        assertEquals(listOf(a to 500L), again.of(ControlKind.StreamDataBlocked).map { it.id to it.a }, "stream-blocked at 500")
        assertTrue(again.of(ControlKind.DataBlocked).isEmpty(), "the connection is no longer blocked")
        assertTrue(m.onMaxStreamData(a, 5000))
        assertFalse(m.flowBlocked())
        m.repeatBlockedReports()
        assertTrue(drain(m).isEmpty())
    }

    @Test fun lostStreamsBlockedIsSentAgainWhileStillBlocked() {
        val m = manager(maxStreams = 1)
        assertTrue(m.open(bidi = true, StreamPriority.Default) >= 0)
        assertEquals(-1L, m.open(bidi = true, StreamPriority.Default))
        assertEquals(listOf(1L), drain(m).of(ControlKind.StreamsBlockedBidi).map { it.a })
        val lost = SentFrames().also { it.flags = SentFrames.STREAMS_BLOCKED_BIDI }
        m.onFramesLost(lost)
        assertEquals(listOf(1L), drain(m).of(ControlKind.StreamsBlockedBidi).map { it.a }, "sent again")
        assertTrue(m.onMaxStreams(true, 2))
        m.onFramesLost(lost)
        assertTrue(drain(m).of(ControlKind.StreamsBlockedBidi).isEmpty())
    }

    @Test fun lostUpdatesAreQueuedOncePerStream() {
        // a PTO probe requeues the frames of packets still in flight, which may be declared lost later: without merging, every
        // round multiplied the queued MAX_STREAM_DATA frames (a packet of 300 of them for one stream in the upload test)
        val m = manager(TlsRole.Server)
        recv(m, 0, ByteArray(300_000))
        m.read(0, ByteArray(300_000), 0, 300_000)
        drain(m)
        val lost =
            SentFrames().also {
                repeat(3) { _ -> it.addId(SentFrames.ID_MAX_STREAM_DATA, 0, 655_360) }
                it.flags = SentFrames.MAX_DATA
            }
        repeat(4) { m.onFramesLost(lost) }
        val queued = drain(m)
        assertEquals(1, queued.of(ControlKind.MaxStreamData).size, "one MAX_STREAM_DATA for stream 0: $queued")
        assertEquals(1, queued.of(ControlKind.MaxData).size)
    }

    @Test fun staleDataBlockedIsAnsweredWithTheCurrentMaxData() {
        val m = manager(TlsRole.Server)
        recv(m, 0, ByteArray(300_000))
        m.read(0, ByteArray(300_000), 0, 300_000)
        val limit = drain(m).of(ControlKind.MaxData).maxOf { it.a }
        assertTrue(limit > 786_432L)
        m.onDataBlocked(786_432, m.now, m.smoothedRtt)
        assertEquals(listOf(limit), drain(m).of(ControlKind.MaxData).map { it.a }, "the update the peer evidently lost, at once")
        m.now += 41.milliseconds
        m.onDataBlocked(limit, m.now, m.smoothedRtt)
        assertTrue(drain(m).isEmpty(), "blocked at what we granted: nothing to say, nothing wrong")
    }

    @Test fun staleStreamDataBlockedIsAnsweredWithTheCurrentMaxStreamData() {
        val m = manager(TlsRole.Server)
        recv(m, 0, ByteArray(300_000))
        m.read(0, ByteArray(300_000), 0, 300_000)
        val limit = drain(m).of(ControlKind.MaxStreamData).maxOf { it.a }
        m.onStreamDataBlocked(0, 524_288, m.now, m.smoothedRtt)
        assertEquals(listOf(0L to limit), drain(m).of(ControlKind.MaxStreamData).map { it.id to it.a })
        m.onStreamDataBlocked(4, 524_288, m.now, m.smoothedRtt)
        assertTrue(drain(m).of(ControlKind.MaxStreamData).isEmpty(), "another stream, not yet over its window")
    }

    @Test fun staleBlockedIsAnsweredOncePerRtt() {
        val m = manager(TlsRole.Server)
        recv(m, 0, ByteArray(300_000))
        m.read(0, ByteArray(300_000), 0, 300_000)
        drain(m)
        m.onDataBlocked(786_432, m.now, m.smoothedRtt)
        assertEquals(1, drain(m).of(ControlKind.MaxData).size)
        m.onDataBlocked(786_432, m.now, m.smoothedRtt)
        m.onDataBlocked(786_000, m.now, m.smoothedRtt)
        assertTrue(drain(m).isEmpty(), "again within the RTT: not answered")
        m.now += 41.milliseconds
        m.onDataBlocked(786_432, m.now, m.smoothedRtt)
        assertEquals(1, drain(m).of(ControlKind.MaxData).size, "an RTT later the peer may still lack the update")
        m.onStreamDataBlocked(0, 524_288, m.now, m.smoothedRtt)
        m.onStreamDataBlocked(0, 524_288, m.now, m.smoothedRtt)
        assertEquals(1, drain(m).of(ControlKind.MaxStreamData).size)
    }

    private fun recv(
        m: StreamManager,
        id: Long,
        bytes: ByteArray,
    ) {
        val b = PacketBuffer.of(bytes + ByteArray(1))
        try {
            m.onStream(id, 0, b, 0, bytes.size, false)
        } finally {
            b.close()
        }
    }
}
