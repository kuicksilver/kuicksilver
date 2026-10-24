// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.wire.AckFrameView
import io.kuicksilver.quic.wire.FrameDecoder
import io.kuicksilver.quic.wire.FrameHandler
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.WireReader

/** A frame as a plain value, for round-trip tests. */
sealed class TestFrame {
    data class Padding(
        val count: Int,
    ) : TestFrame()

    object Ping : TestFrame() {
        override fun toString() = "Ping"
    }

    data class Ack(
        val largest: Long,
        val ackDelay: Long,
        val ranges: List<Pair<Long, Long>> /* (smallest, largest) descending */,
        val ecn: List<Long>?,
    ) : TestFrame()

    data class ResetStream(
        val id: Long,
        val code: Long,
        val finalSize: Long,
    ) : TestFrame()

    data class StopSending(
        val id: Long,
        val code: Long,
    ) : TestFrame()

    data class Crypto(
        val offset: Long,
        val data: List<Byte>,
    ) : TestFrame()

    data class NewToken(
        val token: List<Byte>,
    ) : TestFrame()

    data class Stream(
        val id: Long,
        val offset: Long,
        val data: List<Byte>,
        val fin: Boolean,
    ) : TestFrame()

    data class MaxData(
        val max: Long,
    ) : TestFrame()

    data class MaxStreamData(
        val id: Long,
        val max: Long,
    ) : TestFrame()

    data class MaxStreams(
        val bidi: Boolean,
        val max: Long,
    ) : TestFrame()

    data class DataBlocked(
        val limit: Long,
    ) : TestFrame()

    data class StreamDataBlocked(
        val id: Long,
        val limit: Long,
    ) : TestFrame()

    data class StreamsBlocked(
        val bidi: Boolean,
        val limit: Long,
    ) : TestFrame()

    data class NewConnectionId(
        val seq: Long,
        val retirePriorTo: Long,
        val cid: List<Byte>,
        val token: List<Byte>,
    ) : TestFrame()

    data class RetireConnectionId(
        val seq: Long,
    ) : TestFrame()

    data class PathChallenge(
        val data: Long,
    ) : TestFrame()

    data class PathResponse(
        val data: Long,
    ) : TestFrame()

    data class ConnectionClose(
        val application: Boolean,
        val code: Long,
        val frameType: Long,
        val reason: List<Byte>,
    ) : TestFrame()

    object HandshakeDone : TestFrame() {
        override fun toString() = "HandshakeDone"
    }

    data class Datagram(
        val data: List<Byte>,
    ) : TestFrame()
}

/** The frames of a [NullCryptoProvider] 1-RTT datagram (identity header protection, zero tag) with a [dcidLen]-byte DCID; null for a long-header datagram. */
internal fun nullOneRttFrames(
    bytes: ByteArray,
    dcidLen: Int = 8,
): List<TestFrame>? {
    if (bytes[0].toInt() and 0x80 != 0) return null
    val start = 1 + dcidLen + (bytes[0].toInt() and 0x03) + 1
    val b =
        io.kuicksilver.native.PacketBuffer
            .of(bytes)
    try {
        val h = CollectingHandler()
        io.kuicksilver.quic.wire.FrameDecoder.decode(
            io.kuicksilver.quic.wire.WireReader(
                b,
                start,
                bytes.size - 16,
            ),
            io.kuicksilver.quic.wire.PacketType.OneRtt,
            h,
        )
        return h.frames
    } finally {
        b.close()
    }
}

/**
 * Whether a [NullCryptoProvider] datagram carries an ack-eliciting Initial packet (identity header protection, zero tag): walks
 * the coalesced long-header packets and decodes the Initial's frames. False when it holds no Initial or only ACK/PADDING.
 */
internal fun nullDatagramHasAckElicitingInitial(bytes: ByteArray): Boolean {
    val b = PacketBuffer.of(bytes)
    try {
        val view = PacketHeaderView()
        var off = 0
        while (off < bytes.size && bytes[off].toInt() and 0x80 != 0) {
            if (!PacketHeaderCodec.parse(b, off, bytes.size, 8, view)) break
            if (view.type == PacketType.Initial) {
                val payload = view.pnOffset + (bytes[off].toInt() and 0x03) + 1
                if (FrameDecoder.decode(WireReader(b, payload, view.packetEnd - 16), PacketType.Initial, CollectingHandler())) return true
            }
            off = view.packetEnd
        }
        return false
    } finally {
        b.close()
    }
}

internal fun PacketBuffer.slice(
    off: Int,
    len: Int,
): List<Byte> = ByteArray(len).also { copyTo(it, off, 0, len) }.toList()

/** Collects decoded frames as [TestFrame]s (copies every slice). */
internal class CollectingHandler : FrameHandler {
    val frames = ArrayList<TestFrame>()

    override fun padding(count: Int) {
        frames += TestFrame.Padding(count)
    }

    override fun ping() {
        frames += TestFrame.Ping
    }

    override fun ack(ack: AckFrameView) {
        frames +=
            TestFrame.Ack(
                ack.largest,
                ack.ackDelay,
                (0 until ack.rangeCount).map { ack.smallest(it) to ack.largest(it) },
                ack.ecn?.toList(),
            )
    }

    override fun resetStream(
        id: Long,
        code: Long,
        finalSize: Long,
    ) {
        frames += TestFrame.ResetStream(id, code, finalSize)
    }

    override fun stopSending(
        id: Long,
        code: Long,
    ) {
        frames += TestFrame.StopSending(id, code)
    }

    override fun crypto(
        offset: Long,
        data: PacketBuffer,
        off: Int,
        len: Int,
    ) {
        frames += TestFrame.Crypto(offset, data.slice(off, len))
    }

    override fun newToken(
        token: PacketBuffer,
        off: Int,
        len: Int,
    ) {
        frames += TestFrame.NewToken(token.slice(off, len))
    }

    override fun stream(
        id: Long,
        offset: Long,
        data: PacketBuffer,
        off: Int,
        len: Int,
        fin: Boolean,
    ) {
        frames +=
            TestFrame.Stream(id, offset, data.slice(off, len), fin)
    }

    override fun maxData(max: Long) {
        frames += TestFrame.MaxData(max)
    }

    override fun maxStreamData(
        id: Long,
        max: Long,
    ) {
        frames += TestFrame.MaxStreamData(id, max)
    }

    override fun maxStreams(
        bidi: Boolean,
        max: Long,
    ) {
        frames += TestFrame.MaxStreams(bidi, max)
    }

    override fun dataBlocked(limit: Long) {
        frames += TestFrame.DataBlocked(limit)
    }

    override fun streamDataBlocked(
        id: Long,
        limit: Long,
    ) {
        frames += TestFrame.StreamDataBlocked(id, limit)
    }

    override fun streamsBlocked(
        bidi: Boolean,
        limit: Long,
    ) {
        frames += TestFrame.StreamsBlocked(bidi, limit)
    }

    override fun newConnectionId(
        seq: Long,
        retirePriorTo: Long,
        cid: PacketBuffer,
        cidOff: Int,
        cidLen: Int,
        resetTokenOff: Int,
    ) {
        frames += TestFrame.NewConnectionId(seq, retirePriorTo, cid.slice(cidOff, cidLen), cid.slice(resetTokenOff, 16))
    }

    override fun retireConnectionId(seq: Long) {
        frames += TestFrame.RetireConnectionId(seq)
    }

    override fun pathChallenge(data: Long) {
        frames += TestFrame.PathChallenge(data)
    }

    override fun pathResponse(data: Long) {
        frames += TestFrame.PathResponse(data)
    }

    override fun connectionClose(
        application: Boolean,
        code: Long,
        frameType: Long,
        reason: PacketBuffer,
        off: Int,
        len: Int,
    ) {
        frames +=
            TestFrame.ConnectionClose(application, code, frameType, reason.slice(off, len))
    }

    override fun handshakeDone() {
        frames += TestFrame.HandshakeDone
    }

    override fun datagram(
        data: PacketBuffer,
        off: Int,
        len: Int,
    ) {
        frames += TestFrame.Datagram(data.slice(off, len))
    }
}
