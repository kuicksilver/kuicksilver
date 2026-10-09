// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kuicksilver.native.PacketBuffer

/** Writes frames (RFC 9000 section 19, RFC 9221); the overhead helpers let the packet builder size frames before writing. */
internal object FrameEncoder {
    fun padding(
        w: WireWriter,
        count: Int,
    ) {
        w.zero(count)
    }

    fun ping(w: WireWriter) {
        w.u8(FrameType.PING.toInt())
    }

    /** [ranges] holds (smallest, largest) pairs, descending; [count] pairs are written. */
    fun ack(
        w: WireWriter,
        ranges: LongArray,
        count: Int,
        ackDelayEncoded: Long,
        ecn: LongArray? = null,
    ) {
        w.u8(if (ecn == null) FrameType.ACK.toInt() else FrameType.ACK_ECN.toInt())
        w.varint(ranges[1])
        w.varint(ackDelayEncoded)
        w.varint((count - 1).toLong())
        w.varint(ranges[1] - ranges[0])
        for (i in 1 until count) {
            val prevSmallest = ranges[2 * (i - 1)]
            val largest = ranges[2 * i + 1]
            val smallest = ranges[2 * i]
            w.varint(prevSmallest - largest - 2)
            w.varint(largest - smallest)
        }
        if (ecn != null) {
            w.varint(ecn[0])
            w.varint(ecn[1])
            w.varint(ecn[2])
        }
    }

    fun ackOverhead(
        ranges: LongArray,
        count: Int,
        ackDelayEncoded: Long,
        ecn: LongArray? = null,
    ): Int {
        var n =
            1 + VarInt.size(ranges[1]) + VarInt.size(ackDelayEncoded) + VarInt.size((count - 1).toLong()) +
                VarInt.size(ranges[1] - ranges[0])
        for (i in 1 until count) {
            n +=
                VarInt.size(ranges[2 * (i - 1)] - ranges[2 * i + 1] - 2) + VarInt.size(ranges[2 * i + 1] - ranges[2 * i])
        }
        if (ecn != null) n += VarInt.size(ecn[0]) + VarInt.size(ecn[1]) + VarInt.size(ecn[2])
        return n
    }

    fun resetStream(
        w: WireWriter,
        id: Long,
        code: Long,
        finalSize: Long,
    ) {
        w.u8(FrameType.RESET_STREAM.toInt())
        w.varint(id)
        w.varint(code)
        w.varint(finalSize)
    }

    fun stopSending(
        w: WireWriter,
        id: Long,
        code: Long,
    ) {
        w.u8(FrameType.STOP_SENDING.toInt())
        w.varint(id)
        w.varint(code)
    }

    fun crypto(
        w: WireWriter,
        offset: Long,
        data: PacketBuffer,
        off: Int,
        len: Int,
    ) {
        w.u8(FrameType.CRYPTO.toInt())
        w.varint(offset)
        w.varint(len.toLong())
        w.copy(data, off, len)
    }

    fun cryptoOverhead(
        offset: Long,
        len: Int,
    ): Int = 1 + VarInt.size(offset) + VarInt.size(len.toLong())

    fun newToken(
        w: WireWriter,
        token: PacketBuffer,
        off: Int,
        len: Int,
    ) {
        w.u8(FrameType.NEW_TOKEN.toInt())
        w.varint(len.toLong())
        w.copy(token, off, len)
    }

    fun stream(
        w: WireWriter,
        id: Long,
        offset: Long,
        data: PacketBuffer,
        off: Int,
        len: Int,
        fin: Boolean,
        withLength: Boolean,
    ) {
        var type = FrameType.STREAM
        if (offset !=
            0L
        ) {
            type = type or 0x04
        }
        if (withLength) type = type or 0x02
        if (fin) type = type or 0x01
        w.u8(type.toInt())
        w.varint(id)
        if (offset != 0L) w.varint(offset)
        if (withLength) w.varint(len.toLong())
        w.copy(data, off, len)
    }

    /** Writes only the STREAM frame header; the caller appends exactly [len] bytes. */
    fun streamHeader(
        w: WireWriter,
        id: Long,
        offset: Long,
        len: Int,
        fin: Boolean,
        withLength: Boolean,
    ) {
        var type = FrameType.STREAM
        if (offset !=
            0L
        ) {
            type = type or 0x04
        }
        if (withLength) type = type or 0x02
        if (fin) type = type or 0x01
        w.u8(type.toInt())
        w.varint(id)
        if (offset != 0L) w.varint(offset)
        if (withLength) w.varint(len.toLong())
    }

    fun streamOverhead(
        id: Long,
        offset: Long,
        len: Int,
    ): Int = 1 + VarInt.size(id) + (if (offset != 0L) VarInt.size(offset) else 0) + VarInt.size(len.toLong())

    fun maxData(
        w: WireWriter,
        max: Long,
    ) {
        w.u8(FrameType.MAX_DATA.toInt())
        w.varint(max)
    }

    fun maxStreamData(
        w: WireWriter,
        id: Long,
        max: Long,
    ) {
        w.u8(FrameType.MAX_STREAM_DATA.toInt())
        w.varint(id)
        w.varint(max)
    }

    fun maxStreams(
        w: WireWriter,
        bidi: Boolean,
        max: Long,
    ) {
        w.u8((if (bidi) FrameType.MAX_STREAMS_BIDI else FrameType.MAX_STREAMS_UNI).toInt())
        w.varint(max)
    }

    fun dataBlocked(
        w: WireWriter,
        limit: Long,
    ) {
        w.u8(FrameType.DATA_BLOCKED.toInt())
        w.varint(limit)
    }

    fun streamDataBlocked(
        w: WireWriter,
        id: Long,
        limit: Long,
    ) {
        w.u8(FrameType.STREAM_DATA_BLOCKED.toInt())
        w.varint(id)
        w.varint(limit)
    }

    fun streamsBlocked(
        w: WireWriter,
        bidi: Boolean,
        limit: Long,
    ) {
        w.u8((if (bidi) FrameType.STREAMS_BLOCKED_BIDI else FrameType.STREAMS_BLOCKED_UNI).toInt())
        w.varint(limit)
    }

    fun newConnectionId(
        w: WireWriter,
        seq: Long,
        retirePriorTo: Long,
        cid: ByteArray,
        resetToken: ByteArray,
    ) {
        require(cid.size in 1..20 && resetToken.size == 16)
        w.u8(FrameType.NEW_CONNECTION_ID.toInt())
        w.varint(seq)
        w.varint(retirePriorTo)
        w.u8(cid.size)
        w.bytes(cid)
        w.bytes(resetToken)
    }

    fun retireConnectionId(
        w: WireWriter,
        seq: Long,
    ) {
        w.u8(FrameType.RETIRE_CONNECTION_ID.toInt())
        w.varint(seq)
    }

    fun pathChallenge(
        w: WireWriter,
        data: Long,
    ) {
        w.u8(FrameType.PATH_CHALLENGE.toInt())
        w.u64(data)
    }

    fun pathResponse(
        w: WireWriter,
        data: Long,
    ) {
        w.u8(FrameType.PATH_RESPONSE.toInt())
        w.u64(data)
    }

    fun connectionClose(
        w: WireWriter,
        application: Boolean,
        code: Long,
        frameType: Long,
        reason: ByteArray,
    ) {
        w.u8((if (application) FrameType.CONNECTION_CLOSE_APP else FrameType.CONNECTION_CLOSE).toInt())
        w.varint(code)
        if (!application) w.varint(frameType)
        w.varint(reason.size.toLong())
        w.bytes(reason)
    }

    fun connectionCloseOverhead(
        application: Boolean,
        code: Long,
        frameType: Long,
        reasonLength: Int,
    ): Int = 1 + VarInt.size(code) + (if (application) 0 else VarInt.size(frameType)) + VarInt.size(reasonLength.toLong()) + reasonLength

    fun handshakeDone(w: WireWriter) {
        w.u8(FrameType.HANDSHAKE_DONE.toInt())
    }

    /** DATAGRAM with an explicit length (type 0x31) from a byte array (RFC 9221 section 4). */
    fun datagram(
        w: WireWriter,
        data: ByteArray,
        off: Int,
        len: Int,
    ) {
        w.u8(FrameType.DATAGRAM_LEN.toInt())
        w.varint(len.toLong())
        w.bytes(data, off, len)
    }

    fun datagram(
        w: WireWriter,
        data: PacketBuffer,
        off: Int,
        len: Int,
        withLength: Boolean,
    ) {
        w.u8((if (withLength) FrameType.DATAGRAM_LEN else FrameType.DATAGRAM).toInt())
        if (withLength) w.varint(len.toLong())
        w.copy(data, off, len)
    }
}
