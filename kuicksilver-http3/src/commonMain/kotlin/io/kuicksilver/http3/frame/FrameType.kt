// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.frame

/** Frame types of RFC 9114 section 7.2 and RFC 9218 section 7. */
internal object FrameType {
    const val DATA: Long = 0x0
    const val HEADERS: Long = 0x1
    const val CANCEL_PUSH: Long = 0x3
    const val SETTINGS: Long = 0x4
    const val PUSH_PROMISE: Long = 0x5
    const val GOAWAY: Long = 0x7
    const val MAX_PUSH_ID: Long = 0xd
    const val PRIORITY_UPDATE_REQUEST: Long = 0xf0700
    const val PRIORITY_UPDATE_PUSH: Long = 0xf0701

    /**
     * `WT_STREAM` (draft-ietf-webtrans-http3-16 section 4.3): not a frame but a signal that opens a WebTransport
     * bidirectional stream, followed by the Session ID and no length. Where WebTransport is on, it anywhere else is
     * H3_FRAME_ERROR.
     */
    const val WT_STREAM: Long = 0x41

    /** HTTP/2 frame types with no HTTP/3 meaning (RFC 9114 section 7.2.8): PRIORITY, PING, WINDOW_UPDATE, CONTINUATION. */
    val H2_ONLY: Set<Long> = setOf(0x2L, 0x6L, 0x8L, 0x9L)

    /** Reserved types `0x1f * N + 0x21` (RFC 9114 section 7.2.8); the same pattern reserves stream types, settings and error codes. */
    fun isGrease(t: Long): Boolean = t >= 0x21 && (t - 0x21) % 0x1f == 0L

    fun grease(n: Long): Long = 0x1fL * n + 0x21
}

/** Unidirectional stream types (RFC 9114 section 6.2, RFC 9204 section 4.2). */
internal object StreamType {
    const val CONTROL: Long = 0x0
    const val PUSH: Long = 0x1
    const val QPACK_ENCODER: Long = 0x2
    const val QPACK_DECODER: Long = 0x3

    /** A WebTransport unidirectional stream, followed by the Session ID (draft-ietf-webtrans-http3-16 section 4.2). */
    const val WT_UNI: Long = 0x54
}

/** A frame header: type, payload length and the bytes the two varints took. */
internal class FrameHeader(
    val type: Long,
    val length: Long,
    val headerSize: Int,
)

internal object FrameHeaders {
    /** The header at [off], or null when [end] cuts it; the length is only a number here, never a buffer size. */
    fun parse(
        buf: ByteArray,
        off: Int,
        end: Int,
    ): FrameHeader? {
        val type = VarInt.read(buf, off, end)
        if (type < 0) return null
        val tn = VarInt.encodedLength(buf[off])
        val len = VarInt.read(buf, off + tn, end)
        if (len < 0) return null
        return FrameHeader(type, len, tn + VarInt.encodedLength(buf[off + tn]))
    }

    fun write(
        type: Long,
        length: Long,
        out: ByteArray,
        off: Int,
    ): Int {
        val a = VarInt.write(type, out, off)
        return a +
            VarInt.write(length, out, off + a)
    }

    fun size(
        type: Long,
        length: Long,
    ): Int = VarInt.size(type) + VarInt.size(length)

    /** A whole frame: header plus [payload]. */
    fun frame(
        type: Long,
        payload: ByteArray,
    ): ByteArray {
        val out = ByteArray(size(type, payload.size.toLong()) + payload.size)
        val h = write(type, payload.size.toLong(), out, 0)
        payload.copyInto(out, h)
        return out
    }
}

/** A connection or stream error found by a codec; the runtime turns it into CONNECTION_CLOSE or a stream reset with [code]. */
internal class H3ProtocolError(
    val code: Long,
    message: String,
) : Exception(message)
