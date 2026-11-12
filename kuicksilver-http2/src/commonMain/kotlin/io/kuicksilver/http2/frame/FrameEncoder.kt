// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.frame

/**
 * Encodes HTTP/2 frames (RFC 9113 section 6), each into a new array of exactly its wire size. Reserved bits and flags
 * without meaning for a type are always 0 (section 4.1); callers keep payloads within the peer's SETTINGS_MAX_FRAME_SIZE.
 */
internal object FrameEncoder {
    fun data(
        streamId: Int,
        buf: ByteArray,
        off: Int,
        len: Int,
        endStream: Boolean,
        padLength: Int = 0,
    ): ByteArray = padded(FrameType.DATA, if (endStream) FrameFlags.END_STREAM else 0, streamId, ByteArray(0), buf, off, len, padLength)

    fun headers(
        streamId: Int,
        fragment: ByteArray,
        endStream: Boolean,
        endHeaders: Boolean,
        dependency: Int = -1,
        padLength: Int = 0,
        weight: Int = 16,
    ): ByteArray {
        var flags = (if (endStream) FrameFlags.END_STREAM else 0) or (if (endHeaders) FrameFlags.END_HEADERS else 0)
        val prefix =
            if (dependency >= 0) {
                flags = flags or FrameFlags.PRIORITY
                ByteArray(5).also {
                    putInt(it, 0, dependency) // not exclusive
                    it[4] = (weight - 1).toByte() // weight 1 to 256 as 0 to 255 (RFC 7540 section 6.2)
                }
            } else {
                ByteArray(0)
            }
        return padded(FrameType.HEADERS, flags, streamId, prefix, fragment, 0, fragment.size, padLength)
    }

    fun priority(
        streamId: Int,
        dependency: Int,
    ): ByteArray = frame(FrameType.PRIORITY, 0, streamId, 5).also { putInt(it, 9, dependency) }

    /** PRIORITY_UPDATE (RFC 9218 section 7.1) on stream 0 for [prioritizedStreamId], with an ASCII Priority Field Value. */
    fun priorityUpdate(
        prioritizedStreamId: Int,
        value: String,
    ): ByteArray {
        val v = value.encodeToByteArray()
        return frame(FrameType.PRIORITY_UPDATE, 0, 0, 4 + v.size).also {
            putInt(it, 9, prioritizedStreamId)
            v.copyInto(it, 13)
        }
    }

    fun rstStream(
        streamId: Int,
        errorCode: Long,
    ): ByteArray = frame(FrameType.RST_STREAM, 0, streamId, 4).also { putInt(it, 9, errorCode.toInt()) }

    fun settings(
        ids: IntArray,
        values: LongArray,
    ): ByteArray =
        frame(FrameType.SETTINGS, 0, 0, 6 * ids.size).also {
            for (i in ids.indices) {
                it[9 + 6 * i] = (ids[i] ushr 8).toByte()
                it[10 + 6 * i] = ids[i].toByte()
                putInt(it, 11 + 6 * i, values[i].toInt())
            }
        }

    fun settingsAck(): ByteArray = frame(FrameType.SETTINGS, FrameFlags.ACK, 0, 0)

    fun pushPromise(
        streamId: Int,
        promisedStreamId: Int,
        fragment: ByteArray,
        endHeaders: Boolean,
    ): ByteArray =
        padded(
            FrameType.PUSH_PROMISE,
            if (endHeaders) FrameFlags.END_HEADERS else 0,
            streamId,
            ByteArray(4).also { putInt(it, 0, promisedStreamId) },
            fragment,
            0,
            fragment.size,
            0,
        )

    fun ping(
        ack: Boolean,
        payload: Long,
    ): ByteArray =
        frame(FrameType.PING, if (ack) FrameFlags.ACK else 0, 0, 8).also {
            for (i in 0 until 8) it[9 + i] = (payload ushr (56 - 8 * i)).toByte()
        }

    fun goAway(
        lastStreamId: Int,
        errorCode: Long,
        debug: ByteArray,
    ): ByteArray =
        frame(FrameType.GOAWAY, 0, 0, 8 + debug.size).also {
            putInt(it, 9, lastStreamId)
            putInt(it, 13, errorCode.toInt())
            debug.copyInto(it, 17)
        }

    fun windowUpdate(
        streamId: Int,
        increment: Int,
    ): ByteArray = frame(FrameType.WINDOW_UPDATE, 0, streamId, 4).also { putInt(it, 9, increment) }

    fun continuation(
        streamId: Int,
        fragment: ByteArray,
        endHeaders: Boolean,
    ): ByteArray =
        frame(
            FrameType.CONTINUATION,
            if (endHeaders) FrameFlags.END_HEADERS else 0,
            streamId,
            fragment.size,
        ).also { fragment.copyInto(it, 9) }

    /** Any frame, for tests and extension types: [payload] as is. */
    fun raw(
        type: Int,
        flags: Int,
        streamId: Int,
        payload: ByteArray,
    ): ByteArray = frame(type, flags, streamId, payload.size).also { payload.copyInto(it, 9) }

    private fun padded(
        type: Int,
        flags: Int,
        streamId: Int,
        prefix: ByteArray,
        buf: ByteArray,
        off: Int,
        len: Int,
        padLength: Int,
    ): ByteArray {
        val pad = if (padLength > 0) 1 + padLength else 0
        val out = frame(type, flags or (if (pad > 0) FrameFlags.PADDED else 0), streamId, pad + prefix.size + len)
        var p = 9
        if (pad > 0) out[p++] = padLength.toByte()
        prefix.copyInto(out, p)
        p += prefix.size
        buf.copyInto(out, p, off, off + len)
        return out // the padding is already zero
    }

    private fun frame(
        type: Int,
        flags: Int,
        streamId: Int,
        length: Int,
    ): ByteArray {
        val out = ByteArray(9 + length)
        out[0] = (length ushr 16).toByte()
        out[1] = (length ushr 8).toByte()
        out[2] = length.toByte()
        out[3] = type.toByte()
        out[4] = flags.toByte()
        putInt(out, 5, streamId and Int.MAX_VALUE)
        return out
    }

    private fun putInt(
        b: ByteArray,
        at: Int,
        v: Int,
    ) {
        b[at] = (v ushr 24).toByte()
        b[at + 1] = (v ushr 16).toByte()
        b[at + 2] = (v ushr 8).toByte()
        b[at + 3] = v.toByte()
    }
}
