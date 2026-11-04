// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.frame

import io.kuicksilver.http2.Http2ErrorCode

/**
 * Incremental HTTP/2 frame decoder (RFC 9113 sections 4 and 6). [feed] takes bytes until one frame is complete and
 * returns how many it consumed; [next] hands that frame out. The 9-byte header is checked before the payload is
 * buffered: a declared length above [maxFrameSize] is a FRAME_SIZE_ERROR (section 4.2) before any allocation, and so is
 * a length a fixed-size frame cannot have. A frame of an unknown type (section 5.5) is skipped as it streams by, never
 * buffered, and reported as [Frame.Unknown] once its payload has passed.
 *
 * Errors: [feed] throws [H2ConnectionError] for a connection error (the connection is over, nothing more is read);
 * [next] throws [H2StreamError] for a stream error, after [feed] consumed that frame whole, so the decoder stays in sync.
 * [maxFrameSize] is our SETTINGS_MAX_FRAME_SIZE.
 */
internal class FrameDecoder(
    var maxFrameSize: Int = H2.MIN_MAX_FRAME_SIZE,
) {
    private val head = ByteArray(H2.FRAME_HEADER_SIZE)
    private var headLen = 0
    private var length = 0
    private var type = 0
    private var flags = 0
    private var streamId = 0
    private var payload: ByteArray? = null
    private var have = 0
    private var skipping = false
    private var ready: Frame? = null
    private var pendingError: H2StreamError? = null

    /** Payload bytes ever allocated by this decoder (a test hook: it grows only by frames that passed the length check). */
    var allocatedBytes: Long = 0
        private set

    /** True while a frame is partly read (its header or payload): the input ended inside a frame. */
    val inFrame: Boolean get() = headLen > 0

    /** Consumes bytes until a frame is complete (then [next] returns it); returns how many bytes it took. */
    fun feed(
        buf: ByteArray,
        off: Int,
        len: Int,
    ): Int {
        if (ready != null || pendingError != null) return 0
        var p = off
        val end = off + len
        while (p < end && ready == null && pendingError == null) {
            if (headLen < H2.FRAME_HEADER_SIZE) {
                val n = minOf(H2.FRAME_HEADER_SIZE - headLen, end - p)
                buf.copyInto(head, headLen, p, p + n)
                headLen += n
                p += n
                if (headLen == H2.FRAME_HEADER_SIZE) {
                    try {
                        startFrame()
                    } catch (e: Exception) {
                        reset()
                        throw e
                    }
                }
            } else {
                val n = minOf(length - have, end - p)
                if (!skipping) buf.copyInto(payload!!, have, p, p + n)
                have += n
                p += n
                if (have == length) finishFrame()
            }
        }
        return p - off
    }

    /** The frame [feed] completed, or null; throws the [H2StreamError] of a frame that was consumed but is invalid. */
    fun next(): Frame? {
        pendingError?.let {
            pendingError = null
            throw it
        }
        val f = ready
        ready = null
        return f
    }

    private fun startFrame() {
        length = ((head[0].toInt() and 0xff) shl 16) or ((head[1].toInt() and 0xff) shl 8) or (head[2].toInt() and 0xff)
        type = head[3].toInt() and 0xff
        flags = head[4].toInt() and 0xff
        streamId = readInt31(head, 5) // the R bit is ignored on receipt (section 4.1)
        if (length >
            maxFrameSize
        ) {
            connError(Http2ErrorCode.FRAME_SIZE_ERROR, "frame of $length bytes above SETTINGS_MAX_FRAME_SIZE $maxFrameSize")
        }
        checkHeader()
        have = 0
        skipping = type > FrameType.CONTINUATION
        if (!skipping && length > 0) {
            payload = ByteArray(length)
            allocatedBytes += length
        } else {
            payload = EMPTY
        }
        if (length == 0) finishFrame()
    }

    /** Checks that need only the header: stream identifier rules and fixed lengths (sections 6.1-6.10). */
    private fun checkHeader() {
        when (type) {
            FrameType.DATA, FrameType.HEADERS, FrameType.PRIORITY, FrameType.RST_STREAM, FrameType.PUSH_PROMISE,
            FrameType.CONTINUATION,
            -> {
                if (streamId == 0) connError(Http2ErrorCode.PROTOCOL_ERROR, "frame type $type on stream 0")
            }

            FrameType.SETTINGS, FrameType.PING, FrameType.GOAWAY -> {
                if (streamId != 0) connError(Http2ErrorCode.PROTOCOL_ERROR, "frame type $type on stream $streamId")
            }
        }
        when (type) {
            FrameType.SETTINGS -> {
                if (flags and FrameFlags.ACK != 0 && length != 0) connError(Http2ErrorCode.FRAME_SIZE_ERROR, "SETTINGS ACK with a payload")
                if (length % 6 != 0) connError(Http2ErrorCode.FRAME_SIZE_ERROR, "SETTINGS length $length not a multiple of 6")
            }

            FrameType.PING -> {
                if (length != 8) connError(Http2ErrorCode.FRAME_SIZE_ERROR, "PING length $length")
            }

            FrameType.GOAWAY -> {
                if (length < 8) connError(Http2ErrorCode.FRAME_SIZE_ERROR, "GOAWAY length $length")
            }

            FrameType.RST_STREAM -> {
                if (length != 4) connError(Http2ErrorCode.FRAME_SIZE_ERROR, "RST_STREAM length $length")
            }

            FrameType.WINDOW_UPDATE -> {
                if (length != 4) connError(Http2ErrorCode.FRAME_SIZE_ERROR, "WINDOW_UPDATE length $length")
            }
        }
    }

    private fun finishFrame() {
        val p = payload!!
        val t = type
        val fl = flags
        val id = streamId
        val n = length
        reset()
        try {
            ready = parse(t, fl, id, p, n)
        } catch (e: H2StreamError) {
            pendingError = e
        }
    }

    private fun reset() {
        headLen = 0
        have = 0
        payload = null
        skipping = false
    }

    private fun parse(
        type: Int,
        flags: Int,
        id: Int,
        p: ByteArray,
        n: Int,
    ): Frame =
        when (type) {
            FrameType.DATA -> {
                val (start, end) = unpad(p, n, flags, 0)
                Frame.Data(id, p.copyOfRange(start, end), flags and FrameFlags.END_STREAM != 0, n)
            }

            FrameType.HEADERS -> {
                val prio = flags and FrameFlags.PRIORITY != 0
                val (start, end) = unpad(p, n, flags, if (prio) 5 else 0)
                val dep = if (prio) readInt31(p, start - 5) else -1
                Frame.Headers(
                    id,
                    p.copyOfRange(start, end),
                    flags and FrameFlags.END_STREAM != 0,
                    flags and FrameFlags.END_HEADERS != 0,
                    dep,
                )
            }

            FrameType.PRIORITY -> {
                if (n != 5) throw H2StreamError(id, Http2ErrorCode.FRAME_SIZE_ERROR, "PRIORITY length $n")
                Frame.Priority(id, readInt31(p, 0))
            }

            FrameType.RST_STREAM -> {
                Frame.RstStream(id, readUInt32(p, 0))
            }

            FrameType.SETTINGS -> {
                val count = n / 6
                val ids = IntArray(count) { ((p[6 * it].toInt() and 0xff) shl 8) or (p[6 * it + 1].toInt() and 0xff) }
                val values = LongArray(count) { readUInt32(p, 6 * it + 2) }
                Frame.Settings(flags and FrameFlags.ACK != 0, ids, values)
            }

            FrameType.PUSH_PROMISE -> {
                val (start, end) = unpad(p, n, flags, 4)
                Frame.PushPromise(id, readInt31(p, start - 4), p.copyOfRange(start, end), flags and FrameFlags.END_HEADERS != 0)
            }

            FrameType.PING -> {
                var v = 0L
                for (i in 0 until 8) v = (v shl 8) or (p[i].toLong() and 0xff)
                Frame.Ping(flags and FrameFlags.ACK != 0, v)
            }

            FrameType.GOAWAY -> {
                Frame.GoAway(readInt31(p, 0), readUInt32(p, 4), p.copyOfRange(8, n))
            }

            FrameType.WINDOW_UPDATE -> {
                Frame.WindowUpdate(id, readInt31(p, 0))
            }

            FrameType.CONTINUATION -> {
                Frame.Continuation(id, p.copyOfRange(0, n), flags and FrameFlags.END_HEADERS != 0)
            }

            else -> {
                Frame.Unknown(id, type, flags, n)
            }
        }

    /**
     * The bounds of the content after the optional pad length byte and [fixed] more bytes (priority fields, promised
     * stream). Too short for the mandatory fields is FRAME_SIZE_ERROR (section 4.2); padding that does not fit what is
     * left is PROTOCOL_ERROR (sections 6.1, 6.2, 6.6).
     */
    private fun unpad(
        p: ByteArray,
        n: Int,
        flags: Int,
        fixed: Int,
    ): Pair<Int, Int> {
        val padded = flags and FrameFlags.PADDED != 0
        val start = (if (padded) 1 else 0) + fixed
        if (n < start) connError(Http2ErrorCode.FRAME_SIZE_ERROR, "frame of $n bytes too short for its fields")
        val pad = if (padded) p[0].toInt() and 0xff else 0
        if (pad > n - start) connError(Http2ErrorCode.PROTOCOL_ERROR, "padding of $pad bytes beyond the payload")
        return start to n - pad
    }

    private fun connError(
        code: Http2ErrorCode,
        message: String,
    ): Nothing = throw H2ConnectionError(code, message)

    private companion object {
        val EMPTY = ByteArray(0)

        fun readInt31(
            b: ByteArray,
            at: Int,
        ): Int =
            ((b[at].toInt() and 0x7f) shl 24) or ((b[at + 1].toInt() and 0xff) shl 16) or ((b[at + 2].toInt() and 0xff) shl 8) or
                (b[at + 3].toInt() and 0xff)

        fun readUInt32(
            b: ByteArray,
            at: Int,
        ): Long =
            ((b[at].toLong() and 0xff) shl 24) or ((b[at + 1].toLong() and 0xff) shl 16) or ((b[at + 2].toLong() and 0xff) shl 8) or
                (b[at + 3].toLong() and 0xff)
    }
}
