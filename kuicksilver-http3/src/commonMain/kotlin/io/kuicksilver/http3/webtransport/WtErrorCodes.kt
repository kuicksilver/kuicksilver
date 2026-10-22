// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

/**
 * WebTransport application error codes (0..2^32-1) in the HTTP/3 error code space (draft-ietf-webtrans-http3-16 section
 * 4.4): they map onto `0x52e4a40fa8db..0x52e5ac983162`, skipping the reserved GREASE codepoints `0x1f * N + 0x21`.
 */
internal object WtErrorCodes {
    const val FIRST: Long = 0x52e4a40fa8db
    const val LAST: Long = 0x52e5ac983162
    const val MAX_APPLICATION_CODE: Long = 0xffffffffL

    /** The HTTP/3 code that carries application code [n]; [n] must be 0..2^32-1. */
    fun toHttp3(n: Long): Long {
        require(n in 0..MAX_APPLICATION_CODE) { "WebTransport error code $n is not in 0..2^32-1" }
        return FIRST + n + n / 0x1e
    }

    /** The application code [h] carries, or null when it is outside the range or a GREASE codepoint. */
    fun fromHttp3(h: Long): Long? {
        if (h !in FIRST..LAST || (h - 0x21) % 0x1f == 0L) return null
        val s = h - FIRST
        return s - s / 0x1f
    }
}

/** The value of a WT_CLOSE_SESSION capsule (section 6): a 32-bit code, then a UTF-8 reason of at most 1024 bytes. */
internal object WtCloseCapsule {
    const val TYPE: Long = 0x2843
    const val MAX_REASON: Int = 1024

    /** [reason] is cut to 1024 bytes at a character boundary, never in the middle of a UTF-8 sequence. */
    fun encode(
        code: Long,
        reason: String,
    ): ByteArray {
        var r = reason.encodeToByteArray()
        if (r.size > MAX_REASON) {
            var end = MAX_REASON
            while (end > 0 && (r[end].toInt() and 0xc0) == 0x80) end-- // r[end] continues a sequence: cut before its start
            r = r.copyOf(end)
        }
        return byteArrayOf((code ushr 24).toByte(), (code ushr 16).toByte(), (code ushr 8).toByte(), code.toByte()) + r
    }

    /** Code and reason, or null when the value is malformed: shorter than 4 bytes, a reason above 1024 bytes or not UTF-8. */
    fun decode(value: ByteArray): Pair<Long, String>? {
        if (value.size < 4 || value.size - 4 > MAX_REASON) return null
        var code = 0L
        for (i in 0 until 4) code = (code shl 8) or (value[i].toLong() and 0xff)
        val reason =
            try {
                value.decodeToString(4, value.size, throwOnInvalidSequence = true)
            } catch (_: CharacterCodingException) {
                return null
            }
        return code to reason
    }
}

/** WT_DRAIN_SESSION (section 4.7): no value. */
internal const val WT_DRAIN_SESSION: Long = 0x78ae
