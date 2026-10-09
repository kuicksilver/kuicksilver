// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.frame

/** QUIC variable-length integers (RFC 9000 section 16), as HTTP/3 uses them for frame and stream headers. */
internal object VarInt {
    const val MAX: Long = (1L shl 62) - 1

    fun size(v: Long): Int {
        require(v in 0..MAX) { "varint out of range: $v" }
        return when {
            v < 64 -> 1
            v < 16384 -> 2
            v < (1L shl 30) -> 4
            else -> 8
        }
    }

    /** Length of the varint whose first byte is [first]. */
    fun encodedLength(first: Byte): Int = 1 shl ((first.toInt() and 0xff) ushr 6)

    fun write(
        v: Long,
        out: ByteArray,
        off: Int,
    ): Int {
        val n = size(v)
        var x = v
        for (i in n - 1 downTo 0) {
            out[off + i] = x.toByte()
            x = x ushr 8
        }
        out[off] = (out[off].toInt() and 0x3f or ((n.countTrailingZeroBits()) shl 6)).toByte()
        return n
    }

    fun encode(v: Long): ByteArray {
        val b = ByteArray(size(v))
        write(v, b, 0)
        return b
    }

    /** The value at [off], or -1 when fewer than its length remain before [end]. */
    fun read(
        buf: ByteArray,
        off: Int,
        end: Int,
    ): Long {
        if (off >= end) return -1
        val n = encodedLength(buf[off])
        if (end - off < n) return -1
        var v = (buf[off].toLong() and 0x3f)
        for (i in 1 until n) v = (v shl 8) or (buf[off + i].toLong() and 0xff)
        return v
    }
}
