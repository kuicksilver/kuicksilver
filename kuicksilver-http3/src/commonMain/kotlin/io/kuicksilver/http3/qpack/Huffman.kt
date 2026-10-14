// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.qpack

import io.kuicksilver.http3.Http3ErrorCode

/** The static Huffman code of RFC 7541 Appendix B, shared by HPACK and QPACK (RFC 9204 section 4.1.2). */
internal object Huffman {
    private const val EOS = 256

    // Decoding tree: node n has children at 2n and 2n+1; a value >= 0 is the next node, -(symbol + 1) is a leaf, 0 is "no child".
    private val tree: IntArray by lazy {
        val t = IntArray(2 * 520)
        var next = 1
        for (sym in 0..256) {
            val code = HuffmanTable.CODES[sym]
            val len = HuffmanTable.LENGTHS[sym].toInt()
            var node = 0
            for (i in len - 1 downTo 0) {
                val bit = (code ushr i) and 1
                val slot = 2 * node + bit
                if (i == 0) {
                    t[slot] = -(sym + 1)
                } else {
                    if (t[slot] == 0) t[slot] = next++
                    node = t[slot]
                }
            }
        }
        t
    }

    fun encodedLength(s: ByteArray): Int {
        var bits = 0L
        for (b in s) bits += HuffmanTable.LENGTHS[b.toInt() and 0xff]
        return (
            (bits + 7) /
                8
        ).toInt()
    }

    fun encode(
        s: ByteArray,
        out: QpackWriter,
    ) {
        var acc = 0L
        var n = 0
        for (b in s) {
            val sym = b.toInt() and 0xff
            acc = (acc shl HuffmanTable.LENGTHS[sym].toInt()) or HuffmanTable.CODES[sym].toLong()
            n += HuffmanTable.LENGTHS[sym]
            while (n >= 8) {
                n -= 8
                out.writeByte((acc ushr n).toInt() and 0xff)
            }
            acc = acc and ((1L shl n) - 1)
        }
        if (n > 0) out.writeByte(((acc shl (8 - n)) or ((1L shl (8 - n)) - 1)).toInt() and 0xff) // pad with the EOS prefix (ones)
    }

    /** Decodes [len] bytes at [off]; more than [maxOut] output bytes -> [QpackStringTooLong]. EOS inside, padding over 7 bits or not all ones -> [errorCode]. */
    fun decode(
        buf: ByteArray,
        off: Int,
        len: Int,
        maxOut: Int,
        errorCode: Long = Http3ErrorCode.QPACK_DECOMPRESSION_FAILED,
    ): ByteArray {
        val t = tree
        var out = ByteArray(minOf(maxOf(len * 8 / 5, 16), maxOut.coerceAtLeast(1)))
        var n = 0
        var node = 0
        var pendingBits = 0
        var pendingOnes = true
        for (i in off until off + len) {
            val byte = buf[i].toInt() and 0xff
            for (j in 7 downTo 0) {
                val bit = (byte ushr j) and 1
                val v = t[2 * node + bit]
                pendingBits++
                if (bit == 0) pendingOnes = false
                if (v < 0) {
                    val sym = -v - 1
                    if (sym == EOS) throw QpackError(errorCode, "EOS inside a Huffman string")
                    if (n == maxOut) throw QpackStringTooLong(errorCode, "Huffman string longer than $maxOut bytes")
                    if (n == out.size) out = out.copyOf(minOf(out.size * 2, maxOut))
                    out[n++] = sym.toByte()
                    node = 0
                    pendingBits = 0
                    pendingOnes = true
                } else if (v == 0) {
                    throw QpackError(errorCode, "invalid Huffman code")
                } else {
                    node = v
                }
            }
        }
        if (pendingBits > 7 || !pendingOnes) throw QpackError(errorCode, "invalid Huffman padding")
        return out.copyOf(n)
    }
}
