// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.hpack

/** An HPACK decoding error (RFC 7541 sections 2.3.3, 4.2, 5.1, 5.2, 6.3): a connection error of type COMPRESSION_ERROR (RFC 9113 section 4.3). */
internal class HpackError(
    message: String,
) : Exception(message)

/** Field names and values are octets (RFC 9110 section 5.5): one char per byte, ISO-8859-1. */
internal fun String.latin1(): ByteArray = ByteArray(length) { this[it].code.toByte() }

internal fun ByteArray.latin1(
    off: Int = 0,
    len: Int = size - off,
): String {
    val c = CharArray(len) { Char(this[off + it].toInt() and 0xff) }
    return c.concatToString()
}

/**
 * Reads prefixed integers and string literals (RFC 7541 sections 5.1-5.2) from one field block. A copy of
 * kuicksilver-http3's `QpackReader` (ADR-0017) with HPACK's ceilings: integers fit 31 bits (an index, a length or a
 * table size above that is never valid here), and a string's declared length is checked against [maxStringLength] and
 * the bytes left in the block before anything is allocated.
 */
internal class HpackReader(
    val buf: ByteArray,
    var pos: Int,
    val end: Int,
    private val maxStringLength: Int,
) {
    val remaining: Int get() = end - pos

    /** Literal bytes (raw or Huffman-decoded) allocated so far: a test hook for the decompression limits. */
    var allocated: Long = 0
        private set

    fun peek(): Int {
        if (pos >= end) throw HpackError("field block ends inside a representation")
        return buf[pos].toInt() and 0xff
    }

    /** A [prefixBits]-bit prefixed integer; above 2^31 - 1 (an overflow for every HPACK use) is a decoding error. */
    fun readInt(prefixBits: Int): Int {
        val mask = (1 shl prefixBits) - 1
        var v = (peek() and mask).toLong()
        pos++
        if (v < mask) return v.toInt()
        var shift = 0
        while (true) {
            val b = peek()
            pos++
            v += (b and 0x7f).toLong() shl shift
            if (v > Int.MAX_VALUE) throw HpackError("integer above 2^31 - 1")
            if (b and 0x80 == 0) return v.toInt()
            shift += 7
            // five continuation bytes carry 35 bits: a sixth can only add zero bits or overflow
            if (shift > 28) throw HpackError("integer with more than five continuation bytes")
        }
    }

    /** A string literal whose H bit sits just above a [prefixBits]-bit length (section 5.2). */
    fun readString(prefixBits: Int = 7): String {
        val huffman = (peek() shr prefixBits) and 1 == 1
        val len = readInt(prefixBits)
        if (len > remaining) throw HpackError("string of $len bytes beyond the end of the field block")
        // a Huffman code is at least 5 bits per octet, so its output is at most 8/5 of its length
        if (!huffman && len > maxStringLength) throw HpackError("string of $len bytes above $maxStringLength")
        val s =
            if (huffman) {
                Huffman.decode(buf, pos, len, maxStringLength).also { allocated += it.size }.latin1()
            } else {
                allocated += len
                buf.latin1(pos, len)
            }
        pos += len
        return s
    }
}

/** Growable output for HPACK encodings (a copy of kuicksilver-http3's `QpackWriter`, ADR-0017). */
internal class HpackWriter(
    initial: Int = 64,
) {
    private var buf = ByteArray(initial)
    var size: Int = 0
        private set

    fun writeByte(b: Int) {
        ensure(1)
        buf[size++] = b.toByte()
    }

    fun writeBytes(b: ByteArray) {
        ensure(b.size)
        b.copyInto(buf, size)
        size += b.size
    }

    /** [firstByteFlags] carries the bits above the [prefixBits]-bit prefix (section 5.1). */
    fun writeInt(
        firstByteFlags: Int,
        prefixBits: Int,
        v: Int,
    ) {
        val mask = (1 shl prefixBits) - 1
        if (v < mask) {
            writeByte(firstByteFlags or v)
            return
        }
        writeByte(firstByteFlags or mask)
        var x = v - mask
        while (x >= 128) {
            writeByte((x and 0x7f) or 0x80)
            x = x ushr 7
        }
        writeByte(x)
    }

    /** A string literal with a 7-bit length (section 5.2), Huffman-coded when [huffman]. */
    fun writeString(
        s: String,
        huffman: Boolean,
    ) {
        val raw = s.latin1()
        if (huffman) {
            writeInt(0x80, 7, Huffman.encodedLength(raw))
            Huffman.encode(raw, this)
        } else {
            writeInt(0, 7, raw.size)
            writeBytes(raw)
        }
    }

    fun toByteArray(): ByteArray = buf.copyOf(size)

    private fun ensure(n: Int) {
        if (size + n > buf.size) buf = buf.copyOf(maxOf(buf.size * 2, size + n))
    }
}
