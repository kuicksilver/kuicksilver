// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.qpack

import io.kuicksilver.http3.Http3ErrorCode

/** A QPACK failure; [code] is QPACK_DECOMPRESSION_FAILED, QPACK_ENCODER_STREAM_ERROR or QPACK_DECODER_STREAM_ERROR (RFC 9204 section 6). */
internal open class QpackError(
    val code: Long,
    message: String,
) : Exception(message)

/**
 * The input ended inside an instruction: an error for a complete field section, "wait for more" on the encoder and
 * decoder streams. [needed] is the instruction's full length from its first byte when the string literal's length prefix
 * was read (RFC 9204 section 4.1.2), else 0 ("unknown: parse again when more arrives").
 */
internal class QpackTruncated(
    code: Long,
    val needed: Int = 0,
) : QpackError(code, "truncated")

/**
 * A string literal longer than the reader's ceiling ([QpackLimits.maxStringLength]). In a field section this is "larger
 * than we decode" (RFC 9204 section 7.4): the section is too large, a stream error; on the encoder stream it stays a
 * connection error of [code].
 */
internal class QpackStringTooLong(
    code: Long,
    message: String,
) : QpackError(code, message)

/**
 * Ceilings checked before memory is allocated (threat-model 3.17). The decoder reads field sections with
 * [maxStringLength] = our SETTINGS_MAX_FIELD_SECTION_SIZE (no single string can fit a larger section) and the encoder
 * stream with min(our table capacity, that limit), at least the 64 KiB default (`encoderStreamLimits`).
 */
internal class QpackLimits(
    val maxInteger: Long = (1L shl 62) - 1,
    val maxStringLength: Int = 65_536,
)

/** Field names and values are octets (RFC 9110 section 5.5): one char per byte, ISO-8859-1. */
internal fun String.latin1(): ByteArray = ByteArray(length) { this[it].code.toByte() }

internal fun ByteArray.latin1(
    off: Int = 0,
    len: Int = size - off,
): String {
    val c = CharArray(len) { Char(this[off + it].toInt() and 0xff) }
    return c.concatToString()
}

/** Reads prefixed integers and string literals (RFC 7541 sections 5.1-5.2, RFC 9204 section 4.1); [errorCode] is what a failure reports. */
internal class QpackReader(
    val buf: ByteArray,
    var pos: Int,
    val end: Int,
    private val errorCode: Long = Http3ErrorCode.QPACK_DECOMPRESSION_FAILED,
) {
    val remaining: Int get() = end - pos

    /** Where the instruction being parsed started; [readString] reports the instruction's full length from here. */
    var instructionStart: Int = pos

    fun fail(message: String): Nothing = throw QpackError(errorCode, message)

    fun peek(): Int {
        if (pos >= end) throw QpackTruncated(errorCode)
        return buf[pos].toInt() and 0xff
    }

    fun readInt(
        prefixBits: Int,
        limits: QpackLimits,
    ): Long {
        val mask = (1 shl prefixBits) - 1
        var v = (peek() and mask).toLong()
        pos++
        if (v < mask) return v
        var shift = 0
        for (i in 0 until 10) {
            val b = peek()
            pos++
            // bits shifted past bit 62 would be lost (a 10th byte at shift 63): an overflow, RFC 7541 section 5.1
            if ((b and 0x7f).toLong() > (Long.MAX_VALUE ushr shift)) fail("integer above ${limits.maxInteger}")
            v += (b and 0x7f).toLong() shl shift
            if (v > limits.maxInteger || v < 0) fail("integer above ${limits.maxInteger}")
            if (b and 0x80 == 0) return v
            shift += 7
        }
        fail("integer longer than 10 continuation bytes")
    }

    private fun tooLong(
        len: Long,
        limits: QpackLimits,
    ): Nothing = throw QpackStringTooLong(errorCode, "string of $len bytes above ${limits.maxStringLength}")

    /** A string literal whose H bit sits just above a [prefixBits]-bit length; [QpackStringTooLong] above the ceiling. */
    fun readString(
        prefixBits: Int,
        limits: QpackLimits,
    ): String {
        val huffman = (peek() shr prefixBits) and 1 == 1
        val len = readInt(prefixBits, limits)
        // ceilings first (a Huffman literal decodes to at least 8/30 of its length), then "not all here yet"
        if (len > limits.maxStringLength.toLong() * (if (huffman) 4 else 1)) tooLong(len, limits)
        if (len > remaining) {
            throw QpackTruncated(errorCode, needed = ((pos - instructionStart) + len).coerceAtMost(Int.MAX_VALUE.toLong()).toInt())
        }
        val n = len.toInt()
        val s =
            if (huffman) {
                Huffman.decode(buf, pos, n, limits.maxStringLength, errorCode).latin1()
            } else {
                if (n > limits.maxStringLength) tooLong(n.toLong(), limits)
                buf.latin1(pos, n)
            }
        pos += n
        return s
    }
}

/** Growable output for QPACK encodings. */
internal class QpackWriter(
    initial: Int = 64,
) {
    private var buf = ByteArray(initial)
    var size: Int = 0
        private set

    fun writeByte(b: Int) {
        ensure(1)
        buf[size++] = b.toByte()
    }

    fun writeBytes(
        b: ByteArray,
        off: Int = 0,
        len: Int = b.size - off,
    ) {
        ensure(len)
        b.copyInto(buf, size, off, off + len)
        size += len
    }

    /** [firstByteFlags] carries the bits above the [prefixBits]-bit prefix. */
    fun writeInt(
        firstByteFlags: Int,
        prefixBits: Int,
        v: Long,
    ) {
        val mask = (1 shl prefixBits) - 1
        if (v < mask) {
            writeByte(firstByteFlags or v.toInt())
            return
        }
        writeByte(firstByteFlags or mask)
        var x = v - mask
        while (x >= 128) {
            writeByte(((x and 0x7f) or 0x80).toInt())
            x = x ushr 7
        }
        writeByte(x.toInt())
    }

    /** A string literal; the H bit is `1 shl prefixBits`, set when [huffman] (callers pass true only when it is shorter). */
    fun writeString(
        flagsMask: Int,
        prefixBits: Int,
        s: String,
        huffman: Boolean,
    ) {
        val raw = s.latin1()
        if (huffman) {
            writeInt(flagsMask or (1 shl prefixBits), prefixBits, Huffman.encodedLength(raw).toLong())
            Huffman.encode(raw, this)
        } else {
            writeInt(flagsMask, prefixBits, raw.size.toLong())
            writeBytes(raw)
        }
    }

    /** Huffman when it saves bytes (RFC 7541 section 5.2 leaves the choice to the encoder). */
    fun writeStringAuto(
        flagsMask: Int,
        prefixBits: Int,
        s: String,
    ) {
        val raw = s.latin1()
        writeString(
            flagsMask,
            prefixBits,
            s,
            Huffman.encodedLength(raw) < raw.size,
        )
    }

    fun toByteArray(): ByteArray = buf.copyOf(size)

    fun reset() {
        size = 0
    }

    private fun ensure(n: Int) {
        if (size + n > buf.size) buf = buf.copyOf(maxOf(buf.size * 2, size + n))
    }
}
