// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.qpack

import io.kuicksilver.http3.Http3ErrorCode

/** Outcome of decoding one encoded field section. */
internal sealed interface DecodeResult {
    /** [decodedSize] is the RFC 9114 section 4.2.2 size: name + value + 32 per field. */
    class Decoded(
        val fields: List<Pair<String, String>>,
        val decodedSize: Long,
    ) : DecodeResult

    /** References entries not yet received on the encoder stream; decode again once `insertCount >= requiredInsertCount`. */
    class Blocked(
        val requiredInsertCount: Long,
    ) : DecodeResult

    /** The decoded size passed the limit; decoding stopped there. */
    object TooLarge : DecodeResult
}

/**
 * QPACK decoder (RFC 9204 sections 2.2, 3, 4.3-4.5): applies the peer's encoder stream to the dynamic table, decodes field
 * sections and produces the decoder-stream instructions. [maxTableCapacity] and [maxBlockedStreams] are what we advertised.
 * [limits] bound the encoder stream; by default a string may be as long as the largest field we accept that fits the
 * table (RFC 9204 section 7.4), at least 64 KiB: an entry never exceeds the advertised capacity, so memory stays bounded by it.
 */
internal class QpackDecoder(
    val maxTableCapacity: Long,
    val maxBlockedStreams: Int,
    val maxFieldSectionSize: Long,
    private val limits: QpackLimits = encoderStreamLimits(maxTableCapacity, maxFieldSectionSize),
) {
    /** Field sections: no single string can exceed the section limit (RFC 9204 section 7.4 ties the ceiling to it). */
    private val fieldLimits = QpackLimits(limits.maxInteger, maxFieldSectionSize.coerceIn(1L, Int.MAX_VALUE.toLong()).toInt())
    private val table = DynamicTable(0)

    /**
     * The longest encoder-stream instruction we wait for whole: its name and value fit the table together (RFC 9204 section
     * 3.2.2) and are each within the string ceiling, and a Huffman literal takes up to 4 bytes per octet it carries (codes of
     * up to 30 bits, RFC 7541 appendix B), plus the prefixes. Twice the ceiling, as it was, refused inserts the table takes.
     */
    private val instructionCeiling: Long =
        ((4L * minOf(maxTableCapacity, 2L * limits.maxStringLength)).coerceAtLeast(2L * limits.maxStringLength) + 64)
            .coerceAtMost(Int.MAX_VALUE.toLong())
    private val pend = QpackWriter(0) // an encoder-stream instruction cut by the transport, appended to as its bytes arrive
    private var needed = 0 // the full length of the instruction in [pend] once known (0: parse again when more arrives)
    private val out = QpackWriter() // decoder-stream instructions not yet sent
    private val blocked = HashSet<Long>()
    private var knownReceived = 0L // inserts the encoder knows we have (acks + increments)

    val insertCount: Long get() = table.insertCount
    val tableSize: Long get() = table.size
    val blockedCount: Int get() = blocked.size

    /** Bytes the encoder-stream parser walked over plus bytes copied while reassembling (a test hook for the reassembly cost). */
    internal var scannedBytes: Long = 0

    /**
     * Applies encoder-stream bytes as they arrive. An instruction cut by the transport is reassembled in linear time
     * (RFC 9204 section 7.4): once its length is known from the string literal's prefix, bytes are only appended until it
     * is complete; the parser never re-reads the accumulated prefix per fragment.
     */
    fun onEncoderStream(
        bytes: ByteArray,
        off: Int,
        len: Int,
    ) {
        if (pend.size == 0) {
            parseInstructions(bytes, off, off + len)
            return
        }
        pend.writeBytes(bytes, off, len)
        scannedBytes += len
        if (pend.size < needed) return
        val buf = pend.toByteArray()
        pend.reset()
        needed = 0
        scannedBytes += buf.size
        parseInstructions(buf, 0, buf.size)
    }

    private fun parseInstructions(
        buf: ByteArray,
        start: Int,
        end: Int,
    ) {
        val r = QpackReader(buf, start, end, Http3ErrorCode.QPACK_ENCODER_STREAM_ERROR)
        while (r.remaining > 0) {
            val mark = r.pos
            r.instructionStart = mark
            try {
                encoderInstruction(r)
                scannedBytes += r.pos - mark
            } catch (t: QpackTruncated) {
                scannedBytes += r.pos - mark
                val rest = end - mark
                if (rest > instructionCeiling || t.needed > instructionCeiling) {
                    r.fail("encoder-stream instruction above $instructionCeiling bytes")
                }
                pend.writeBytes(buf, mark, rest)
                scannedBytes += rest
                needed = t.needed
                return
            }
        }
    }

    private fun encoderInstruction(r: QpackReader) {
        val b = r.peek()
        when {
            b and 0x80 != 0 -> { // Insert with Name Reference
                val static = b and 0x40 != 0
                val idx = r.readInt(6, limits)
                val name =
                    if (static) {
                        if (idx >= StaticTable.SIZE) r.fail("static index $idx")
                        StaticTable.name(idx.toInt())
                    } else {
                        (table.absolute(table.insertCount - idx - 1) ?: r.fail("dynamic name reference $idx")).first
                    }
                val value = r.readString(7, limits)
                insert(r, name, value)
            }

            b and 0x40 != 0 -> {
                val name = r.readString(5, limits)
                val value = r.readString(7, limits)
                insert(r, name, value)
            }

            // Insert with Literal Name
            b and 0x20 != 0 -> { // Set Dynamic Table Capacity
                val c = r.readInt(5, limits)
                if (c >
                    maxTableCapacity
                ) {
                    r.fail("capacity $c above the advertised $maxTableCapacity")
                }
                table.setCapacity(c)
            }

            else -> {
                val idx = r.readInt(5, limits)
                val e =
                    table.absolute(table.insertCount - idx - 1) ?: r.fail("duplicate of $idx")
                insert(r, e.first, e.second)
            }
        }
    }

    private fun insert(
        r: QpackReader,
        name: String,
        value: String,
    ) {
        if (!table.insert(name, value)) r.fail("entry larger than the table")
    }

    fun decode(
        streamId: Long,
        block: ByteArray,
    ): DecodeResult {
        val r = QpackReader(block, 0, block.size)
        val ric = requiredInsertCount(r, r.readInt(8, limits))
        val sign = r.peek() and 0x80 != 0
        val delta = r.readInt(7, limits)
        val base =
            if (!sign) {
                ric + delta
            } else {
                if (delta >= ric) r.fail("negative base")
                ric - delta - 1
            }
        if (ric > table.insertCount) return DecodeResult.Blocked(ric)
        val fields = ArrayList<Pair<String, String>>()
        var size = 0L

        fun dynamic(abs: Long): Pair<String, String> {
            if (abs < 0 ||
                abs >= ric
            ) {
                r.fail("dynamic index $abs outside the required insert count $ric")
            }
            return table.absolute(abs)
                ?: r.fail("evicted entry $abs")
        }

        fun static(i: Long): Pair<String, String> {
            if (i >=
                StaticTable.SIZE
            ) {
                r.fail("static index $i")
            }
            return StaticTable.name(i.toInt()) to StaticTable.value(i.toInt())
        }
        while (r.remaining > 0) {
            val b = r.peek()
            val f: Pair<String, String> =
                try {
                    fieldLine(r, b, base, ::dynamic, ::static)
                } catch (e: QpackStringTooLong) {
                    // one string larger than we decode: the section is too large, a stream error (RFC 9204 section 7.4)
                    acknowledge(streamId, ric)
                    return DecodeResult.TooLarge
                }
            size += entrySize(f.first, f.second)
            if (size > maxFieldSectionSize) {
                acknowledge(streamId, ric)
                return DecodeResult.TooLarge
            }
            fields += f
        }
        acknowledge(streamId, ric)
        return DecodeResult.Decoded(fields, size)
    }

    /** One field line (RFC 9204 sections 4.5.2-4.5.6) starting with byte [b]. */
    private fun fieldLine(
        r: QpackReader,
        b: Int,
        base: Long,
        dynamic: (Long) -> Pair<String, String>,
        static: (Long) -> Pair<String, String>,
    ): Pair<String, String> =
        when {
            b and 0x80 != 0 -> {
                val t = b and 0x40 != 0
                val i = r.readInt(6, limits)
                if (t) static(i) else dynamic(base - i - 1)
            }

            b and 0x40 != 0 -> {
                val t =
                    b and 0x10 != 0
                val i = r.readInt(4, limits)
                val name = if (t) static(i).first else dynamic(base - i - 1).first
                name to
                    r.readString(7, fieldLimits)
            }

            b and 0x20 != 0 -> {
                val name = r.readString(3, fieldLimits)
                name to r.readString(7, fieldLimits)
            }

            b and 0x10 != 0 -> {
                dynamic(base + r.readInt(4, limits))
            }

            else -> {
                val i = r.readInt(3, limits)
                dynamic(base + i).first to r.readString(7, fieldLimits)
            }
        }

    /** RFC 9204 section 4.5.1.1. */
    private fun requiredInsertCount(
        r: QpackReader,
        encoded: Long,
    ): Long {
        if (encoded == 0L) return 0
        val maxEntries = maxTableCapacity / 32
        val fullRange = 2 * maxEntries
        if (encoded > fullRange) r.fail("encoded required insert count $encoded above $fullRange")
        val maxValue = table.insertCount + maxEntries
        val maxWrapped = (maxValue / fullRange) * fullRange
        var ric = maxWrapped + encoded - 1
        if (ric > maxValue) {
            if (ric <= fullRange) r.fail("required insert count wraps below zero")
            ric -= fullRange
        }
        if (ric == 0L) r.fail("required insert count 0 encoded as non-zero")
        return ric
    }

    private fun acknowledge(
        streamId: Long,
        ric: Long,
    ) {
        unblock(streamId)
        if (ric == 0L) return
        out.writeInt(0x80, 7, streamId) // Section Acknowledgment
        if (ric > knownReceived) knownReceived = ric
    }

    fun markBlocked(streamId: Long) {
        if (streamId in blocked) return
        if (blocked.size >=
            maxBlockedStreams
        ) {
            throw QpackError(Http3ErrorCode.QPACK_DECOMPRESSION_FAILED, "more than $maxBlockedStreams blocked streams")
        }
        blocked += streamId
    }

    fun unblock(streamId: Long) {
        blocked -= streamId
    }

    /** The stream was reset or abandoned before its field sections were processed (RFC 9204 section 4.4.2). */
    fun cancelStream(streamId: Long) {
        unblock(streamId)
        if (maxTableCapacity > 0) {
            out.writeInt(0x40, 6, streamId)
            cancellationsMade++
        }
    }

    /** Stream Cancellation instructions made (a test hook). */
    var cancellationsMade: Long = 0
        private set

    /** Pending decoder-stream bytes: acknowledgments and cancellations first, then an Insert Count Increment for unannounced inserts. */
    fun drainDecoderStream(): ByteArray {
        if (table.insertCount >
            knownReceived
        ) {
            out.writeInt(0x00, 6, table.insertCount - knownReceived)
            knownReceived = table.insertCount
        }
        val b = out.toByteArray()
        out.reset()
        return b
    }
}

/** Largest encoder-stream string we ever read (256 MiB): keeps the instruction lengths (up to 4x for Huffman) within an Int. */
internal const val MAX_ENCODER_STREAM_STRING: Int = 1 shl 28

/**
 * The encoder-stream string ceiling of RFC 9204 section 7.4: the largest field we accept that fits the table,
 * min(table capacity, field-section limit), at least 64 KiB and at most [MAX_ENCODER_STREAM_STRING].
 */
internal fun encoderStreamLimits(
    maxTableCapacity: Long,
    maxFieldSectionSize: Long,
): QpackLimits {
    val default = QpackLimits()
    val largest =
        minOf(maxTableCapacity, maxFieldSectionSize).coerceIn(default.maxStringLength.toLong(), MAX_ENCODER_STREAM_STRING.toLong())
    return QpackLimits(maxStringLength = largest.toInt())
}
