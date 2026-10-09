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
 */
internal class QpackDecoder(
    val maxTableCapacity: Long,
    val maxBlockedStreams: Int,
    val maxFieldSectionSize: Long,
    private val limits: QpackLimits = QpackLimits(),
) {
    private val table = DynamicTable(0)
    private var pending = ByteArray(0) // an encoder-stream instruction cut by the transport
    private val out = QpackWriter() // decoder-stream instructions not yet sent
    private val blocked = HashSet<Long>()
    private var knownReceived = 0L // inserts the encoder knows we have (acks + increments)

    val insertCount: Long get() = table.insertCount
    val tableSize: Long get() = table.size
    val blockedCount: Int get() = blocked.size

    fun onEncoderStream(
        bytes: ByteArray,
        off: Int,
        len: Int,
    ) {
        val joined = pending.isNotEmpty()
        val buf = if (joined) pending + bytes.copyOfRange(off, off + len) else bytes
        val start = if (joined) 0 else off
        val end = if (joined) buf.size else off + len
        val r = QpackReader(buf, start, end, Http3ErrorCode.QPACK_ENCODER_STREAM_ERROR)
        while (r.remaining > 0) {
            val mark = r.pos
            try {
                encoderInstruction(r)
            } catch (t: QpackTruncated) {
                val rest = end - mark
                if (rest > 2 * limits.maxStringLength + 64) r.fail("encoder-stream instruction above ${2 * limits.maxStringLength} bytes")
                pending = buf.copyOfRange(mark, end)
                return
            }
        }
        pending = ByteArray(0)
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
                            r.readString(7, limits)
                    }

                    b and 0x20 != 0 -> {
                        val name = r.readString(3, limits)
                        name to r.readString(7, limits)
                    }

                    b and 0x10 != 0 -> {
                        dynamic(base + r.readInt(4, limits))
                    }

                    else -> {
                        val i = r.readInt(3, limits)
                        dynamic(base + i).first to r.readString(7, limits)
                    }
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
        if (maxTableCapacity > 0) out.writeInt(0x40, 6, streamId)
    }

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
