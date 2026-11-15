// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.qpack

import io.kuicksilver.http3.Http3ErrorCode
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

/**
 * Decoder and encoder corners that the rest of the QPACK suite did not pin: every representation of RFC 9204 section 4.5
 * with and without the 'N' bit, the exact boundaries of section 3.2 and 4.5.1, the decoder's acknowledgment of a section
 * it refused as too large, and the encoder's eviction rules of section 2.1.1 with acknowledged, referenced and
 * unacknowledged entries.
 */
class QpackGapTest {
    private fun QpackDecoder.feed(w: QpackWriter) {
        val b = w.toByteArray()
        onEncoderStream(b, 0, b.size)
    }

    private fun QpackDecoder.feed(b: ByteArray) = onEncoderStream(b, 0, b.size)

    private fun insertLiteral(
        w: QpackWriter,
        name: String,
        value: String,
    ) {
        w.writeString(0x40, 5, name, huffman = false)
        w.writeString(0, 7, value, huffman = false)
    }

    /** A decoder whose table holds `x-a: 1` (absolute 0) and `x-b: 2` (absolute 1). */
    private fun twoEntries(max: Long = 65_536): QpackDecoder {
        val d = QpackDecoder(maxTableCapacity = 4096, maxBlockedStreams = 16, maxFieldSectionSize = max)
        val w = QpackWriter()
        w.writeInt(0x20, 5, 4096)
        insertLiteral(w, "x-a", "1")
        insertLiteral(w, "x-b", "2")
        d.feed(w)
        assertEquals(2, d.insertCount)
        return d
    }

    /**
     * RFC 9204 section 4.5.5: "A literal field line with post-Base name reference representation encodes a field line where
     * the field name matches the field name of a dynamic table entry with an absolute index greater than or equal to the
     * value of the Base" ('0000' pattern, 'N' bit, 3-bit index). Sections 4.5.4 and 4.5.6: "when a peer sends a field line
     * that it received represented as a literal field line with the 'N' bit set, it MUST use a literal representation to
     * forward this field line" -- so the decoder must report exactly the lines that carried 'N', whatever their form.
     */
    @Test fun negative_everyRepresentationAndItsNeverIndexBit() {
        val d = twoEntries()
        val s = QpackWriter()
        s.writeInt(0, 8, 3) // Required Insert Count 2 (2 mod 256 + 1)
        s.writeInt(0x80, 7, 1) // Sign 1, Delta Base 1: Base = 2 - 1 - 1 = 0, every dynamic reference is post-Base
        s.writeInt(0x10, 4, 1) // indexed, post-Base index 1 -> x-b: 2
        s.writeInt(0x00, 3, 1) // literal, post-Base name index 1, N = 0
        s.writeString(0, 7, "v", huffman = false)
        s.writeInt(0x08, 3, 1) // literal, post-Base name index 1, N = 1
        s.writeString(0, 7, "w", huffman = false)
        s.writeInt(0x50, 4, 1) // literal, static name 1 (:path), N = 0
        s.writeString(0, 7, "/", huffman = false)
        s.writeInt(0x70, 4, 1) // literal, static name 1 (:path), N = 1
        s.writeString(0, 7, "/s", huffman = false)
        s.writeString(0x20, 3, "x-c", huffman = false) // literal name (odd length), N = 0
        s.writeString(0, 7, "z", huffman = false)
        s.writeString(0x30, 3, "x-d", huffman = false) // literal name, N = 1
        s.writeString(0, 7, "y", huffman = false)
        s.writeInt(0xc0, 6, 1) // indexed, static 1
        s.writeInt(0x40, 4, 0) // literal, dynamic (pre-Base) name: Base 0 makes relative 0 absolute -1, so it is not used here
        val all = s.toByteArray()
        // the last line is invalid on purpose: decode the section without it first
        val ok = d.decode(4, all.copyOf(all.size - 1))
        val decoded = assertIs<DecodeResult.Decoded>(ok)
        assertEquals(
            listOf(
                "x-b" to "2",
                "x-b" to "v",
                "x-b" to "w",
                ":path" to "/",
                ":path" to "/s",
                "x-c" to "z",
                "x-d" to "y",
                ":path" to "/",
            ),
            decoded.fields,
        )
        assertEquals(listOf("x-b" to "w", ":path" to "/s", "x-d" to "y"), decoded.neverIndexed)
        // a pre-Base reference below a Base of 0 points at absolute -1
        val e = assertFailsWith<QpackError> { twoEntries().decode(8, all) }
        assertEquals(Http3ErrorCode.QPACK_DECOMPRESSION_FAILED, e.code)
    }

    /**
     * RFC 9204 section 4.5.1.2: "An endpoint MUST treat a field block with a Sign bit of 1 as invalid if the value of
     * Required Insert Count is less than or equal to the value of Delta Base." Delta Base equal to the Required Insert
     * Count is the first invalid value, even for a section with no field lines.
     */
    @Test fun negative_signedDeltaBaseEqualToRequiredInsertCount() {
        val s = QpackWriter()
        s.writeInt(0, 8, 3) // Required Insert Count 2
        s.writeInt(0x80, 7, 2) // Sign 1, Delta Base 2 = Required Insert Count: Base would be -1
        assertFailsWith<QpackError> { twoEntries().decode(0, s.toByteArray()) }
        val ok = QpackWriter()
        ok.writeInt(0, 8, 3)
        ok.writeInt(0x80, 7, 1) // Delta Base 1 < 2: Base 0 is valid
        assertIs<DecodeResult.Decoded>(twoEntries().decode(0, ok.toByteArray()))
    }

    /**
     * RFC 9204 section 4.5.1.1: "if ReqInsertCount > MaxValue: ... ReqInsertCount -= FullRange". A value equal to MaxValue
     * is not wrapped: with a 64-byte table (MaxEntries 2, FullRange 4) and no inserts, MaxValue is 2 and an encoded 3 is a
     * Required Insert Count of 2 (blocked), not an error.
     */
    @Test fun negative_requiredInsertCountEqualToMaxValueIsNotWrapped() {
        val d = QpackDecoder(maxTableCapacity = 64, maxBlockedStreams = 16, maxFieldSectionSize = 65_536)
        assertEquals(2, d.requiredInsertCount(3))
        assertEquals(2, assertIs<DecodeResult.Blocked>(d.decode(0, byteArrayOf(3, 0))).requiredInsertCount)
        assertEquals(1, d.requiredInsertCount(2))
        assertFailsWith<QpackError> { d.requiredInsertCount(5) } // above FullRange
    }

    /**
     * RFC 9204 section 3.2.2: "It is an error if the encoder attempts to add an entry that is larger than the dynamic table
     * capacity" -- an entry exactly as large as the capacity is not larger, and fills the table.
     */
    @Test fun negative_entryExactlyAsLargeAsTheCapacityIsInserted() {
        val d = QpackDecoder(maxTableCapacity = 100, maxBlockedStreams = 16, maxFieldSectionSize = 65_536)
        val w = QpackWriter()
        w.writeInt(0x20, 5, 64)
        insertLiteral(w, "a", "b".repeat(31)) // 1 + 31 + 32 = 64
        d.feed(w)
        assertEquals(1, d.insertCount)
        assertEquals(64, d.tableSize)
        val over = QpackWriter()
        insertLiteral(over, "a", "b".repeat(32)) // 65
        val e = assertFailsWith<QpackError> { d.feed(over) }
        assertEquals(Http3ErrorCode.QPACK_ENCODER_STREAM_ERROR, e.code)
    }

    /**
     * RFC 9204 section 3.2.2: "Whenever the dynamic table capacity is reduced by the encoder (Section 4.3.1), entries are
     * evicted from the end of the dynamic table until the size of the dynamic table is less than or equal to the new
     * capacity." Equal keeps every entry; one byte less evicts the oldest, and a reference to it then fails (section 2.2.3:
     * a reference to an evicted entry is QPACK_DECOMPRESSION_FAILED).
     */
    @Test fun negative_capacityReductionEvictsDownToTheNewCapacityOnly() {
        val d = QpackDecoder(maxTableCapacity = 200, maxBlockedStreams = 16, maxFieldSectionSize = 65_536)
        val w = QpackWriter()
        w.writeInt(0x20, 5, 200)
        insertLiteral(w, "a", "1234567") // 40
        insertLiteral(w, "b", "1234567") // 40
        d.feed(w)
        assertEquals(80, d.tableSize)
        d.feed(QpackWriter().also { it.writeInt(0x20, 5, 80) })
        assertEquals(80, d.tableSize) // equal: nothing evicted
        d.feed(QpackWriter().also { it.writeInt(0x20, 5, 79) })
        assertEquals(40, d.tableSize) // the oldest entry went
        val newest = QpackWriter()
        newest.writeInt(0, 8, 3) // Required Insert Count 2 (MaxEntries 6, FullRange 12)
        newest.writeInt(0, 7, 0) // Base 2
        newest.writeInt(0x80, 6, 0) // relative 0 -> absolute 1
        assertEquals(listOf("b" to "1234567"), assertIs<DecodeResult.Decoded>(d.decode(0, newest.toByteArray())).fields)
        val evicted = QpackWriter()
        evicted.writeInt(0, 8, 3)
        evicted.writeInt(0, 7, 0)
        evicted.writeInt(0x80, 6, 1) // relative 1 -> absolute 0, evicted
        val e = assertFailsWith<QpackError> { d.decode(4, evicted.toByteArray()) }
        assertEquals(Http3ErrorCode.QPACK_DECOMPRESSION_FAILED, e.code)
    }

    /**
     * RFC 9114 section 4.2.2: the field section size is "the length of the name and value in bytes plus an overhead of 32
     * bytes for each field", and SETTINGS_MAX_FIELD_SECTION_SIZE is the largest size accepted: a section of exactly that
     * size decodes.
     */
    @Test fun negative_sectionOfExactlyTheMaximumSizeDecodes() {
        val s = QpackWriter()
        s.writeInt(0, 8, 0)
        s.writeInt(0, 7, 0)
        s.writeString(0x20, 3, "x", huffman = false)
        s.writeString(0, 7, "y", huffman = false) // 1 + 1 + 32 = 34
        val exact = QpackDecoder(0, 0, maxFieldSectionSize = 34).decode(0, s.toByteArray())
        assertEquals(34, assertIs<DecodeResult.Decoded>(exact).decodedSize)
        assertIs<DecodeResult.TooLarge>(QpackDecoder(0, 0, maxFieldSectionSize = 33).decode(0, s.toByteArray()))
    }

    /**
     * RFC 9204 section 2.2.2.1: "After the decoder finishes decoding a field section encoded using representations
     * containing dynamic table references, it MUST emit a Section Acknowledgment instruction". A section the decoder stops
     * reading because it is too large (sum of fields, or one string longer than it decodes, section 7.4) still referenced
     * the table: without the acknowledgment the encoder keeps those entries pinned forever (section 2.1.1) and the stream
     * stays counted as blocked.
     */
    @Test fun negative_tooLargeSectionIsStillAcknowledged() {
        for (valueTooLong in listOf(false, true)) {
            val d = twoEntries(max = 40)
            d.drainDecoderStream() // the Insert Count Increment of the two inserts
            d.markBlocked(4)
            val s = QpackWriter()
            s.writeInt(0, 8, 3) // Required Insert Count 2
            s.writeInt(0, 7, 0) // Base 2
            s.writeInt(0x80, 6, 0) // x-b: 2 (36 bytes)
            if (valueTooLong) {
                s.writeInt(0x50, 4, 1) // :path with a 41-byte value: one string longer than the section limit
                s.writeString(0, 7, "/" + "p".repeat(40), huffman = false)
            } else {
                s.writeInt(0x80, 6, 1) // x-a: 1, 72 bytes in all
            }
            val r = assertIs<DecodeResult.TooLarge>(d.decode(4, s.toByteArray()))
            assertEquals(valueTooLong, r.valueTooLong)
            assertContentEquals(byteArrayOf(0x84.toByte()), d.drainDecoderStream(), "Section Acknowledgment for stream 4")
            assertEquals(0, d.blockedCount)
        }
    }

    // ---------------------------------------------------------------- encoder, RFC 9204 section 2.1.1

    /** An encoder and a decoder joined by their streams; sections are decoded when the test says so. */
    private class Pair2(
        cap: Long,
        blocked: Long,
    ) {
        val e = QpackEncoder(maxCapacity = cap)
        val d = QpackDecoder(maxTableCapacity = cap, maxBlockedStreams = 100, maxFieldSectionSize = 65_536)

        init {
            e.onPeerSettings(cap, blocked)
        }

        fun encode(
            stream: Long,
            vararg f: Pair<String, String>,
        ): ByteArray {
            val block = e.encode(stream, f.toList())
            val ins = e.drainEncoderStream()
            d.onEncoderStream(ins, 0, ins.size)
            return block
        }

        fun decode(
            stream: Long,
            block: ByteArray,
        ): List<Pair<String, String>> = assertIs<DecodeResult.Decoded>(d.decode(stream, block)).fields

        /** The decoder's acknowledgments and increments reach the encoder. */
        fun ack() {
            val b = d.drainDecoderStream()
            e.onDecoderStream(b, 0, b.size)
        }
    }

    private fun v(n: Int) = "v".repeat(n)

    /**
     * Section 2.1.1: "Once the insertion of a dynamic table entry has been acknowledged and there are no outstanding
     * references to the entry in unacknowledged representations, the entry becomes evictable" and "If the dynamic table
     * does not contain enough room for a new entry without evicting other entries, and the entries that would be evicted
     * are not evictable, the encoder MUST NOT insert that entry"; section 3.2.2 evicts "until the size of the dynamic table
     * is less than or equal to (table capacity - size of new entry)". So an insert that needs exactly the room of the
     * oldest evictable entry happens, one that would also need a referenced entry does not, and a late section that
     * references that entry still decodes.
     */
    @Test fun negative_encoderEvictsExactlyTheEvictableEntriesItNeeds() {
        val p = Pair2(cap = 128, blocked = 100)
        p.ack()
        val s0 = p.encode(0, "x-1" to v(5)) // 3 + 5 + 32 = 40
        assertEquals(listOf("x-1" to v(5)), p.decode(0, s0))
        p.ack() // x-1 acknowledged and unreferenced: evictable
        val s4 = p.encode(4, "x-2" to v(5))
        p.ack() // Insert Count Increment: x-2 acknowledged, but s4 (not decoded yet) still references it
        val s8 = p.encode(8, "x-3" to v(5))
        assertEquals(listOf("x-3" to v(5)), p.decode(8, s8))
        p.ack()
        assertEquals(3, p.e.insertCount) // 120 of 128 bytes
        // 48 bytes need exactly the 40 of x-1 more: x-1 goes, x-2 stays
        val s12 = p.encode(12, "x-4" to v(13))
        assertEquals(4, p.e.insertCount, "the insert that only needs the evictable oldest entry happens")
        // 48 more bytes would need x-2 too, which s4 still references: no insert
        val s16 = p.encode(16, "x-5" to v(13))
        assertEquals(4, p.e.insertCount, "an entry referenced by an unacknowledged section is not evicted")
        assertEquals(listOf("x-2" to v(5)), p.decode(4, s4))
        assertEquals(listOf("x-4" to v(13)), p.decode(12, s12))
        assertEquals(listOf("x-5" to v(13)), p.decode(16, s16))
    }

    /**
     * Section 2.1.1: an entry whose insertion is not acknowledged is not evictable, referenced or not. With no blocked
     * streams allowed the encoder inserts speculatively without referencing; the table fills with unacknowledged entries
     * and the next insert that needs room must wait for the acknowledgment.
     */
    @Test fun negative_encoderNeverEvictsAnUnacknowledgedInsert() {
        val p = Pair2(cap = 128, blocked = 0)
        p.ack()
        for ((i, s) in listOf(0L, 4L, 8L).withIndex()) {
            val block = p.encode(s, "x-$i" to v(5))
            assertEquals(listOf("x-$i" to v(5)), p.decode(s, block)) // static or literal only: decodes now
        }
        assertEquals(3, p.e.insertCount)
        p.encode(12, "x-9" to v(13))
        assertEquals(3, p.e.insertCount, "no unacknowledged entry was evicted")
        p.ack() // Insert Count Increment 3: all acknowledged, none referenced
        p.encode(16, "x-9" to v(13))
        assertEquals(4, p.e.insertCount)
    }

    /** The decoder's Insert Count Increment (not a Section Acknowledgment) reaches the encoder. */
    private fun Pair2.increment() {
        val b = d.drainDecoderStream()
        assertEquals(0, b[0].toInt() and 0xc0, "an Insert Count Increment")
        e.onDecoderStream(b, 0, b.size)
    }

    private fun ric(block: ByteArray) = block[0].toInt() and 0xff // the encoded Required Insert Count (small values)

    /**
     * Section 2.1.2: "An encoder MUST limit the number of streams that could become blocked to the value of
     * SETTINGS_QPACK_BLOCKED_STREAMS at all times." A stream that already could block (its first section is unacknowledged
     * and above the Known Received Count) may send a second blocking section, trailers for instance, without counting
     * twice; another stream may not while the limit is used.
     */
    @Test fun negative_blockedStreamLimitCountsStreamsNotSections() {
        val p = Pair2(cap = 4096, blocked = 1)
        p.ack()
        val s0 = p.encode(0, "x-a" to "1")
        assertEquals(2, ric(s0), "stream 0 may block: it is the one stream allowed")
        val s4 = p.encode(4, "x-b" to "2")
        assertEquals(0, ric(s4), "stream 4 may not block while stream 0 can")
        val trailers = p.encode(0, "x-c" to "3")
        assertEquals(4, ric(trailers), "stream 0 already counts: its trailers may reference the new entry")
        assertEquals(listOf("x-a" to "1"), p.decode(0, s0))
        assertEquals(listOf("x-b" to "2"), p.decode(4, s4))
        assertEquals(listOf("x-c" to "3"), p.decode(0, trailers))
        // section 2.2.2.1: each Section Acknowledgment acknowledges "the earliest unacknowledged field section containing
        // dynamic table references sent on the given stream": two for stream 0, in order, one for stream 4 (none: static)
        p.ack()
        assertEquals(0, p.e.outstandingSections)
    }

    /**
     * Section 2.1.2 with the Known Received Count of section 2.1.4: a section whose Required Insert Count the decoder has
     * acknowledged by an Insert Count Increment cannot block any more, even before its Section Acknowledgment; the stream
     * no longer counts toward the limit, and a stream whose only sections are such does not count either.
     */
    @Test fun negative_acknowledgedInsertsFreeTheBlockedStreamBudget() {
        val p = Pair2(cap = 4096, blocked = 1)
        p.ack()
        val s0 = p.encode(0, "x-a" to "1")
        assertEquals(2, ric(s0))
        p.increment() // Known Received Count 1: s0 (Required Insert Count 1) cannot block now, though unacknowledged
        val s4 = p.encode(4, "x-b" to "2")
        assertEquals(3, ric(s4), "the budget is free again: stream 4 may block")
        val trailers = p.encode(0, "x-c" to "3")
        assertEquals(0, ric(trailers), "stream 0 does not block any more and stream 4 uses the one slot")
        assertEquals(listOf("x-b" to "2"), p.decode(4, s4))
        assertEquals(listOf("x-a" to "1"), p.decode(0, s0))
        assertEquals(listOf("x-c" to "3"), p.decode(0, trailers))
    }

    /**
     * Section 2.1.1: an entry is evictable only when "there are no outstanding references to the entry in unacknowledged
     * representations". Two unacknowledged sections reference the same entry; acknowledging one leaves the other's
     * reference, so the entry stays; once both are acknowledged it may go. The references are counted, not flagged.
     */
    @Test fun negative_eachUnacknowledgedSectionKeepsItsReference() {
        val p = Pair2(cap = 128, blocked = 100)
        p.ack()
        val s0 = p.encode(0, "x-1" to v(5)) // inserts x-1 (40 bytes) and references it
        p.increment() // x-1 acknowledged; s0 not yet
        val s4 = p.encode(4, "x-1" to v(5)) // a second reference to x-1
        assertEquals(2, ric(s4), "s4 references x-1")
        p.decode(8, p.encode(8, "x-2" to v(5), "x-3" to v(5)))
        p.ack() // x-2 and x-3 acknowledged and released; 120 of 128 bytes used
        assertEquals(listOf("x-1" to v(5)), p.decode(0, s0))
        p.ack() // s0 acknowledged: x-1 still referenced by s4
        val s12 = p.encode(12, "x-4" to v(13)) // 48 bytes would need x-1's room
        assertEquals(3, p.e.insertCount, "x-1 is still referenced by s4: not evicted")
        assertEquals(listOf("x-1" to v(5)), p.decode(4, s4))
        assertEquals(listOf("x-4" to v(13)), p.decode(12, s12))
        p.ack() // s4 acknowledged: no reference left
        p.encode(16, "x-4" to v(13))
        assertEquals(4, p.e.insertCount, "with both sections acknowledged x-1 is evictable")
    }

    /**
     * Section 4.3.2 (Insert with Name Reference, T=0) is what the encoder uses for a new value of a name the dynamic table
     * already holds; the newest entry with that name is found, not only the oldest.
     */
    @Test fun negative_encoderReferencesTheNewestDynamicName() {
        val p = Pair2(cap = 4096, blocked = 100)
        p.ack()
        p.decode(0, p.encode(0, "x-a" to "1", "x-b" to "2"))
        p.ack()
        val block = p.e.encode(4, listOf("x-b" to "3"))
        val ins = p.e.drainEncoderStream()
        assertEquals(0x80, ins[0].toInt() and 0xff, "Insert with Name Reference, dynamic, relative index 0 (x-b)")
        p.d.onEncoderStream(ins, 0, ins.size)
        assertEquals(listOf("x-b" to "3"), p.decode(4, block))
    }
}

/** Prefixed integers and string literals (RFC 9204 section 4.1, RFC 7541 sections 5.1 and 5.2) at their boundaries. */
class QpackPrimitivesGapTest {
    private fun roundTripInt(
        prefix: Int,
        v: Long,
    ) {
        val w = QpackWriter()
        w.writeInt(0, prefix, v)
        val b = w.toByteArray()
        val r = QpackReader(b, 0, b.size)
        assertEquals(v, r.readInt(prefix, QpackLimits()), "value $v with a $prefix-bit prefix")
        assertEquals(0, r.remaining)
    }

    /**
     * RFC 7541 section 5.1: "while I >= 128: encode (I % 128 + 128) on 8 bits; I = I / 128". A remainder of exactly 128
     * after the prefix needs a continuation byte; written as one byte it would carry a dangling continuation bit. A
     * 255-byte value (7-bit length prefix: 127 + 128) is such a case.
     */
    @Test fun negative_integerRemainderOf128() {
        for (prefix in 1..8) {
            val mask = (1L shl prefix) - 1
            for (v in listOf(mask + 127, mask + 128, mask + 129, mask + 128 * 128, mask + 128 * 128 - 1)) roundTripInt(prefix, v)
        }
        val value = "{".repeat(255) // 15-bit Huffman codes: sent raw, length 255 = 127 + 128
        val e = QpackEncoder()
        val d = QpackDecoder(0, 0, 65_536)
        val got = assertIs<DecodeResult.Decoded>(d.decode(0, e.encode(0, listOf("x-long" to value)))).fields
        assertEquals(listOf("x-long" to value), got)
    }

    /** RFC 7541 section 5.1 does not bound the continuation bytes; we stop at 10 (63 bits): an 11th is an error, not data. */
    @Test fun negative_elevenContinuationBytes() {
        val b = byteArrayOf(0x1f) + ByteArray(10) { 0x80.toByte() } + byteArrayOf(0)
        assertFailsWith<QpackError> { QpackReader(b, 0, b.size).readInt(5, QpackLimits()) }
        val ten = byteArrayOf(0x1f) + ByteArray(9) { 0x80.toByte() } + byteArrayOf(0)
        assertEquals(31, QpackReader(ten, 0, ten.size).readInt(5, QpackLimits()))
    }

    /** The integer ceiling is inclusive: the largest value allowed decodes, one more fails. */
    @Test fun negative_integerAtTheCeiling() {
        val limits = QpackLimits(maxInteger = 200)
        for ((v, ok) in listOf(200L to true, 201L to false)) {
            val w = QpackWriter()
            w.writeInt(0, 5, v)
            val b = w.toByteArray()
            if (ok) {
                assertEquals(v, QpackReader(b, 0, b.size).readInt(5, limits))
            } else {
                assertFailsWith<QpackError> {
                    QpackReader(b, 0, b.size).readInt(5, limits)
                }
            }
        }
    }

    /** RFC 9204 section 7.4: the string ceiling is inclusive: a literal exactly as long as the ceiling decodes. */
    @Test fun negative_stringExactlyAtTheCeiling() {
        val limits = QpackLimits(maxStringLength = 300)
        val w = QpackWriter()
        w.writeString(0, 7, "s".repeat(300), huffman = false)
        val b = w.toByteArray()
        assertEquals(300, QpackReader(b, 0, b.size).readString(7, limits).length)
        val over = QpackWriter()
        over.writeString(0, 7, "s".repeat(301), huffman = false)
        val o = over.toByteArray()
        assertFailsWith<QpackStringTooLong> { QpackReader(o, 0, o.size).readString(7, limits) }
    }

    /** RFC 9110 section 5.5 allows obs-text (0x80-0xFF) in field values; U+00FF is the last byte value, U+0100 is not one. */
    @Test fun negative_latin1UpperBoundary() {
        assertContentEquals(byteArrayOf(0xff.toByte()), "ÿ".latin1())
        assertFailsWith<IllegalArgumentException> { "Ā".latin1() }
    }
}

/** The static table in the encoder's output (RFC 9204 section 3.1 and Appendix A). */
class QpackStaticGapTest {
    /**
     * RFC 9204 Appendix A: index 17 is `:method: GET`, index 1 is the name `:path`. With no dynamic table the encoder uses
     * them: an Indexed Field Line (section 4.5.2, `1T` with T=1) and a Literal Field Line with Name Reference (section
     * 4.5.4, `01NT`, T=1), not literal names.
     */
    @Test fun negative_encoderUsesStaticReferences() {
        val block = QpackEncoder().encode(0, listOf(":method" to "GET", ":path" to "/x"))
        assertContentEquals(hex("0000 d1 51 02 2f 78"), block)
        assertEquals(17, StaticTable.find(":method", "GET"))
        assertEquals(1, StaticTable.findName(":path"))
        assertEquals(98, StaticTable.find("x-frame-options", "sameorigin")) // the last entry
        assertEquals(0, StaticTable.findName(":authority")) // the first entry
    }
}
