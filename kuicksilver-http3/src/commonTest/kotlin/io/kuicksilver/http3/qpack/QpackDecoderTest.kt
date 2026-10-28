// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.qpack

import io.kuicksilver.http3.Http3ErrorCode
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

private fun QpackDecoder.feed(h: String) {
    val b = hex(h)
    onEncoderStream(b, 0, b.size)
}

private fun DecodeResult.fields() = assertIs<DecodeResult.Decoded>(this).fields

/** RFC 9204 Appendix B, run in sequence on one decoder. */
class RfcAppendixBTest {
    private val d = QpackDecoder(maxTableCapacity = 4096, maxBlockedStreams = 16, maxFieldSectionSize = 65_536)

    @Test fun appendixBInSequence() {
        // B.1 Literal Field Line with Name Reference
        assertEquals(listOf(":path" to "/index.html"), d.decode(0, hex("0000 510b 2f69 6e64 6578 2e68 746d 6c")).fields())
        assertContentEquals(ByteArray(0), d.drainDecoderStream()) // no dynamic references: nothing to acknowledge
        // B.2 Dynamic Table
        d.feed("3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468")
        assertEquals(2, d.insertCount)
        assertEquals(106, d.tableSize)
        assertEquals(listOf(":authority" to "www.example.com", ":path" to "/sample/path"), d.decode(4, hex("0381 10 11")).fields())
        assertContentEquals(hex("84"), d.drainDecoderStream())
        // B.3 Speculative Insert
        d.feed("4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565")
        assertEquals(160, d.tableSize)
        assertContentEquals(hex("01"), d.drainDecoderStream())
        // B.4 Duplicate, Stream Cancellation: the field section arrives before the duplicate
        val blocked = d.decode(8, hex("0500 80 c1 81"))
        assertEquals(4, assertIs<DecodeResult.Blocked>(blocked).requiredInsertCount)
        d.markBlocked(8)
        d.cancelStream(8)
        assertContentEquals(hex("48"), d.drainDecoderStream())
        d.feed("02")
        assertEquals(217, d.tableSize)
        assertContentEquals(hex("01"), d.drainDecoderStream()) // the duplicate is acknowledged by an increment
        assertEquals(
            listOf(":authority" to "www.example.com", ":path" to "/", "custom-key" to "custom-value"),
            d.decode(12, hex("0500 80 c1 81")).fields(),
        )
        assertContentEquals(hex("8c"), d.drainDecoderStream())
        // B.5 Dynamic Table Insert, Eviction
        d.feed("810d 6375 7374 6f6d 2d76 616c 7565 32")
        assertEquals(215, d.tableSize)
        assertEquals(5, d.insertCount)
    }
}

class QpackDecoderTest {
    private fun dec(
        cap: Long = 4096,
        blocked: Int = 16,
        max: Long = 65_536,
    ) = QpackDecoder(cap, blocked, max)

    @Test fun blockedUntilInsert() {
        val d = dec()
        d.feed("3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d") // capacity 220, one insert
        val block = hex("0381 10 11") // needs two inserts
        assertEquals(2, assertIs<DecodeResult.Blocked>(d.decode(4, block)).requiredInsertCount)
        d.feed("c10c 2f73 616d 706c 652f 7061 7468")
        assertEquals(2, d.decode(4, block).fields().size)
    }

    @Test fun negative_qpackBlockedStreams() {
        val d = dec(blocked = 2)
        d.markBlocked(0)
        d.markBlocked(4)
        assertEquals(Http3ErrorCode.QPACK_DECOMPRESSION_FAILED, assertFailsWith<QpackError> { d.markBlocked(8) }.code)
        d.unblock(0)
        d.markBlocked(8) // a slot freed
    }

    @Test fun capacityAboveAdvertisedIsEncoderStreamError() {
        val d = dec(cap = 100)
        assertEquals(Http3ErrorCode.QPACK_ENCODER_STREAM_ERROR, assertFailsWith<QpackError> { d.feed("3fbd01") }.code) // 220 > 100
    }

    @Test fun referenceToEvictedEntryFails() {
        val d = dec()
        d.feed("3f19") // capacity 56
        d.feed("4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565") // 54 bytes, abs 0
        d.feed("00") // duplicate abs 0 -> evicts abs 0 itself? 54+54 > 56: the duplicate evicts the original first
        assertEquals(2, d.insertCount)
        // a field section referencing abs 0 (RIC=1, base=1, relative index 0)
        assertEquals(Http3ErrorCode.QPACK_DECOMPRESSION_FAILED, assertFailsWith<QpackError> { d.decode(0, hex("0200 80")) }.code)
    }

    @Test fun negative_h3DecodedFieldSectionTooLarge() {
        val d = dec(cap = 0, max = 65_536)
        val w = QpackWriter()
        w.writeByte(0)
        w.writeByte(0)
        repeat(3) {
            w.writeString(0x20, 3, "x-big", huffman = false)
            w.writeString(0, 7, "v".repeat(30_000), huffman = false)
        } // literal name, literal value
        assertIs<DecodeResult.TooLarge>(d.decode(0, w.toByteArray()))
        // two of them fit: 2 * (5 + 30000 + 32) = 60074
        val w2 = QpackWriter()
        w2.writeByte(0)
        w2.writeByte(0)
        repeat(2) {
            w2.writeString(0x20, 3, "x-big", huffman = false)
            w2.writeString(0, 7, "v".repeat(30_000), huffman = false)
        }
        assertEquals(60_074, assertIs<DecodeResult.Decoded>(d.decode(0, w2.toByteArray())).decodedSize)
    }

    /**
     * RFC 9204 section 7.4: a single string above what we can decode is a stream error (the section is TooLarge: 431 on a
     * request stream), not a connection error; the ceiling follows maxFieldSectionSize.
     */
    @Test fun oversizedSingleFieldIsTooLargeNotAnError() {
        fun section(
            value: String,
            huffman: Boolean,
        ): ByteArray {
            val w = QpackWriter()
            w.writeByte(0)
            w.writeByte(0)
            w.writeString(0x20, 3, "x-big", huffman = false)
            w.writeString(0, 7, value, huffman = huffman)
            return w.toByteArray()
        }
        val d = dec(cap = 0, max = 65_536)
        assertIs<DecodeResult.TooLarge>(d.decode(0, section("v".repeat(65_600), huffman = false)))
        assertIs<DecodeResult.TooLarge>(d.decode(4, section("a".repeat(65_600), huffman = true)))
        // a raised limit: one 100 KB value fits a 1 MiB field section
        val raised = dec(cap = 0, max = 1L shl 20)
        val f = assertIs<DecodeResult.Decoded>(raised.decode(0, section("v".repeat(100_000), huffman = false))).fields
        assertEquals(100_000, f.single().second.length)
        assertEquals(
            100_000,
            assertIs<DecodeResult.Decoded>(raised.decode(4, section("a".repeat(100_000), huffman = true)))
                .fields
                .single()
                .second.length,
        )
    }

    @Test fun staticOnlyWhenCapacityZero() {
        val d = dec(cap = 0)
        assertEquals(Http3ErrorCode.QPACK_DECOMPRESSION_FAILED, assertFailsWith<QpackError> { d.decode(0, hex("0381 10")) }.code)
        assertEquals(Http3ErrorCode.QPACK_ENCODER_STREAM_ERROR, assertFailsWith<QpackError> { d.feed("3f01") }.code) // capacity 32 > 0
    }

    @Test fun encoderStreamPartialInstructionBuffered() {
        val d = dec()
        d.feed("3fbd01")
        val ins = hex("c00f 7777 772e 6578 616d 706c 652e 636f 6d")
        d.onEncoderStream(ins, 0, 3)
        d.onEncoderStream(ins, 3, 5)
        assertEquals(0, d.insertCount)
        d.onEncoderStream(ins, 8, ins.size - 8)
        assertEquals(1, d.insertCount)
    }

    @Test fun negative_qpackFragmentedEncoderInstructionLinear() {
        val d = dec(cap = 4096)
        d.feed("3fe11f") // capacity 4096
        val w = QpackWriter() // Insert with Literal Name, name "x-n", a 60 000-byte value
        w.writeString(0x40, 5, "x-n", huffman = false)
        w.writeString(0x00, 7, "v".repeat(60_000), huffman = false)
        val b = w.toByteArray()
        for (i in 0 until b.size - 1) d.onEncoderStream(b, i, 1) // one byte at a time, as a hostile transport could
        assertEquals(0, d.insertCount)
        // the complete entry is larger than the table: an encoder-stream error (RFC 9204 section 3.2.2)
        assertEquals(Http3ErrorCode.QPACK_ENCODER_STREAM_ERROR, assertFailsWith<QpackError> { d.onEncoderStream(b, b.size - 1, 1) }.code)
        assertTrue(d.scannedBytes < 4L * b.size, "scanned ${d.scannedBytes} bytes for ${b.size}: quadratic reassembly")
    }

    /**
     * RFC 9204 section 7.4: the encoder-stream limits "SHOULD be large enough to process the largest individual field the
     * HTTP implementation can be configured to accept". With a 1 MiB table and field-section limit, a 100 000-byte value
     * inserted on the encoder stream (also arriving in pieces) is accepted, as it would be as a literal in a field section.
     */
    @Test fun largeInsertWithinCapacityAccepted() {
        val d = QpackDecoder(1L shl 20, 0, 1L shl 20)
        val w = QpackWriter()
        w.writeInt(0x20, 5, 1L shl 20) // Set Dynamic Table Capacity
        w.writeString(0x40, 5, "x-big", huffman = false) // Insert with Literal Name
        w.writeString(0x00, 7, "v".repeat(100_000), huffman = false)
        val b = w.toByteArray()
        d.onEncoderStream(b, 0, 50_000)
        d.onEncoderStream(b, 50_000, b.size - 50_000)
        assertEquals(1, d.insertCount)
        // the ceiling stays the table: an entry larger than it is still an encoder-stream error (section 3.2.2)
        val small = QpackDecoder(1L shl 20, 0, 1L shl 20)
        val w2 = QpackWriter()
        w2.writeInt(0x20, 5, 100_000)
        w2.writeString(0x40, 5, "x-big", huffman = false)
        w2.writeString(0x00, 7, "v".repeat(100_000), huffman = false)
        val b2 = w2.toByteArray()
        assertEquals(Http3ErrorCode.QPACK_ENCODER_STREAM_ERROR, assertFailsWith<QpackError> { small.onEncoderStream(b2, 0, b2.size) }.code)
    }

    /**
     * A Huffman literal can be longer than the string it carries (codes of up to 30 bits for an 8-bit octet, RFC 7541
     * appendix B): an insert that fits the table (RFC 9204 section 3.2.2) with a value of obs-text octets of long codes is
     * about 3.4 times its decoded size on the wire. Arriving in pieces it waits whole for its last byte and is accepted;
     * the wait for it was bounded at twice the string ceiling, which such an insert passes.
     */
    @Test fun huffmanInsertLongerThanTwiceTheCeilingAccepted() {
        val d = QpackDecoder(65_536, 0, 65_536) // string ceiling 64 KiB
        val longest = (0x80..0xFF).maxBy { Huffman.encodedLength(byteArrayOf(it.toByte())) }.toChar()
        val value = longest.toString().repeat(60_000)
        val w = QpackWriter()
        w.writeInt(0x20, 5, 65_536) // Set Dynamic Table Capacity
        w.writeString(0x40, 5, "x-n", huffman = true) // Insert with Literal Name
        w.writeString(0x00, 7, value, huffman = true)
        val b = w.toByteArray()
        assertTrue(b.size > 2 * 65_536 + 64, "the insert is ${b.size} bytes on the wire")
        d.onEncoderStream(b, 0, 100)
        d.onEncoderStream(b, 100, b.size - 100)
        assertEquals(1, d.insertCount)
    }

    private fun failCode(block: () -> Unit): Long = assertFailsWith<QpackError> { block() }.code

    /** RFC 9204 section 4.5.1.2: with Sign=1 the Base is RIC - DeltaBase - 1; DeltaBase >= RIC would make it negative. */
    @Test fun negativeBaseFails() {
        val d = dec()
        d.feed("3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d") // capacity 220, one insert
        assertEquals(Http3ErrorCode.QPACK_DECOMPRESSION_FAILED, failCode { d.decode(0, hex("0281 10")) }) // RIC 1, Sign=1, DeltaBase 1
        assertEquals(1, d.decode(4, hex("0280 10")).fields().size) // DeltaBase 0: Base 0, a post-base reference to entry 0
    }

    /** RFC 9204 section 4.5.1.1: an EncodedInsertCount above 2 * MaxEntries, or one decoding below zero, cannot come from a conformant encoder. */
    @Test fun impossibleEncodedInsertCountFails() {
        val d = dec(cap = 4096) // MaxEntries 128, FullRange 256
        assertEquals(Http3ErrorCode.QPACK_DECOMPRESSION_FAILED, failCode { d.decode(0, hex("ff02 00")) }) // 257
        // 200 with nothing inserted: wraps below 0
        assertEquals(Http3ErrorCode.QPACK_DECOMPRESSION_FAILED, failCode { d.decode(0, hex("c8 00")) })
    }

    /** RFC 9204 section 3.1: a static index outside the table is QPACK_DECOMPRESSION_FAILED in a field line. */
    @Test fun staticIndexOutOfRangeInFieldLineFails() {
        val d = dec()
        assertEquals(Http3ErrorCode.QPACK_DECOMPRESSION_FAILED, failCode { d.decode(0, hex("0000 ff24")) }) // indexed, static 99
        assertEquals(Http3ErrorCode.QPACK_DECOMPRESSION_FAILED, failCode { d.decode(0, hex("0000 5f54 00")) }) // literal, static name 99
        assertEquals(1, d.decode(0, hex("0000 ff23")).fields().size) // 98, the last entry
    }

    /** RFC 9204 section 3.1: a static index outside the table on the encoder stream is QPACK_ENCODER_STREAM_ERROR. */
    @Test fun staticIndexOutOfRangeOnEncoderStreamFails() {
        val d = dec()
        d.feed("3fbd01")
        assertEquals(Http3ErrorCode.QPACK_ENCODER_STREAM_ERROR, failCode { d.feed("ff24 00") }) // Insert with static name 99
    }

    /** RFC 9204 section 3.2.2: an entry larger than the table capacity is QPACK_ENCODER_STREAM_ERROR. */
    @Test fun insertLargerThanCapacityFails() {
        val d = dec()
        val w = QpackWriter()
        w.writeInt(0x20, 5, 56) // capacity 56
        w.writeString(0x40, 5, "x", huffman = false)
        w.writeString(0x00, 7, "a".repeat(24), huffman = false) // 1 + 24 + 32 = 57
        val b = w.toByteArray()
        assertEquals(Http3ErrorCode.QPACK_ENCODER_STREAM_ERROR, failCode { d.onEncoderStream(b, 0, b.size) })
        assertEquals(0, d.insertCount)
    }

    /** RFC 9204 section 2.2.3: a Duplicate or a dynamic name reference on the encoder stream to an evicted entry is QPACK_ENCODER_STREAM_ERROR. */
    @Test fun encoderStreamReferenceToEvictedEntryFails() {
        for (instruction in listOf("01", "81 00")) { // Duplicate relative 1; Insert with dynamic name reference relative 1, empty value
            val d = dec()
            d.feed("3f19") // capacity 56
            d.feed("4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565") // 54 bytes, abs 0
            d.feed("00") // duplicate: abs 1, evicts abs 0
            assertEquals(Http3ErrorCode.QPACK_ENCODER_STREAM_ERROR, failCode { d.feed(instruction) }, instruction)
        }
    }

    @Test fun dynamicIndexAtOrAboveRequiredInsertCountFails() {
        val d = dec()
        d.feed("3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468")
        // RIC = 1, base = 1, post-base index 0 -> abs 1 >= RIC
        assertFailsWith<QpackError> { d.decode(0, hex("0200 10")) }
    }

    @Test fun truncatedFieldSectionFails() {
        assertFailsWith<QpackError> { dec().decode(0, hex("0000 510b 2f69")) }
    }

    @Test fun cancelWithoutDynamicTableSendsNothing() {
        val d = dec(cap = 0)
        d.cancelStream(4)
        assertContentEquals(ByteArray(0), d.drainDecoderStream())
    }
}

class DynamicTableTest {
    @Test fun evictsOldestAndCountsInserts() {
        val t = DynamicTable(100)
        assertEquals(true, t.insert("a", "1"))
        assertEquals(true, t.insert("b", "2"))
        assertEquals(true, t.insert("c", "3")) // 34 each
        assertEquals(3, t.insertCount)
        assertEquals(68, t.size)
        assertNull(t.absolute(0))
        assertEquals("b" to "2", t.absolute(1))
        assertEquals(false, t.insert("x", "y".repeat(100)))
        assertEquals(2L, t.findExact("c", "3"))
        assertEquals(-1L, t.findExact("a", "1"))
        assertEquals(1L, t.findName("b"))
    }
}
