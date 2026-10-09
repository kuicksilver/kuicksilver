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
