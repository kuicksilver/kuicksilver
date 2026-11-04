// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.hpack

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HpackLimitsTest {
    private fun bytes(vararg b: Int): ByteArray = ByteArray(b.size) { b[it].toByte() }

    private fun decodeAll(
        d: HpackDecoder,
        block: ByteArray,
    ): List<Pair<String, String>> = mutableListOf<Pair<String, String>>().also { out -> d.decode(block) { n, v -> out += n to v } }

    @Test
    fun negative_tableSizeUpdateAboveSettingIsCompressionError() {
        val d = HpackDecoder(maxTableSize = 4096)
        val e = assertFailsWith<HpackError> { decodeAll(d, HpackWriter().also { it.writeInt(0x20, 5, 4097) }.toByteArray()) }
        assertTrue("above the limit" in e.message!!)
        // exactly the setting is fine, and so is 0
        decodeAll(HpackDecoder(maxTableSize = 4096), HpackWriter().also { it.writeInt(0x20, 5, 4096) }.toByteArray())
        decodeAll(HpackDecoder(maxTableSize = 4096), bytes(0x20, 0x82))
    }

    @Test
    fun negative_tableSizeUpdateAfterFirstFieldIsCompressionError() {
        // :method GET, then an update to 0 (section 4.2: only at the beginning of a block)
        assertFailsWith<HpackError> { decodeAll(HpackDecoder(), bytes(0x82, 0x20)) }
        // two updates before the first field are allowed (section 4.2)
        assertEquals(listOf(":method" to "GET"), decodeAll(HpackDecoder(), bytes(0x20, 0x3f, 0xe1, 0x1f, 0x82)))
    }

    @Test
    fun negative_requiredTableSizeUpdateMissing() {
        val d = HpackDecoder(maxTableSize = 4096)
        d.setMaxTableSize(100) // our SETTINGS_HEADER_TABLE_SIZE fell below the table's size and was acknowledged
        assertFailsWith<HpackError> { decodeAll(d, bytes(0x82)) }
        val ok = HpackDecoder(maxTableSize = 4096)
        ok.setMaxTableSize(100)
        assertEquals(
            listOf(":method" to "GET"),
            decodeAll(ok, HpackWriter().also { it.writeInt(0x20, 5, 100) }.toByteArray() + bytes(0x82)),
        )
        assertEquals(listOf(":method" to "GET"), decodeAll(ok, bytes(0x82))) // only the first block after the change must carry it
    }

    @Test
    fun negative_indexZeroAndBeyondTable() {
        assertFailsWith<HpackError> { decodeAll(HpackDecoder(), bytes(0x80)) } // index 0 (section 6.1)
        assertFailsWith<HpackError> { decodeAll(HpackDecoder(), bytes(0x80 or 62)) } // empty dynamic table
        assertFailsWith<HpackError> { decodeAll(HpackDecoder(), bytes(0x40 or 62, 0x01, 0x61)) } // literal with a missing name index
        assertEquals(listOf("www-authenticate" to ""), decodeAll(HpackDecoder(), bytes(0x80 or 61))) // the last static entry
    }

    @Test
    fun negative_hpackBomb() {
        // one 4 KiB-sized entry in the table, then 16 KiB of one-byte references to it: 16 384 fields of ~4 KiB each
        val d = HpackDecoder(maxTableSize = 4096, maxHeaderListSize = 65_536)
        val value = "x".repeat(4000)
        val w = HpackWriter()
        w.writeInt(0x40, 6, 0)
        w.writeString("bomb", huffman = false)
        w.writeString(value, huffman = false)
        val block = w.toByteArray() + ByteArray(16_384) { (0x80 or 62).toByte() }
        var emitted = 0
        var emittedBytes = 0L
        val fits =
            d.decode(block) { n, v ->
                emitted++
                emittedBytes += n.length + v.length
            }
        assertFalse(fits)
        assertEquals(65_536 / entrySize("bomb", value), emitted) // the sink stopped at the limit (16 fields)
        assertTrue(emittedBytes <= 65_536)
        assertEquals(4L + 4000L, d.lastAllocated) // the references allocated nothing: the literal's two strings only
        // the table is still in step: the next block's reference resolves
        assertEquals(listOf("bomb" to value), decodeAll(d, bytes(0x80 or 62)))
    }

    @Test
    fun negative_hugeStringLengthRejectedBeforeAllocation() {
        // a literal name declared 2^31 - 1 bytes long (the largest integer we read), then 2^31 (an overflow)
        val w = HpackWriter()
        w.writeByte(0x40)
        w.writeInt(0, 7, Int.MAX_VALUE)
        val d = HpackDecoder()
        assertFailsWith<HpackError> { decodeAll(d, w.toByteArray()) }
        assertEquals(0L, d.lastAllocated)
        val over = bytes(0x40, 0x7f, 0x81, 0xff, 0xff, 0xff, 0x07) // 127 + 0x7fffff81 = 2^31
        assertFailsWith<HpackError> { decodeAll(d, over) }
        assertEquals(0L, d.lastAllocated)
        // a declared length within the block but above maxStringLength
        val small = HpackDecoder(maxHeaderListSize = 1000, maxStringLength = 10)
        val lit =
            HpackWriter().also {
                it.writeByte(0x40)
                it.writeString("a".repeat(11), huffman = false)
                it.writeString("", huffman = false)
            }
        assertFailsWith<HpackError> { decodeAll(small, lit.toByteArray()) }
        assertEquals(0L, small.lastAllocated)
        // a Huffman literal whose output passes maxStringLength stops at it
        val huff =
            HpackWriter().also {
                it.writeByte(0x40)
                it.writeString("a".repeat(40), huffman = true)
                it.writeString("", huffman = false)
            }
        assertFailsWith<HpackError> { decodeAll(small, huff.toByteArray()) }
    }

    @Test
    fun negative_integerOverflow() {
        // a 5-bit prefix (size update) followed by ten continuation bytes
        assertFailsWith<HpackError> { decodeAll(HpackDecoder(), bytes(0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00)) }
        // a small value padded with zero continuation bytes past five (section 5.1: an octet length over the limit)
        assertFailsWith<HpackError> { decodeAll(HpackDecoder(), bytes(0x3f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00)) }
        // a block that ends inside an integer
        assertFailsWith<HpackError> { decodeAll(HpackDecoder(), bytes(0xff, 0x80)) }
    }

    @Test
    fun negative_huffmanEosOrBadPadding() {
        fun literal(huffman: ByteArray) = bytes(0x00, 0x01, 0x61, 0x80 or huffman.size) + huffman
        // EOS (30 ones) inside the string, padded with ones to 32 bits
        assertFailsWith<HpackError> { decodeAll(HpackDecoder(), literal(bytes(0xff, 0xff, 0xff, 0xff))) }
        // 'a' is 00011 (5 bits): padded with 3 zero bits instead of ones
        assertFailsWith<HpackError> { decodeAll(HpackDecoder(), literal(bytes(0x18))) }
        // 'a' then a whole byte of ones: padding longer than 7 bits
        assertFailsWith<HpackError> { decodeAll(HpackDecoder(), literal(bytes(0x1f, 0xff))) }
        // the correct form decodes
        assertEquals(listOf("a" to "a"), decodeAll(HpackDecoder(), literal(bytes(0x1f))))
    }

    @Test
    fun sensitiveFieldsNeverIndexed() {
        val e = HpackEncoder()
        for (name in listOf("authorization", "proxy-authorization", "set-cookie")) {
            val block = e.encode(listOf(name to "secret"))
            assertEquals(0x10, block[0].toInt() and 0xf0, name) // 0001: never indexed (section 6.2.3)
        }
        assertEquals(0x10, e.encode(listOf("cookie" to "id=1"))[0].toInt() and 0xf0) // a short cookie is guessable
        assertEquals(0x40, e.encode(listOf("cookie" to "session=0123456789abcdef"))[0].toInt() and 0xc0) // a long one is indexed
        assertEquals(0x00, e.encode(listOf(":path" to "/a?token=1"))[0].toInt() and 0xf0) // per-request values: without indexing
        // they round-trip, and nothing sensitive went into the decoder's table
        val d = HpackDecoder()
        val fields = listOf("authorization" to "Bearer x", ":path" to "/p", "x-trace" to "1")
        assertEquals(fields, decodeAll(d, HpackEncoder().encode(fields)))
        assertEquals(listOf("x-trace" to "1"), d.tableEntries())
    }

    @Test
    fun encoderRespectsPeerTableSize() {
        val e = HpackEncoder()
        val d = HpackDecoder()
        e.setPeerMaxTableSize(0)
        val first = e.encode(listOf("x-a" to "1"))
        assertEquals(0x20, first[0].toInt() and 0xff) // an update to 0 starts the next block (section 4.2)
        assertEquals(0x00, first[1].toInt() and 0xf0) // and the field is a literal without indexing: nothing fits
        assertEquals(listOf("x-a" to "1"), decodeAll(d, first))
        assertEquals(0, d.tableSize)
        val second = e.encode(listOf("x-a" to "1"))
        assertEquals(0x00, second[0].toInt() and 0xf0) // no second update
        // a peer limit above our ceiling: the table stays at the ceiling (4096), no update needed
        val big = HpackEncoder(maxTableSize = 4096)
        big.setPeerMaxTableSize(1L shl 20)
        assertEquals(4096, big.tableCapacity)
        assertEquals(0x40, big.encode(listOf("x-b" to "2"))[0].toInt() and 0xc0)
        // lowered twice before the next block: the smallest first, then the final size
        val twice = HpackEncoder()
        twice.setPeerMaxTableSize(100)
        twice.setPeerMaxTableSize(200)
        assertContentEquals(bytes(0x3f, 0x45, 0x3f, 0xa9, 0x01), twice.encode(emptyList()))
    }
}
