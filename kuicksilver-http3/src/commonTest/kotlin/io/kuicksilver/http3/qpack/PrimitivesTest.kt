// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.qpack

import io.kotest.property.Arb
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.int
import io.kotest.property.checkAll
import io.kuicksilver.http3.Http3ErrorCode
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

internal fun hex(s: String): ByteArray =
    s
        .replace(" ", "")
        .chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()

class PrimitivesTest {
    private val limits = QpackLimits()

    @Test fun rfc7541IntegerExamples() {
        val w1 = QpackWriter()
        w1.writeInt(0, 5, 10)
        assertContentEquals(hex("0a"), w1.toByteArray())
        val w2 = QpackWriter()
        w2.writeInt(0, 5, 1337)
        assertContentEquals(hex("1f9a0a"), w2.toByteArray())
        val w3 = QpackWriter()
        w3.writeInt(0, 8, 42)
        assertContentEquals(hex("2a"), w3.toByteArray())
        assertEquals(1337, QpackReader(hex("1f9a0a"), 0, 3).readInt(5, limits))
        assertEquals(10, QpackReader(hex("ea"), 0, 1).readInt(5, limits)) // flags above the prefix are ignored
    }

    @Test fun integerRoundTrip() =
        runTest {
            checkAll(500, Arb.int(1..8), Arb.int(0..Int.MAX_VALUE)) { prefix, v ->
                val w = QpackWriter()
                w.writeInt(0, prefix, v.toLong())
                val b = w.toByteArray()
                val r = QpackReader(b, 0, b.size)
                assertEquals(v.toLong(), r.readInt(prefix, limits))
                assertEquals(b.size, r.pos)
            }
        }

    @Test fun truncatedIntegerFails() {
        assertFailsWith<QpackError> { QpackReader(hex("1f9a"), 0, 2).readInt(5, limits) }
    }

    @Test fun negative_qpackHugeIntegerOrLiteral() {
        // 11 continuation bytes: more than any 62-bit value needs
        val huge = hex("1f" + "ff".repeat(10) + "01")
        assertEquals(
            Http3ErrorCode.QPACK_DECOMPRESSION_FAILED,
            assertFailsWith<QpackError> {
                QpackReader(huge, 0, huge.size).readInt(5, limits)
            }.code,
        )
        // a string announcing 2^31 bytes with nothing behind it: refused before allocation
        val w = QpackWriter()
        w.writeInt(0, 7, 1L shl 31)
        val b = w.toByteArray()
        assertFailsWith<QpackError> { QpackReader(b, 0, b.size).readString(7, limits) }
        // just above the string ceiling
        val w2 = QpackWriter()
        w2.writeString(0, 7, "a".repeat(65_537), huffman = false)
        val b2 = w2.toByteArray()
        assertFailsWith<QpackError> { QpackReader(b2, 0, b2.size).readString(7, QpackLimits(maxStringLength = 65_536)) }
        // a Huffman string whose decoded form exceeds the ceiling
        val w3 = QpackWriter()
        w3.writeString(0, 7, "a".repeat(2000), huffman = true)
        val b3 = w3.toByteArray()
        assertFailsWith<QpackError> { QpackReader(b3, 0, b3.size).readString(7, QpackLimits(maxStringLength = 1000)) }
    }

    /** RFC 7541 section 5.1: bits shifted past 63 in the 10th continuation byte are an overflow, not silently dropped. */
    @Test fun negative_qpackIntegerOverflowIn10thContinuationByte() {
        // prefix all ones, nine 0x80 continuation bytes (shift reaches 63), then 0x02: 2^64 + 31 would read as 31
        val even = hex("1f" + "80".repeat(9) + "02")
        val e =
            assertFailsWith<QpackError> {
                QpackReader(even, 0, even.size).readInt(5, QpackLimits(maxInteger = Long.MAX_VALUE))
            }
        assertEquals(Http3ErrorCode.QPACK_DECOMPRESSION_FAILED, e.code)
        assertFailsWith<QpackError> { QpackReader(even, 0, even.size).readInt(5, limits) }
        // zero padding in the 10th byte adds nothing and is still a valid (if non-canonical) encoding
        val padded = hex("1f" + "81" + "80".repeat(8) + "00")
        assertEquals(32L, QpackReader(padded, 0, padded.size).readInt(5, limits))
    }

    @Test fun stringRoundTripBothEncodings() {
        for (h in listOf(false, true)) {
            val w = QpackWriter()
            w.writeString(0x40, 3, "custom-value", huffman = h)
            val b = w.toByteArray()
            assertEquals(if (h) 0x48 else 0x40, b[0].toInt() and 0x78)
            assertEquals("custom-value", QpackReader(b, 0, b.size).readString(3, limits))
        }
    }
}

class HuffmanTest {
    private fun enc(s: String): ByteArray {
        val w = QpackWriter()
        Huffman.encode(s.encodeToByteArray(), w)
        return w.toByteArray()
    }

    @Test fun rfc7541Examples() {
        assertContentEquals(hex("f1e3 c2e5 f23a 6ba0 ab90 f4ff"), enc("www.example.com"))
        assertContentEquals(hex("a8eb 1064 9cbf"), enc("no-cache"))
        assertContentEquals(hex("25a8 49e9 5ba9 7d7f"), enc("custom-key"))
        assertContentEquals(hex("25a8 49e9 5bb8 e8b4 bf"), enc("custom-value"))
        assertEquals("www.example.com", Huffman.decode(hex("f1e3 c2e5 f23a 6ba0 ab90 f4ff"), 0, 12, 100).decodeToString())
        assertEquals(12, Huffman.encodedLength("www.example.com".encodeToByteArray()))
    }

    @Test fun roundTripAllBytes() =
        runTest {
            checkAll(1000, Arb.byteArray(Arb.int(0..200), Arb.byte())) { s ->
                val w = QpackWriter()
                Huffman.encode(s, w)
                val b = w.toByteArray()
                assertContentEquals(s, Huffman.decode(b, 0, b.size, 10_000))
            }
        }

    @Test fun eosInStringRejected() {
        assertFailsWith<QpackError> { Huffman.decode(hex("ffffffff"), 0, 4, 100) }
    } // 30 ones = EOS, then more ones

    @Test fun paddingLongerThan7BitsRejected() {
        assertFailsWith<QpackError> { Huffman.decode(hex("1fff"), 0, 2, 100) } // 'a' (00011) + 11 one-bits of padding
        assertFailsWith<QpackError> { Huffman.decode(hex("00"), 0, 1, 100) } // '0' (00000) + "000": padding must be ones
    }
}

class StaticTableTest {
    @Test fun entriesMatchRfc() {
        assertEquals(99, StaticTable.SIZE)
        assertEquals(":authority" to "", StaticTable.name(0) to StaticTable.value(0))
        assertEquals(":method" to "GET", StaticTable.name(17) to StaticTable.value(17))
        assertEquals(":status" to "200", StaticTable.name(25) to StaticTable.value(25))
        assertEquals(
            "content-security-policy" to "script-src 'none'; object-src 'none'; base-uri 'none'",
            StaticTable.name(85) to StaticTable.value(85),
        )
        assertEquals("x-frame-options" to "sameorigin", StaticTable.name(98) to StaticTable.value(98))
    }

    @Test fun findExactAndName() {
        assertEquals(17, StaticTable.find(":method", "GET"))
        assertEquals(-1, StaticTable.find(":method", "PATCH"))
        assertEquals(15, StaticTable.findName(":method"))
        assertEquals(-1, StaticTable.findName("x-unknown"))
    }
}
