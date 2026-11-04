// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.hpack

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** RFC 7541 appendix C byte for byte, from the vectors tools/http/gen-tables.py extracted from the RFC text. */
class HpackRfcVectorsTest {
    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private fun ByteArray.hex(): String = joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    private fun pairs(flat: List<String>): List<Pair<String, String>> = flat.chunked(2).map { it[0] to it[1] }

    @Test
    fun appendixC1Integers() {
        fun enc(
            prefix: Int,
            v: Int,
        ) = HpackWriter().also { it.writeInt(0, prefix, v) }.toByteArray().hex()
        assertEquals("0a", enc(5, 10)) // C.1.1
        assertEquals("1f9a0a", enc(5, 1337)) // C.1.2
        assertEquals("2a", enc(8, 42)) // C.1.3
        assertEquals(1337, HpackReader(hex("1f9a0a"), 0, 3, 100).readInt(5))
    }

    @Test
    fun appendixC2toC6() {
        // C.2.x are independent examples; C.3 to C.6 are each one connection (three blocks in sequence)
        val groups = Rfc7541Vectors.EXAMPLES.groupBy { if (it.id.startsWith("C.2")) it.id else it.id.substring(0, 3) }
        assertEquals(4 + 4, groups.size)
        for ((_, examples) in groups) {
            val first = examples.first()
            val decoder = HpackDecoder(maxTableSize = first.tableSize)
            val encoder = HpackEncoder(maxTableSize = first.tableSize, peerTableSize = first.tableSize)
            encoder.indexEverything = true // the RFC's examples add every literal to the table
            encoder.huffman = if (first.huffman) HpackEncoder.HuffmanMode.ALWAYS else HpackEncoder.HuffmanMode.NEVER
            for (e in examples) {
                val block = hex(e.encodedHex.joinToString(""))
                val decoded = mutableListOf<Pair<String, String>>()
                assertTrue(decoder.decode(block) { n, v -> decoded += n to v }, e.id)
                assertEquals(pairs(e.fields), decoded, e.id)
                assertEquals(pairs(e.tableAfter), decoder.tableEntries(), e.id)
                assertEquals(e.tableBytes, decoder.tableSize, e.id)
                // C.2.2 and C.2.3 use representations a general encoder does not pick; C.3-C.6 are what ours writes
                if (!e.id.startsWith("C.2")) assertEquals(e.encodedHex.joinToString(""), encoder.encode(pairs(e.fields)).hex(), e.id)
            }
        }
    }

    @Test
    fun huffmanVectors() {
        val v = Rfc7541Vectors.HUFFMAN.chunked(2)
        assertTrue(v.size >= 10)
        for ((s, code) in v) {
            val out = HpackWriter()
            Huffman.encode(s.latin1(), out)
            assertEquals(code, out.toByteArray().hex(), s)
            assertEquals(s, Huffman.decode(hex(code), 0, code.length / 2, 1000).latin1())
        }
    }

    @Test
    fun huffmanRoundTripAllBytes() {
        val all = ByteArray(256) { it.toByte() }
        val out = HpackWriter()
        Huffman.encode(all, out)
        val enc = out.toByteArray()
        assertEquals(Huffman.encodedLength(all), enc.size)
        assertTrue(all.contentEquals(Huffman.decode(enc, 0, enc.size, 256)))
    }
}
