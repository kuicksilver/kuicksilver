// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.hpack

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The Huffman table is a generated copy of the one in kuicksilver-http3 (ADR-0017): its digest must be the one
 * tools/http/gen-tables.py computed from the RFC 7541 text, and `gen-tables.py --check` compares both modules' copies.
 */
class HuffmanTableParityTest {
    @Test
    fun tableMatchesGenerator() {
        val bytes = ByteArray(257 * 4 + 257)
        for (i in 0 until 257) {
            val c = HuffmanTable.CODES[i]
            for (k in 0 until 4) bytes[i * 4 + k] = (c ushr (24 - 8 * k)).toByte()
            bytes[257 * 4 + i] = HuffmanTable.LENGTHS[i]
        }
        assertEquals(Rfc7541Vectors.HUFFMAN_TABLE_SHA256, sha256Hex(bytes))
    }

    @Test
    fun sha256KnownAnswer() {
        // FIPS 180-2 appendix B.1: "abc"
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", sha256Hex("abc".encodeToByteArray()))
    }
}

/** SHA-256 (FIPS 180-4) for the parity test; the common test sources have no digest of their own. */
internal fun sha256Hex(msg: ByteArray): String {
    val k =
        intArrayOf(
            0x428a2f98,
            0x71374491,
            -0x4a3f0431,
            -0x164a245b,
            0x3956c25b,
            0x59f111f1,
            -0x6dc07d5c,
            -0x54e3a12b,
            -0x27f85568,
            0x12835b01,
            0x243185be,
            0x550c7dc3,
            0x72be5d74,
            -0x7f214e02,
            -0x6423f959,
            -0x3e640e8c,
            -0x1b64963f,
            -0x1041b87a,
            0x0fc19dc6,
            0x240ca1cc,
            0x2de92c6f,
            0x4a7484aa,
            0x5cb0a9dc,
            0x76f988da,
            -0x67c1aeae,
            -0x57ce3993,
            -0x4ffcd838,
            -0x40a68039,
            -0x391ff40d,
            -0x2a586eb9,
            0x06ca6351,
            0x14292967,
            0x27b70a85,
            0x2e1b2138,
            0x4d2c6dfc,
            0x53380d13,
            0x650a7354,
            0x766a0abb,
            -0x7e3d36d2,
            -0x6d8dd37b,
            -0x5d40175f,
            -0x57e599b5,
            -0x3db47490,
            -0x3893ae5d,
            -0x2e6d17e7,
            -0x2966f9dc,
            -0xbf1ca7b,
            0x106aa070,
            0x19a4c116,
            0x1e376c08,
            0x2748774c,
            0x34b0bcb5,
            0x391c0cb3,
            0x4ed8aa4a,
            0x5b9cca4f,
            0x682e6ff3,
            0x748f82ee,
            0x78a5636f,
            -0x7b3787ec,
            -0x7338fdf8,
            -0x6f410006,
            -0x5baf9315,
            -0x41065c09,
            -0x398e870e,
        )
    val h = intArrayOf(0x6a09e667, -0x4498517b, 0x3c6ef372, -0x5ab00ac6, 0x510e527f, -0x64fa9774, 0x1f83d9ab, 0x5be0cd19)
    val bitLen = msg.size.toLong() * 8
    val padded = ByteArray(((msg.size + 9 + 63) / 64) * 64)
    msg.copyInto(padded)
    padded[msg.size] = 0x80.toByte()
    for (i in 0 until 8) padded[padded.size - 1 - i] = (bitLen ushr (8 * i)).toByte()
    val w = IntArray(64)
    for (chunk in padded.indices step 64) {
        for (i in 0 until 16) {
            w[i] = ((padded[chunk + 4 * i].toInt() and 0xff) shl 24) or ((padded[chunk + 4 * i + 1].toInt() and 0xff) shl 16) or
                ((padded[chunk + 4 * i + 2].toInt() and 0xff) shl 8) or (padded[chunk + 4 * i + 3].toInt() and 0xff)
        }
        for (i in 16 until 64) {
            val s0 = w[i - 15].rotateRight(7) xor w[i - 15].rotateRight(18) xor (w[i - 15] ushr 3)
            val s1 = w[i - 2].rotateRight(17) xor w[i - 2].rotateRight(19) xor (w[i - 2] ushr 10)
            w[i] = w[i - 16] + s0 + w[i - 7] + s1
        }
        var (a, b, c, d) = h
        var e = h[4]
        var f = h[5]
        var g = h[6]
        var hh = h[7]
        for (i in 0 until 64) {
            val t1 = hh + (e.rotateRight(6) xor e.rotateRight(11) xor e.rotateRight(25)) + ((e and f) xor (e.inv() and g)) + k[i] + w[i]
            val t2 = (a.rotateRight(2) xor a.rotateRight(13) xor a.rotateRight(22)) + ((a and b) xor (a and c) xor (b and c))
            hh = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2
        }
        h[0] += a
        h[1] += b
        h[2] += c
        h[3] += d
        h[4] += e
        h[5] += f
        h[6] += g
        h[7] += hh
    }
    return h.joinToString("") { it.toUInt().toString(16).padStart(8, '0') }
}
