// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class SipHashTest {
    private fun hash(
        k0: Long,
        k1: Long,
        bytes: ByteArray,
    ): Long {
        val b = PacketBuffer.of(bytes + ByteArray(1))
        try {
            return SipHash.hash24(k0, k1, b, 0, bytes.size)
        } finally {
            b.close()
        }
    }

    @Test fun sipHash24ReferenceVector() {
        // SipHash-2-4 reference: key 00..0f, message 00..0e (15 bytes) -> a129ca6149be45e5 (little-endian 64-bit)
        val k0 = 0x0706050403020100L
        val k1 = 0x0f0e0d0c0b0a0908L
        assertEquals(0xa129ca6149be45e5uL.toLong(), hash(k0, k1, ByteArray(15) { it.toByte() }))
        assertEquals(0x726fdb47dd0e0e31uL.toLong(), hash(k0, k1, ByteArray(0)))
    }

    @Test fun heapSliceHashesAsTheBuffer() {
        // the CID registry keys its entries from a heap array and looks them up from the packet buffer: both must agree
        val all = ByteArray(24) { (it * 37 + 11).toByte() }
        for (off in 0..3) {
            for (len in 0..20) {
                val slice = all.copyOfRange(off, off + len)
                assertEquals(hash(7, 9, slice), SipHash.hash24(7, 9, all, off, len), "off $off len $len")
                assertEquals(hash(7, 9, slice), SipHash.hash24(7, 9, slice), "whole $len")
            }
        }
    }

    /** SipHash-2-4 written out as the paper does (Aumasson and Bernstein, 2012): the model the shared body must match. */
    private fun textbook(
        k0: Long,
        k1: Long,
        m: ByteArray,
    ): Long {
        val v = longArrayOf(k0 xor 0x736f6d6570736575L, k1 xor 0x646f72616e646f6dL, k0 xor 0x6c7967656e657261L, k1 xor 0x7465646279746573L)

        fun rotl(
            x: Long,
            b: Int,
        ) = (x shl b) or (x ushr (64 - b))

        fun sipRound() {
            v[0] += v[1]
            v[1] = rotl(v[1], 13) xor v[0]
            v[0] = rotl(v[0], 32)
            v[2] += v[3]
            v[3] = rotl(v[3], 16) xor v[2]
            v[0] += v[3]
            v[3] = rotl(v[3], 21) xor v[0]
            v[2] += v[1]
            v[1] = rotl(v[1], 17) xor v[2]
            v[2] = rotl(v[2], 32)
        }
        val padded = m.copyOf((m.size / 8 + 1) * 8)
        padded[padded.size - 1] = m.size.toByte()
        for (b in 0 until padded.size / 8) {
            var w = 0L
            for (i in 0 until 8) w = w or ((padded[b * 8 + i].toLong() and 0xff) shl (8 * i))
            v[3] = v[3] xor w
            sipRound()
            sipRound()
            v[0] = v[0] xor w
        }
        v[2] = v[2] xor 0xff
        repeat(4) { sipRound() }
        return v[0] xor v[1] xor v[2] xor v[3]
    }

    @Test fun bothVariantsMatchTheTextbookForEveryLength() {
        val all = ByteArray(80) { (it * 53 + 7).toByte() }
        for (len in 0..64) {
            val m = all.copyOfRange(3, 3 + len)
            val want = textbook(0x0706050403020100L, 0x0f0e0d0c0b0a0908L, m)
            assertEquals(want, hash(0x0706050403020100L, 0x0f0e0d0c0b0a0908L, m), "buffer, $len bytes")
            assertEquals(want, SipHash.hash24(0x0706050403020100L, 0x0f0e0d0c0b0a0908L, all, 3, len), "array slice, $len bytes")
        }
    }

    @Test fun differentKeysDifferentHashes() {
        val m = ByteArray(8) { 5 }
        assertNotEquals(hash(1, 2, m), hash(3, 4, m))
    }
}
