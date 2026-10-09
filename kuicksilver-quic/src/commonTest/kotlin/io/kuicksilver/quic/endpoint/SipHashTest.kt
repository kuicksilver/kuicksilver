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

    @Test fun differentKeysDifferentHashes() {
        val m = ByteArray(8) { 5 }
        assertNotEquals(hash(1, 2, m), hash(3, 4, m))
    }
}
