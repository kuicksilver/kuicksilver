// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.Arbs
import io.kuicksilver.quic.forAllSeeded
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class VarIntTest {
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun read(hex: String): Long {
        val b = PacketBuffer.of(hex(hex))
        try {
            return WireReader(b, 0, b.capacity).varint()
        } finally {
            b.close()
        }
    }

    @Test fun rfc9000AppendixA1Examples() {
        assertEquals(151288809941952652L, read("c2197c5eff14e88c"))
        assertEquals(494878333L, read("9d7f3e7d"))
        assertEquals(15293L, read("7bbd"))
        assertEquals(37L, read("25"))
        assertEquals(37L, read("4025"))
    }

    @Test fun minimalEncodingSizes() {
        assertEquals(1, VarInt.size(63))
        assertEquals(2, VarInt.size(64))
        assertEquals(2, VarInt.size(16383))
        assertEquals(4, VarInt.size(16384))
        assertEquals(4, VarInt.size(1073741823))
        assertEquals(8, VarInt.size(1073741824))
        assertEquals(8, VarInt.size(VarInt.MAX))
    }

    @Test fun valueAbove2Pow62Rejected() {
        assertFailsWith<IllegalArgumentException> { VarInt.size(VarInt.MAX + 1) }
        val b = PacketBuffer.allocate(8)
        try {
            assertFailsWith<IllegalArgumentException> { VarInt.write(b, 0, -1) }
        } finally {
            b.close()
        }
    }

    @Test fun truncatedVarintIsFrameEncodingError() {
        val e = assertFailsWith<QuicWireException> { read("40") }
        assertEquals(0x07L, e.code)
    }

    /** Every boundary of the four length classes, then 10 000 random values. */
    @Test fun roundTrip() {
        val b = PacketBuffer.allocate(8)
        try {
            fun check(v: Long) {
                val end = VarInt.write(b, 0, v)
                assertEquals(VarInt.size(v), end, "v=$v")
                val r = WireReader(b, 0, end)
                assertEquals(v, r.varint())
                assertEquals(0, r.remaining)
            }
            for (v in listOf(0L, 1L, 63L, 64L, 16383L, 16384L, (1L shl 30) - 1, 1L shl 30, VarInt.MAX - 1, VarInt.MAX)) check(v)
            forAllSeeded(10_000, seed = 0x7A121L) { rnd, _ -> check(Arbs.varint(rnd)) }
        } finally {
            b.close()
        }
    }
}
