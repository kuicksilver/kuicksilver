// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.native

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class PacketBufferTest {
    @Test fun copyInAndOut() {
        PacketBuffer.allocate(16).use { b ->
            b.copyFrom(byteArrayOf(1, 2, 3, 4), 1, 2, 3)
            assertEquals(2, b[2])
            assertEquals(4, b[4])
            b[5] = 9
            val out = ByteArray(4)
            b.copyTo(out, 2, 0, 4)
            assertContentEquals(byteArrayOf(2, 3, 4, 9), out)
            assertEquals(16, b.capacity)
        }
    }

    @Test fun boundsAreChecked() {
        PacketBuffer.allocate(4).use { b ->
            assertFailsWith<IndexOutOfBoundsException> { b[4] }
            assertFailsWith<IndexOutOfBoundsException> { b[-1] }
            assertFailsWith<IndexOutOfBoundsException> { b[Int.MIN_VALUE] }
            assertFailsWith<IndexOutOfBoundsException> { b[4] = 1 }
            assertFailsWith<IndexOutOfBoundsException> { b[-1] = 1 }
            b[3] = 7
            assertEquals(7, b[3])
            b[0] = -1
            assertEquals(-1, b[0])
            assertFailsWith<IndexOutOfBoundsException> { b.copyFrom(ByteArray(8), 0, 0, 8) }
        }
    }

    /** The Kotlin array side of a copy is bounds-checked on every platform (Native used to memcpy past it). */
    @Test fun negative_arrayBoundsChecked() {
        PacketBuffer.allocate(16).use { b ->
            assertFailsWith<IndexOutOfBoundsException> { b.copyFrom(ByteArray(2), 0, 0, 4) }
            assertFailsWith<IndexOutOfBoundsException> { b.copyFrom(ByteArray(4), 2, 0, 4) }
            assertFailsWith<IndexOutOfBoundsException> { b.copyFrom(ByteArray(4), -1, 0, 1) }
            assertFailsWith<IndexOutOfBoundsException> { b.copyTo(ByteArray(2), 0, 0, 4) }
            assertFailsWith<IndexOutOfBoundsException> { b.copyTo(ByteArray(4), 0, 3, 2) }
            assertFailsWith<IndexOutOfBoundsException> { b.copyTo(ByteArray(4), 0, -1, 1) }
            assertFailsWith<IndexOutOfBoundsException> { b.copyFrom(ByteArray(4), Int.MAX_VALUE, 0, 2) }
        }
    }

    @Test fun useAfterCloseThrows() {
        val b = PacketBuffer.allocate(4)
        b.close()
        b.close()
        assertFailsWith<IllegalStateException> { b[0] }
        assertFailsWith<IllegalStateException> { b[0] = 1 }
        // closed wins over out of range: the closed check comes first (one null test before the index compare on Native)
        assertFailsWith<IllegalStateException> { b[4] }
        assertFailsWith<IllegalStateException> { b[-1] = 1 }
    }
}
