// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kotest.property.Arb
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.long
import io.kotest.property.checkAll
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ReassemblerTest {
    private fun insert(
        r: Reassembler,
        offset: Long,
        bytes: ByteArray,
    ) {
        val b = PacketBuffer.of(bytes + ByteArray(1))
        try {
            r.insert(offset, b, 0, bytes.size)
        } finally {
            b.close()
        }
    }

    private fun readAll(r: Reassembler): ByteArray {
        val out = ByteArray(r.readable)
        var off = 0
        while (off <
            out.size
        ) {
            off += r.read(out, off, out.size - off)
        }
        return out
    }

    @Test fun outOfOrderAndDuplicatesDeliverExactBytes() =
        runTest {
            checkAll(200, Arb.long(1L..1000L), Arb.int(16..64)) { seed, chunk ->
                // chunks of 16+ bytes keep the worst case under the 256-range cap
                val data = ByteArray(2000) { (it * 7 + seed).toByte() }
                val rnd = Random(seed)
                val pieces = (0 until data.size step chunk).map { it to minOf(chunk, data.size - it) }.shuffled(rnd)
                val r = Reassembler(256, RangeBudget(4096))
                for ((off, len) in pieces) {
                    insert(r, off.toLong(), data.copyOfRange(off, off + len))
                    if (rnd.nextInt(4) ==
                        0
                    ) {
                        insert(r, off.toLong(), data.copyOfRange(off, off + len))
                    }
                }
                val overlapStart = rnd.nextInt(data.size - 100)
                insert(
                    r,
                    overlapStart.toLong(),
                    data.copyOfRange(
                        overlapStart,
                        overlapStart + 100,
                    ),
                )
                assertEquals(data.size, r.readable)
                assertContentEquals(data, readAll(r))
                assertEquals(0, r.rangeCount)
            }
        }

    @Test fun negative_fragmentedStreamRangesCap() {
        val r = Reassembler(256, RangeBudget(4096))
        for (i in 0 until 256) insert(r, 2L * i + 2, byteArrayOf(1)) // gaps keep every fragment its own range
        assertEquals(256, r.rangeCount)
        // refused without a connection error: loss alone can get a peer here (K7 F2.9); the packet goes unacknowledged
        assertFailsWith<ReassemblyFull> { insert(r, 2L * 256 + 2, byteArrayOf(1)) }
        assertEquals(256, r.rangeCount)
        insert(r, 3, byteArrayOf(1)) // filling a hole merges and is always taken
        assertEquals(255, r.rangeCount)
        val budget = RangeBudget(4096)
        val streams = List(17) { Reassembler(256, budget) }
        var n = 0
        assertFailsWith<ReassemblyFull> {
            for (s in streams) {
                for (i in 0 until 256) {
                    insert(s, 2L * i + 2, byteArrayOf(1))
                    n++
                }
            }
        }
        assertEquals(4096, n, "the 4097th range on the connection is refused")
    }

    @Test fun overlappingDataMustMatchIsAcceptedOnce() {
        val r = Reassembler(256, RangeBudget(4096))
        insert(r, 0, byteArrayOf(1, 2, 3, 4))
        insert(r, 2, byteArrayOf(3, 4, 5, 6))
        insert(r, 0, byteArrayOf(1, 2))
        assertEquals(6, r.readable)
        assertContentEquals(byteArrayOf(1, 2, 3, 4, 5, 6), readAll(r))
        assertEquals(0, r.readable)
    }

    @Test fun readableIsContiguousPrefixOnly() {
        val r = Reassembler(256, RangeBudget(4096))
        insert(r, 10, byteArrayOf(9))
        assertEquals(0, r.readable)
        insert(r, 0, ByteArray(10))
        assertEquals(11, r.readable)
    }

    // ---- reads copy little, drained windows shrink ----
    @Test fun readMovesOnlyWhatItReturns() {
        val r = Reassembler(256, RangeBudget(4096))
        val total = 1 shl 20
        val chunk = 16 shl 10
        var off = 0L
        while (off < total) {
            insert(r, off, ByteArray(chunk) { (off + it).toByte() })
            off += chunk
        }
        val before = r.bytesMovedForTest
        val out = ByteArray(chunk)
        var read = 0
        while (read < total) read += r.read(out, 0, chunk)
        assertTrue(
            r.bytesMovedForTest - before <= 2L * total,
            "reads copy each byte at most twice, never the whole buffer per read: ${r.bytesMovedForTest - before}",
        )
    }

    @Test fun drainedLargeWindowShrinks() {
        val r = Reassembler(256, RangeBudget(4096))
        insert(r, 0, ByteArray(2 shl 20))
        assertTrue(r.capacityForTest >= (2 shl 20))
        val out = ByteArray(64 shl 10)
        while (r.readable > 0) r.read(out, 0, out.size)
        assertTrue(r.capacityForTest <= 4096, "an empty reassembler does not keep a multi-megabyte window: ${r.capacityForTest}")
    }
}
