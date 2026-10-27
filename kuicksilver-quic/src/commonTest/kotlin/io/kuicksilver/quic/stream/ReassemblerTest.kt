// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.forAllSeeded
import io.kuicksilver.quic.int
import io.kuicksilver.quic.long
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
        forAllSeeded(200, seed = 0x4EA55L) { draw, _ ->
            val seed = draw.long(1L..1000L)
            val chunk = draw.int(16..64)
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

    @Test fun negative_fragmentedStreamRangesCap() {
        val r = Reassembler(256, RangeBudget(4096))
        for (i in 0 until 256) insert(r, 2L * i + 2, byteArrayOf(1)) // gaps keep every fragment its own range
        assertEquals(256, r.rangeCount)
        // refused without a connection error: loss alone can get a peer here; the packet goes unacknowledged
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

    /**
     * Review: a frame at the read offset that does not reach the first buffered range opened a new range, and with the
     * stream at its gap limit it was refused. Nothing was readable, so nothing ever freed a range, and the peer's retransmissions
     * of that frame were refused too, until the idle timeout. A frame at the read offset makes data readable and opens no gap:
     * it is always taken, and the transfer completes.
     */
    @Test fun aFrameAtTheReadOffsetIsTakenAtTheGapLimit() {
        val r = Reassembler(256, RangeBudget(4096))
        val data = ByteArray(513) { (it * 7 + 1).toByte() }
        for (i in 1..256) insert(r, 2L * i, byteArrayOf(data[2 * i])) // 256 gaps: [1,2), [3,4), ...
        assertEquals(0, r.readable)
        assertFailsWith<ReassemblyFull> { insert(r, 600, byteArrayOf(1)) } // a new gap is still refused
        insert(r, 0, byteArrayOf(data[0])) // at the read offset: was refused
        assertEquals(1, r.readable)
        assertFailsWith<ReassemblyFull> { insert(r, 600, byteArrayOf(1)) } // and the cap on gaps still holds
        for (i in 0 until 256) insert(r, 2L * i + 1, byteArrayOf(data[2 * i + 1])) // the holes merge
        assertContentEquals(data, readAll(r))
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
