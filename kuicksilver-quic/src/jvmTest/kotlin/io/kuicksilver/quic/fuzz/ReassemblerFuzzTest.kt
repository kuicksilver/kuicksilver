// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.stream.RangeBudget
import io.kuicksilver.quic.stream.Reassembler
import io.kuicksilver.quic.stream.ReassemblyFull
import java.util.BitSet

/**
 * Fuzz target `streamReassembler`: the input is a list of operations, checked against a bitmap model.
 * Insert = [op & 3 in 0..1][offset: u16 relative to readOffset - 256][length: u16 % 2048];
 * read = [op & 3 == 2][max length: u8 * 16]; clear = [op & 3 == 3][selector: u8, clears when 0].
 * Bytes at stream offset o carry the value (o * 31 + 7) so overlapping copies agree, as flow control guarantees the
 * window: offsets stay within 64 KiB of the read offset.
 */
class ReassemblerFuzzTest {
    private fun valueAt(o: Long): Byte = (o * 31 + 7).toByte()

    @FuzzTest(maxDuration = "60s")
    fun streamReassembler(data: ByteArray) {
        KslLoader.ensureLoaded()
        val budget = RangeBudget(3)
        val r = Reassembler(4, budget)
        val have = BitSet() // received, unread offsets, indexed from the read offset
        val src = PacketBuffer.allocate(2048 + 256)
        val out = ByteArray(255 * 16)
        try {
            var p = 0

            fun u8(): Int = if (p < data.size) data[p++].toInt() and 0xff else 0

            fun u16(): Int = (u8() shl 8) or u8()
            while (p < data.size) {
                val op = u8() and 3
                when (op) {
                    0, 1 -> {
                        val offset = maxOf(0L, r.readOffset - 256 + u16())
                        val len = u16() % 2048
                        val pad = u8() % 256 // the slice starts at an arbitrary position of the packet buffer
                        for (i in 0 until len) src[pad + i] = valueAt(offset + i)
                        val before = r.rangeCount
                        try {
                            r.insert(offset, src, pad, len)
                        } catch (e: ReassemblyFull) {
                            check(r.rangeCount == before) { "a refused insert changed the ranges" }
                            check(before >= 4 || budget.used >= budget.max) { "refused below the limits: ${e.message}" }
                            check(offset > r.readOffset) { "refused a frame at the read offset" }
                            continue
                        }
                        val from = maxOf(offset, r.readOffset)
                        if (offset + len >
                            from
                        ) {
                            have.set((from - r.readOffset).toInt(), (offset + len - r.readOffset).toInt())
                        }
                    }

                    2 -> {
                        val max = u8() * 16
                        val expected = have.nextClearBit(0).let { if (have.get(0)) it else 0 }
                        check(r.readable == expected) { "readable ${r.readable}, model $expected" }
                        val base = r.readOffset
                        val n = r.read(out, 0, max)
                        check(n == minOf(max, expected)) { "read $n of ${minOf(max, expected)}" }
                        for (i in 0 until n) check(out[i] == valueAt(base + i)) { "wrong byte at stream offset ${base + i}" }
                        shift(have, n)
                    }

                    3 -> {
                        if (u8() == 0) {
                            r.clear()
                            have.clear()
                        }
                    }
                }
                check(r.rangeCount == runs(have)) { "ranges ${r.rangeCount}, model ${runs(have)}" }
                // 4 gaps plus the readable range at the read offset, which is always taken
                check(budget.used == r.rangeCount && r.rangeCount <= 5) { "budget ${budget.used} for ${r.rangeCount} ranges" }
            }
        } finally {
            src.close()
        }
    }

    private fun shift(
        b: BitSet,
        n: Int,
    ) {
        if (n == 0) return
        val s = b.get(n, maxOf(n, b.length()))
        b.clear()
        b.or(s)
    }

    private fun runs(b: BitSet): Int {
        var c = 0
        var i = b.nextSetBit(0)
        while (i >=
            0
        ) {
            c++
            i = b.nextSetBit(b.nextClearBit(i))
        }
        return c
    }
}
