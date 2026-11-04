// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.native.PacketBuffer

/** SipHash-2-4 over a buffer slice (keyed CID routing: attackers cannot steer connections into one bucket). */
internal object SipHash {
    fun hash24(
        k0: Long,
        k1: Long,
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): Long = hash24(k0, k1, off, len) { buf[it] }

    /** As the [PacketBuffer] variant, over a heap array slice (the 0-RTT replay register's ticket identities, the CID registry's keys). */
    fun hash24(
        k0: Long,
        k1: Long,
        buf: ByteArray,
        off: Int = 0,
        len: Int = buf.size,
    ): Long = hash24(k0, k1, off, len) { buf[it] }

    /**
     * The one SipHash-2-4 body, inlined into each variant with its byte read: no lambda object and no boxed state (a local
     * round function mutating the four words would capture them in heap cells on the JVM). Every block, the last one with
     * the length in its top byte, takes two SipRounds; finalization (v2 ^= 0xff, four SipRounds) is the same compression
     * step run twice on a zero word, which leaves v3 and v0 unchanged by the XORs.
     */
    private inline fun hash24(
        k0: Long,
        k1: Long,
        off: Int,
        len: Int,
        byteAt: (Int) -> Byte,
    ): Long {
        var v0 = k0 xor 0x736f6d6570736575L
        var v1 = k1 xor 0x646f72616e646f6dL
        var v2 = k0 xor 0x6c7967656e657261L
        var v3 = k1 xor 0x7465646279746573L
        val words = len ushr 3
        val tail = off + (words shl 3)
        for (w in 0 until words + 3) {
            val m: Long =
                if (w < words) {
                    val p = off + (w shl 3)
                    var x = 0L
                    for (i in 0 until 8) x = x or ((byteAt(p + i).toLong() and 0xff) shl (8 * i))
                    x
                } else if (w == words) {
                    var x = len.toLong() shl 56
                    for (i in 0 until (len and 7)) x = x or ((byteAt(tail + i).toLong() and 0xff) shl (8 * i))
                    x
                } else {
                    if (w == words + 1) v2 = v2 xor 0xff
                    0L
                }
            v3 = v3 xor m
            repeat(2) {
                v0 += v1
                v1 = (v1 shl 13) or (v1 ushr 51)
                v1 = v1 xor v0
                v0 = (v0 shl 32) or (v0 ushr 32)
                v2 += v3
                v3 = (v3 shl 16) or (v3 ushr 48)
                v3 = v3 xor v2
                v0 += v3
                v3 = (v3 shl 21) or (v3 ushr 43)
                v3 = v3 xor v0
                v2 += v1
                v1 = (v1 shl 17) or (v1 ushr 47)
                v1 = v1 xor v2
                v2 = (v2 shl 32) or (v2 ushr 32)
            }
            v0 = v0 xor m
        }
        return v0 xor v1 xor v2 xor v3
    }
}
