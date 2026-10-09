// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.native.PacketBuffer

/** SipHash-2-4 over a buffer slice (keyed CID routing: attackers cannot steer connections into one bucket). */
internal object SipHash {
    private fun rotl(
        x: Long,
        b: Int,
    ): Long = (x shl b) or (x ushr (64 - b))

    fun hash24(
        k0: Long,
        k1: Long,
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): Long {
        var v0 =
            k0 xor 0x736f6d6570736575L
        var v1 =
            k1 xor 0x646f72616e646f6dL
        var v2 = k0 xor 0x6c7967656e657261L
        var v3 = k1 xor 0x7465646279746573L

        fun round() {
            v0 += v1
            v1 = rotl(v1, 13)
            v1 = v1 xor v0
            v0 = rotl(v0, 32)
            v2 += v3
            v3 = rotl(v3, 16)
            v3 = v3 xor v2
            v0 += v3
            v3 = rotl(v3, 21)
            v3 = v3 xor v0
            v2 += v1
            v1 = rotl(v1, 17)
            v1 = v1 xor v2
            v2 = rotl(v2, 32)
        }
        val end = off + len
        var p = off
        while (end - p >= 8) {
            var m = 0L
            for (i in 0 until 8) m = m or ((buf[p + i].toLong() and 0xff) shl (8 * i))
            p += 8
            v3 = v3 xor m
            round()
            round()
            v0 = v0 xor m
        }
        var b = len.toLong() shl 56
        var i = 0
        while (p < end) {
            b = b or ((buf[p].toLong() and 0xff) shl (8 * i))
            p++
            i++
        }
        v3 = v3 xor b
        round()
        round()
        v0 = v0 xor b
        v2 = v2 xor 0xff
        round()
        round()
        round()
        round()
        return v0 xor v1 xor v2 xor v3
    }
}
