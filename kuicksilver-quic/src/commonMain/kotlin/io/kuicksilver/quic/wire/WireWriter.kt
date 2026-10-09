// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kuicksilver.native.PacketBuffer

/** A cursor writing into a [PacketBuffer] slice; callers size frames with the encoder's overhead helpers before writing. */
internal class WireWriter(
    var buf: PacketBuffer,
    var pos: Int,
    var limit: Int,
) {
    val remaining: Int get() = limit - pos

    private fun need(n: Int) {
        if (remaining < n) throw IndexOutOfBoundsException("writer needs $n bytes, $remaining left")
    }

    fun u8(v: Int) {
        need(1)
        buf[pos++] = v.toByte()
    }

    fun u16(v: Int) {
        need(2)
        buf[pos] = (v ushr 8).toByte()
        buf[pos + 1] = v.toByte()
        pos += 2
    }

    fun u32(v: Long) {
        need(4)
        for (i in 0 until 4) buf[pos + i] = (v ushr (8 * (3 - i))).toByte()
        pos += 4
    }

    fun u64(v: Long) {
        need(8)
        for (i in 0 until 8) buf[pos + i] = (v ushr (8 * (7 - i))).toByte()
        pos += 8
    }

    fun varint(v: Long) {
        need(VarInt.size(v))
        pos = VarInt.write(buf, pos, v)
    }

    fun bytes(
        src: ByteArray,
        off: Int = 0,
        len: Int = src.size - off,
    ) {
        need(len)
        buf.copyFrom(src, off, pos, len)
        pos += len
    }

    fun cid(c: ConnectionId) {
        need(c.length)
        c.copyTo(buf, pos)
        pos += c.length
    }

    fun copy(
        src: PacketBuffer,
        off: Int,
        len: Int,
    ) {
        need(len)
        for (i in 0 until len) buf[pos + i] = src[off + i]
        pos += len
    }

    fun zero(len: Int) {
        need(len)
        for (i in 0 until len) buf[pos + i] = 0
        pos += len
    }
}
