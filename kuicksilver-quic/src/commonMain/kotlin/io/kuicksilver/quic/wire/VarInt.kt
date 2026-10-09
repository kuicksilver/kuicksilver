// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kuicksilver.native.PacketBuffer

/** Variable-length integers (RFC 9000 section 16). */
internal object VarInt {
    const val MAX: Long = (1L shl 62) - 1

    fun size(value: Long): Int {
        require(value in 0..MAX) { "varint out of range: $value" }
        return when {
            value < 64 -> 1
            value < 16384 -> 2
            value < 1073741824 -> 4
            else -> 8
        }
    }

    /** Writes [value] at [offset] and returns the offset after it. */
    fun write(
        buf: PacketBuffer,
        offset: Int,
        value: Long,
    ): Int {
        val n = size(value)
        when (n) {
            1 -> {
                buf[offset] = value.toByte()
            }

            2 -> {
                buf[offset] = (0x40 or (value ushr 8).toInt()).toByte()
                buf[offset + 1] = value.toByte()
            }

            4 -> {
                buf[offset] = (0x80 or (value ushr 24).toInt()).toByte()
                buf[offset + 1] = (value ushr 16).toByte()
                buf[offset + 2] =
                    (value ushr 8).toByte()
                buf[offset + 3] = value.toByte()
            }

            else -> {
                buf[offset] = (0xc0 or (value ushr 56).toInt()).toByte()
                for (i in 1..7) {
                    buf[offset + i] =
                        (value ushr (8 * (7 - i))).toByte()
                }
            }
        }
        return offset + n
    }

    /** Writes [value] in exactly [n] bytes (2, 4 or 8), as the Length field of a long header needs. */
    fun writeFixed(
        buf: PacketBuffer,
        offset: Int,
        value: Long,
        n: Int,
    ): Int {
        require(n == 1 || n == 2 || n == 4 || (n == 8 && value <= MAX))
        val prefix =
            when (n) {
                1 -> 0x00
                2 -> 0x40
                4 -> 0x80
                else -> 0xc0
            }
        buf[offset] = (prefix or (value ushr (8 * (n - 1))).toInt()).toByte()
        for (i in 1 until n) buf[offset + i] = (value ushr (8 * (n - 1 - i))).toByte()
        return offset + n
    }
}
