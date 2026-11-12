// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readByteArray
import kotlinx.io.EOFException

/** WebSocket frames for the guard tests (RFC 6455 section 5.2), built and read byte by byte. */
internal object WsTestFrames {
    fun bytes(vararg b: Int) = ByteArray(b.size) { b[it].toByte() }

    /** One frame as read from the wire: the first byte, the masking key (null when unmasked) and the unmasked payload. */
    class Wire(
        val b0: Int,
        val mask: ByteArray?,
        val payload: ByteArray,
    ) {
        val fin get() = b0 and 0x80 != 0
        val rsv get() = b0 and 0x70
        val opcode get() = b0 and 0x0f
        val closeCode get() = ((payload[0].toInt() and 0xff) shl 8) or (payload[1].toInt() and 0xff)
        val closeReason get() = payload.copyOfRange(2, payload.size)
    }

    /** A frame header for [length] payload bytes, with the masking key [mask] when given. */
    fun header(
        b0: Int,
        length: Long,
        mask: ByteArray? = null,
    ): ByteArray {
        val m = if (mask != null) 0x80 else 0
        val h =
            when {
                length < 126 -> bytes(b0, m or length.toInt())
                length < 65536 -> bytes(b0, m or 126, (length shr 8).toInt(), (length and 0xff).toInt())
                else -> bytes(b0, m or 127) + ByteArray(8) { (length shr (56 - 8 * it)).toByte() }
            }
        return if (mask != null) h + mask else h
    }

    /** A whole frame: [b0], then [payload], masked with [mask] when given. */
    fun frame(
        b0: Int,
        payload: ByteArray,
        mask: ByteArray? = null,
    ): ByteArray {
        val p = payload.copyOf()
        if (mask != null) for (i in p.indices) p[i] = (p[i].toInt() xor mask[i % 4].toInt()).toByte()
        return header(b0, p.size.toLong(), mask) + p
    }

    /** A Close frame with [code] and the raw [reason] bytes. */
    fun close(
        code: Int,
        reason: ByteArray = ByteArray(0),
        mask: ByteArray? = null,
    ): ByteArray = frame(0x88, bytes(code shr 8, code and 0xff) + reason, mask)

    /** Every frame of [channel] until it ends. */
    suspend fun frames(channel: ByteReadChannel): List<Wire> {
        val out = ArrayList<Wire>()
        while (true) {
            val b0 =
                try {
                    channel.readByte().toInt() and 0xff
                } catch (_: EOFException) {
                    return out
                }
            val b1 = channel.readByte().toInt() and 0xff
            var length = (b1 and 0x7f).toLong()
            if (length == 126L) {
                length = channel.readByteArray(2).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xff) }
            } else if (length == 127L) {
                length = channel.readByteArray(8).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xff) }
            }
            val mask = if (b1 and 0x80 != 0) channel.readByteArray(4) else null
            val payload = channel.readByteArray(length.toInt())
            if (mask != null) for (i in payload.indices) payload[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
            out += Wire(b0, mask, payload)
        }
    }
}
