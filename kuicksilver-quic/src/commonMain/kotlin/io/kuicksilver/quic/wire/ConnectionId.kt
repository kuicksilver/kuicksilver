// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kuicksilver.native.PacketBuffer

/** A connection ID of 0..20 bytes (RFC 9000 section 5.1); immutable, compared by content. */
internal class ConnectionId(
    bytes: ByteArray,
) {
    private val bytes: ByteArray = bytes.copyOf()
    val length: Int get() = bytes.size

    init {
        require(bytes.size <= 20) { "connection id longer than 20 bytes" }
    }

    fun copyTo(
        buf: PacketBuffer,
        off: Int,
    ) {
        buf.copyFrom(bytes, 0, off, bytes.size)
    }

    fun toByteArray(): ByteArray = bytes.copyOf()

    fun copyToArray(
        dst: ByteArray,
        off: Int,
    ) {
        bytes.copyInto(dst, off)
    }

    operator fun get(i: Int): Byte = bytes[i]

    fun contentEquals(
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): Boolean {
        if (len != bytes.size) return false
        for (i in 0 until len) if (buf[off + i] != bytes[i]) return false
        return true
    }

    override fun equals(other: Any?): Boolean = other is ConnectionId && other.bytes.contentEquals(bytes)

    override fun hashCode(): Int = bytes.contentHashCode()

    override fun toString(): String = bytes.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    companion object {
        val EMPTY: ConnectionId = ConnectionId(ByteArray(0))
    }
}
