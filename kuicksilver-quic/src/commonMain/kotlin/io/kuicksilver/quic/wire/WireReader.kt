// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.TransportError

/** A cursor over a [PacketBuffer] slice; running out of bytes is a FRAME_ENCODING_ERROR for the frame being parsed. */
internal class WireReader(
    var buf: PacketBuffer,
    var pos: Int,
    var limit: Int,
) {
    /** Type of the frame being decoded, for error reports. */
    var frameType: Long = 0

    /** Set by the frame decoder: the last packet carried nothing but PING, PADDING and ACK frames. */
    var pingOnly: Boolean = false

    /** Set by the frame decoder: the last packet carried only probing frames (PATH_CHALLENGE, PATH_RESPONSE, NEW_CONNECTION_ID, PADDING; RFC 9000 section 9.1). */
    var probingOnly: Boolean = false

    val remaining: Int get() = limit - pos

    fun require(n: Int) {
        if (n < 0 || limit - pos < n) truncated(n)
    }

    /** Out of line: [require] runs per field, and Kotlin/Native compiles a function that builds a String into a slower one. */
    private fun truncated(n: Int): Nothing =
        throw QuicWireException(TransportError.FRAME_ENCODING_ERROR, frameType, "truncated: need $n bytes, $remaining left")

    fun u8(): Int {
        require(1)
        return buf[pos++].toInt() and 0xff
    }

    fun u16(): Int {
        require(2)
        val v = ((buf[pos].toInt() and 0xff) shl 8) or (buf[pos + 1].toInt() and 0xff)
        pos += 2
        return v
    }

    fun u32(): Long {
        require(4)
        var v = 0L
        for (i in 0 until 4) v = (v shl 8) or (buf[pos + i].toLong() and 0xff)
        pos += 4
        return v
    }

    fun u64(): Long {
        require(8)
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (buf[pos + i].toLong() and 0xff)
        pos += 8
        return v
    }

    fun varint(): Long {
        require(1)
        val first = buf[pos].toInt() and 0xff
        val n = 1 shl (first ushr 6)
        require(n)
        var v = (first and 0x3f).toLong()
        for (i in 1 until n) v = (v shl 8) or (buf[pos + i].toLong() and 0xff)
        pos += n
        return v
    }

    /** Reads a varint that must fit an Int-sized length. */
    fun length(): Int {
        val v = varint()
        if (v >
            remaining
        ) {
            throw QuicWireException(TransportError.FRAME_ENCODING_ERROR, frameType, "length $v beyond payload")
        }
        return v.toInt()
    }

    fun skip(n: Int) {
        require(n)
        pos += n
    }
}
