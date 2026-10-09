// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.message

import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.frame.H3ProtocolError
import io.kuicksilver.http3.frame.VarInt

/**
 * The Capsule Protocol of RFC 9297 section 3.2 over the data of a stream: type, length, value. Known capsules (DATAGRAM,
 * 0x00) are delivered whole up to [maxCapsuleLength]; unknown ones are skipped as their bytes arrive, never buffered
 * (section 3.2: unknown types are silently dropped). Base for WebTransport after v1.
 */
internal class CapsuleParser(
    private val maxCapsuleLength: Long = 65_536,
    private val known: Set<Long> = setOf(DATAGRAM),
) {
    private val header = ByteArray(16)
    private var headerLen = 0
    private var type = -1L
    private var remaining = 0L
    private var skipping = false
    private var payload: ByteArray? = null
    private var filled = 0

    /** Largest buffer held at once (tests check that unknown capsules are not buffered). */
    var maxBuffered: Int = 0
        private set

    fun feed(
        bytes: ByteArray,
        off: Int,
        len: Int,
        out: (type: Long, payload: ByteArray) -> Unit,
    ) {
        var p = off
        val end = off + len
        while (p < end) {
            if (type < 0) { // collect the two varints
                header[headerLen++] = bytes[p++]
                val t = VarInt.read(header, 0, headerLen)
                if (t < 0) continue
                val tn = VarInt.encodedLength(header[0])
                val l = VarInt.read(header, tn, headerLen)
                if (l < 0) continue
                headerLen = 0
                type = t
                remaining = l
                skipping = t !in known
                if (!skipping) {
                    if (l >
                        maxCapsuleLength
                    ) {
                        throw H3ProtocolError(Http3ErrorCode.MESSAGE_ERROR, "capsule of $l bytes above $maxCapsuleLength")
                    }
                    payload = ByteArray(l.toInt())
                    filled = 0
                    maxBuffered = maxOf(maxBuffered, l.toInt())
                }
                if (remaining == 0L) finish(out)
                continue
            }
            val n = minOf((end - p).toLong(), remaining).toInt()
            if (!skipping) {
                bytes.copyInto(payload!!, filled, p, p + n)
                filled += n
            }
            p += n
            remaining -= n
            if (remaining == 0L) finish(out)
        }
    }

    private fun finish(out: (Long, ByteArray) -> Unit) {
        val t = type
        val b = payload
        type = -1
        payload = null
        if (!skipping &&
            b != null
        ) {
            out(t, b)
        }
    }

    companion object {
        const val DATAGRAM: Long = 0x00
    }
}
