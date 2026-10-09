// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.frame

import io.kuicksilver.http3.Http3ErrorCode

/** Setting identifiers (RFC 9114 section 7.2.4.1, RFC 9204 section 5, RFC 9220 section 3, RFC 9297 section 2.1.1). */
internal object SettingsId {
    const val QPACK_MAX_TABLE_CAPACITY: Long = 0x1
    const val MAX_FIELD_SECTION_SIZE: Long = 0x6
    const val QPACK_BLOCKED_STREAMS: Long = 0x7
    const val ENABLE_CONNECT_PROTOCOL: Long = 0x8
    const val H3_DATAGRAM: Long = 0x33

    /** HTTP/2 settings reserved in HTTP/3: receiving one is H3_SETTINGS_ERROR. */
    val H2_RESERVED: Set<Long> = setOf(0x0L, 0x2L, 0x3L, 0x4L, 0x5L)
}

/** SETTINGS frame payload (RFC 9114 section 7.2.4). */
internal object SettingsCodec {
    fun encode(values: List<Pair<Long, Long>>): ByteArray {
        val out = ByteArray(values.sumOf { VarInt.size(it.first) + VarInt.size(it.second) })
        var p = 0
        for ((id, v) in values) {
            p += VarInt.write(id, out, p)
            p += VarInt.write(v, out, p)
        }
        return out
    }

    /** All settings, unknown and reserved ones included (the caller ignores them). */
    fun decode(payload: ByteArray): Map<Long, Long> {
        val out = LinkedHashMap<Long, Long>()
        var p = 0
        while (p < payload.size) {
            val id = VarInt.read(payload, p, payload.size)
            if (id <
                0
            ) {
                throw H3ProtocolError(Http3ErrorCode.FRAME_ERROR, "truncated setting identifier")
            }
            p += VarInt.encodedLength(payload[p])
            val v = VarInt.read(payload, p, payload.size)
            if (v <
                0
            ) {
                throw H3ProtocolError(Http3ErrorCode.FRAME_ERROR, "truncated setting value")
            }
            p += VarInt.encodedLength(payload[p])
            if (id in SettingsId.H2_RESERVED) throw H3ProtocolError(Http3ErrorCode.SETTINGS_ERROR, "HTTP/2 setting 0x${id.toString(16)}")
            if (id in out) throw H3ProtocolError(Http3ErrorCode.SETTINGS_ERROR, "duplicate setting 0x${id.toString(16)}")
            if ((id == SettingsId.ENABLE_CONNECT_PROTOCOL || id == SettingsId.H3_DATAGRAM) &&
                v > 1
            ) {
                throw H3ProtocolError(Http3ErrorCode.SETTINGS_ERROR, "setting 0x${id.toString(16)} must be 0 or 1")
            }
            out[id] = v
        }
        return out
    }
}
