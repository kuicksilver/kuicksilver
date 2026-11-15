// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.message

import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.frame.VarInt

/** Sans-IO pieces of the Capsule Protocol (RFC 9297 section 3): the `Capsule-Protocol` field, the section 3.2 rules, encoding. */
internal object CapsuleRules {
    const val FIELD: String = "capsule-protocol"

    /** Largest capsule type: a QUIC variable-length integer (RFC 9297 section 3.2). */
    const val MAX_TYPE: Long = (1L shl 62) - 1

    /**
     * RFC 9297 section 3.4: the field is a Structured Field Item (RFC 8941) of type Boolean; parameters are ignored. One
     * field line whose value is `?1` (with any well-formed parameters) is true; `?0`, any other item, a parse failure or
     * several field lines (they would combine into a List) is false.
     */
    fun isEnabled(headers: Http3Headers): Boolean {
        val values = headers.getAll(FIELD)
        if (values.size != 1) return false
        val v = values[0].trim(' ', '\t')
        if (!v.startsWith("?1")) return false
        return sfParametersEnd(v, 2) == v.length
    }

    /**
     * RFC 9297 section 3.2: the Capsule Protocol MUST NOT be used with messages that carry Content-Length, Content-Type or
     * Transfer-Encoding, nor with 204, 205 or 206 responses. Returns the broken rule, or null. [status] is null for a request.
     */
    fun violation(
        headers: Http3Headers,
        status: Int?,
    ): String? {
        for (name in FORBIDDEN_FIELDS) if (headers[name] != null) return "$name with the Capsule Protocol (RFC 9297 section 3.2)"
        if (status != null && status in FORBIDDEN_STATUSES) return "status $status with the Capsule Protocol (RFC 9297 section 3.2)"
        return null
    }

    /** Type, length and value, each varint the shortest encoding. */
    fun encode(
        type: Long,
        value: ByteArray,
    ): ByteArray = VarInt.encode(type) + VarInt.encode(value.size.toLong()) + value

    private val FORBIDDEN_FIELDS = listOf("content-length", "content-type", "transfer-encoding")
    private val FORBIDDEN_STATUSES = setOf(204, 205, 206)
}
