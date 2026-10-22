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
        return parameters(v, 2) == v.length
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

    /** Parses `*( ";" *SP key [ "=" bare-item ] )` from [start]; returns where it stopped, or -1 on a malformed parameter. */
    private fun parameters(
        s: String,
        start: Int,
    ): Int {
        var p = start
        while (p < s.length && s[p] == ';') {
            p++
            while (p < s.length && s[p] == ' ') p++
            if (p >= s.length || !(s[p] in 'a'..'z' || s[p] == '*')) return -1
            p++
            while (p < s.length && (s[p] in 'a'..'z' || s[p] in '0'..'9' || s[p] in "_-.*")) p++
            if (p < s.length && s[p] == '=') {
                p = bareItem(s, p + 1)
                if (p < 0) return -1
            }
        }
        return p
    }

    /** RFC 8941 section 4.2.3.1: integer, decimal, string, token, byte sequence or boolean; returns its end, or -1. */
    private fun bareItem(
        s: String,
        start: Int,
    ): Int {
        if (start >= s.length) return -1
        val c = s[start]
        return when {
            c == '-' || c in '0'..'9' -> number(s, start)
            c == '"' -> string(s, start)
            c == '*' || c in 'a'..'z' || c in 'A'..'Z' -> token(s, start)
            c == ':' -> byteSequence(s, start)
            c == '?' -> if (start + 1 < s.length && s[start + 1] in "01") start + 2 else -1
            else -> -1
        }
    }

    private fun number(
        s: String,
        start: Int,
    ): Int {
        var p = start
        if (s[p] == '-') p++
        val intStart = p
        while (p < s.length && s[p] in '0'..'9') p++
        val intDigits = p - intStart
        if (intDigits == 0 || intDigits > 15) return -1
        if (p < s.length && s[p] == '.') {
            if (intDigits > 12) return -1
            val fracStart = ++p
            while (p < s.length && s[p] in '0'..'9') p++
            if (p - fracStart !in 1..3) return -1
        }
        return p
    }

    private fun string(
        s: String,
        start: Int,
    ): Int {
        var p = start + 1
        while (p < s.length) {
            val c = s[p++]
            when {
                c == '"' -> return p
                c == '\\' -> if (p < s.length && s[p] in "\"\\") p++ else return -1
                c.code !in 0x20..0x7e -> return -1
            }
        }
        return -1
    }

    private fun token(
        s: String,
        start: Int,
    ): Int {
        var p = start + 1
        while (p < s.length && (isAsciiAlnum(s[p]) || s[p] in "!#$%&'*+-.^_`|~:/")) p++
        return p
    }

    private fun byteSequence(
        s: String,
        start: Int,
    ): Int {
        var p = start + 1
        while (p < s.length && (isAsciiAlnum(s[p]) || s[p] in "+/=")) p++
        return if (p < s.length && s[p] == ':') p + 1 else -1
    }

    private fun isAsciiAlnum(c: Char): Boolean = c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9'
}
