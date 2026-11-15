// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.message

/**
 * RFC 8941 section 4.2.7: the Byte Sequence starting with the `:` at [start] of [s]; returns the index after its closing
 * `:`, or -1 when parsing fails. "If b64_content contains a character not included in ALPHA, DIGIT, "+", "/", and "=",
 * fail parsing", and "If base64 decoding fails, parsing fails": decoding fails on `=` before the data ends, more than two
 * `=`, a length of 1 modulo 4, or `=` padding that does not complete a quantum. Missing padding and non-zero pad bits are
 * accepted, as the section asks ("parsers SHOULD NOT fail when "=" padding is not present").
 */
internal fun sfByteSequenceEnd(
    s: String,
    start: Int,
): Int {
    if (start >= s.length || s[start] != ':') return -1
    var pos = start + 1
    var data = 0
    var padding = 0
    while (pos < s.length) {
        val c = s[pos++]
        when {
            c == ':' -> {
                if (data % 4 == 1 || (padding > 0 && (data + padding) % 4 != 0)) return -1
                return pos
            }

            c == '=' -> {
                if (++padding > 2) return -1
            }

            c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '+' || c == '/' -> {
                if (padding > 0) return -1
                data++
            }

            else -> {
                return -1
            }
        }
    }
    return -1
}
