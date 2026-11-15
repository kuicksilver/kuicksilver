// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.message

// Structured Field pieces (RFC 8941) shared by the parsers of `Capsule-Protocol` (CapsuleRules), `priority`
// (PriorityDictionary) and `WT-Available-Protocols` / `WT-Protocol` (WtProtocols), so all of them accept the same values.
// Each returns the index after what it parsed, or -1 when parsing fails.

/**
 * RFC 8941 section 4.2.3.2: `*( ";" *SP key [ "=" bare-item ] )` from [start] (section 3.1.2); where it stopped (the
 * first character that does not start another parameter), or -1 on a malformed one.
 */
internal fun sfParametersEnd(
    s: String,
    start: Int,
): Int {
    var p = start
    while (p < s.length && s[p] == ';') {
        p++
        while (p < s.length && s[p] == ' ') p++
        p = sfKeyEnd(s, p)
        if (p < 0) return -1
        if (p < s.length && s[p] == '=') {
            p = sfBareItemEnd(s, p + 1)
            if (p < 0) return -1
        }
    }
    return p
}

/** RFC 8941 section 4.2.3.3: `key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )`, ASCII only. */
internal fun sfKeyEnd(
    s: String,
    start: Int,
): Int {
    if (start >= s.length || !(s[start] in 'a'..'z' || s[start] == '*')) return -1
    var p = start + 1
    while (p < s.length && (s[p] in 'a'..'z' || s[p] in '0'..'9' || s[p] in "_-.*")) p++
    return p
}

/** RFC 8941 section 4.2.3.1: an Integer, Decimal, String, Token, Byte Sequence or Boolean at [start]. */
internal fun sfBareItemEnd(
    s: String,
    start: Int,
): Int {
    if (start >= s.length) return -1
    val c = s[start]
    return when {
        c == '-' || c in '0'..'9' -> sfNumberEnd(s, start)
        c == '"' -> sfStringEnd(s, start)
        c == '*' || c in 'a'..'z' || c in 'A'..'Z' -> sfTokenEnd(s, start)
        c == ':' -> sfByteSequenceEnd(s, start)
        c == '?' -> if (start + 1 < s.length && s[start + 1] in "01") start + 2 else -1
        else -> -1
    }
}

/** RFC 8941 section 4.2.4: at most 15 integer digits, or a Decimal of at most 12 integer and 1 to 3 fraction digits. */
internal fun sfNumberEnd(
    s: String,
    start: Int,
): Int {
    var p = start
    if (p < s.length && s[p] == '-') p++
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

/** RFC 8941 section 4.2.5: printable ASCII between double quotes, `\` escaping only `"` and `\`. */
internal fun sfStringEnd(
    s: String,
    start: Int,
): Int {
    if (start >= s.length || s[start] != '"') return -1
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

/** RFC 8941 section 4.2.6: ALPHA or `*`, then tchar, `:` or `/`. */
internal fun sfTokenEnd(
    s: String,
    start: Int,
): Int {
    if (start >= s.length || !(s[start] == '*' || s[start] in 'a'..'z' || s[start] in 'A'..'Z')) return -1
    var p = start + 1
    while (p < s.length && (s[p] in 'a'..'z' || s[p] in 'A'..'Z' || s[p] in '0'..'9' || s[p] in "!#$%&'*+-.^_`|~:/")) p++
    return p
}

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
