// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

/** One transfer coding of a Transfer-Encoding value (RFC 9112 section 6.1): its name, lower-cased, and whether it has parameters. */
internal class TransferCoding(
    val name: String,
    val hasParameters: Boolean,
)

/**
 * The transfer codings that the Transfer-Encoding field lines [values] list, in order, or null when the value is not
 * `#transfer-coding` (RFC 9112 section 6.1): `token *( OWS ";" OWS transfer-parameter )` with
 * `transfer-parameter = token BWS "=" BWS ( token / quoted-string )` (section 7.3), elements separated by `OWS "," OWS`
 * and empty elements ignored (RFC 9110 section 5.6.1). OWS and BWS are only SP and HTAB (RFC 9110 section 5.6.3): VT,
 * FF or U+00A0 next to `chunked` make the value invalid, not `chunked`. Names are case-insensitive (RFC 9112 section 7).
 */
internal fun transferCodingsOf(values: List<CharSequence>): List<TransferCoding>? {
    val result = ArrayList<TransferCoding>()
    for (s in values) {
        var i = 0

        fun ows() {
            while (i < s.length && isOws(s[i])) i++
        }

        fun token(): Boolean {
            val start = i
            while (i < s.length && isTchar(s[i])) i++
            return i > start
        }

        fun quotedString(): Boolean {
            if (i >= s.length || s[i] != '"') return false
            i++
            while (i < s.length) {
                val c = s[i++]
                when {
                    c == '"' -> return true
                    c == '\\' -> if (i < s.length && isQuotedPairChar(s[i])) i++ else return false
                    !isQdtext(c) -> return false
                }
            }
            return false
        }

        while (true) {
            ows()
            if (i >= s.length) break
            if (s[i] == ',') {
                i++
                continue
            }
            val start = i
            if (!token()) return null
            val name = s.substring(start, i).lowercase()
            var hasParameters = false
            while (true) {
                ows()
                if (i >= s.length || s[i] != ';') break
                i++
                ows()
                if (!token()) return null
                ows()
                if (i >= s.length || s[i] != '=') return null
                i++
                ows()
                if (!token() && !quotedString()) return null
                hasParameters = true
            }
            if (i < s.length && s[i] != ',') return null
            result += TransferCoding(name, hasParameters)
        }
    }
    return result
}

/**
 * The one length that every Content-Length value in [values] states, or null when one is not `1*DIGIT` or they differ
 * (RFC 9110 section 8.6: a list of identical values may be taken as that one value). Only SP and HTAB are OWS around a
 * value or a list element (RFC 9110 section 5.6.3).
 */
internal fun contentLengthOf(values: List<CharSequence>): Long? {
    var result: Long? = null
    for (v in values) {
        for (part in v.split(',')) {
            val t = part.trim(::isOws)
            if (t.isEmpty() || t.length > 18 || t.any { it !in '0'..'9' }) return null
            val n = t.toLong()
            if (result != null && result != n) return null
            result = n
        }
    }
    return result
}

/** OWS (RFC 9110 section 5.6.3). */
private fun isOws(c: Char) = c == ' ' || c == '\t'

/** tchar (RFC 9110 section 5.6.2). */
private fun isTchar(c: Char) = c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c in "!#$%&'*+-.^_`|~"

/** obs-text (RFC 9110 section 5.5): a byte above 0x7F, here a decoded character above U+007F. */
private fun isObsText(c: Char) = c.code >= 0x80

/** qdtext (RFC 9110 section 5.6.4). */
private fun isQdtext(c: Char) = c == '\t' || c == ' ' || c.code == 0x21 || c.code in 0x23..0x5B || c.code in 0x5D..0x7E || isObsText(c)

/** What may follow a backslash in a quoted-pair (RFC 9110 section 5.6.4). */
private fun isQuotedPairChar(c: Char) = c == '\t' || c == ' ' || c.code in 0x21..0x7E || isObsText(c)
