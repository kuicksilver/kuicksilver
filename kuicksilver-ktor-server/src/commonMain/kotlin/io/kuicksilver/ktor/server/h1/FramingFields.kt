// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

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

/**
 * Whether [value] is a valid Host field value, `uri-host [ ":" port ]` (RFC 9110 section 7.2), with `uri-host` the `host`
 * of RFC 3986 section 3.2.2: an IP-literal (`[` IPv6address or IPvFuture `]`), or a reg-name (unreserved, pct-encoded
 * and sub-delims characters, which covers IPv4 addresses), possibly empty (RFC 9112 section 3.2: an empty Host for a
 * target without an authority), and `port = *DIGIT` (section 3.2.3): any digits, or none after the colon (the default
 * port).
 */
internal fun isValidHostField(value: String): Boolean {
    val hostEnd: Int
    if (value.startsWith("[")) {
        val close = value.indexOf(']')
        if (close < 0 || !isIpLiteralBody(value.substring(1, close))) return false
        hostEnd = close + 1
    } else {
        hostEnd = value.indexOf(':').let { if (it < 0) value.length else it }
        if (!isRegName(value.substring(0, hostEnd))) return false
    }
    if (hostEnd == value.length) return true
    if (value[hostEnd] != ':') return false
    return value.substring(hostEnd + 1).all { it in '0'..'9' }
}

/** reg-name = *( unreserved / pct-encoded / sub-delims ) (RFC 3986 section 3.2.2). */
private fun isRegName(s: String): Boolean {
    var i = 0
    while (i < s.length) {
        val c = s[i]
        if (c == '%') {
            if (i + 2 >= s.length || !isHexDigit(s[i + 1]) || !isHexDigit(s[i + 2])) return false
            i += 3
            continue
        }
        if (!isUnreserved(c) && !isSubDelim(c)) return false
        i++
    }
    return true
}

/** IPv6address / IPvFuture, the inside of an IP-literal (RFC 3986 section 3.2.2; no zone identifier). */
private fun isIpLiteralBody(s: String): Boolean {
    if (s.startsWith("v") || s.startsWith("V")) {
        // IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
        val dot = s.indexOf('.')
        if (dot < 2 || dot == s.length - 1) return false
        if (!s.substring(1, dot).all(::isHexDigit)) return false
        return s.substring(dot + 1).all { isUnreserved(it) || isSubDelim(it) || it == ':' }
    }
    return isIpv6(s)
}

/** IPv6address (RFC 3986 section 3.2.2): eight 16-bit pieces, `::` once for a run of zero pieces, an IPv4 tail allowed. */
private fun isIpv6(s: String): Boolean {
    val doubleColon = s.indexOf("::")
    if (doubleColon >= 0 && s.indexOf("::", doubleColon + 1) >= 0) return false
    val parts =
        if (doubleColon < 0) {
            listOf(s)
        } else {
            listOf(s.substring(0, doubleColon), s.substring(doubleColon + 2))
        }
    var pieces = 0
    for ((index, part) in parts.withIndex()) {
        if (part.isEmpty()) continue
        val groups = part.split(':')
        for ((g, group) in groups.withIndex()) {
            val last = index == parts.size - 1 && g == groups.size - 1
            if (last && '.' in group) {
                if (!isIpv4(group)) return false
                pieces += 2
            } else {
                if (group.isEmpty() || group.length > 4 || !group.all(::isHexDigit)) return false
                pieces++
            }
        }
    }
    return if (doubleColon < 0) pieces == 8 else pieces <= 7
}

/** IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet (RFC 3986 section 3.2.2). */
private fun isIpv4(s: String): Boolean {
    val octets = s.split('.')
    return octets.size == 4 &&
        octets.all { o ->
            o.isNotEmpty() && o.length <= 3 && o.all { it in '0'..'9' } && (o.length == 1 || o[0] != '0') && o.toInt() <= 255
        }
}

private fun isHexDigit(c: Char) = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'

/** unreserved (RFC 3986 section 2.3). */
private fun isUnreserved(c: Char) = c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c in "-._~"

/** sub-delims (RFC 3986 section 2.2). */
private fun isSubDelim(c: Char) = c in "!$&'()*+,;="

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
