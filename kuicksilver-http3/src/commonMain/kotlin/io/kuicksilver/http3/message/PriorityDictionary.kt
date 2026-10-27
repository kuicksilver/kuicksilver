// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.message

import io.kuicksilver.http3.Http3Headers

/**
 * The value of the `priority` field lines in [this], combined into one field value as RFC 8941 section 4.2 asks
 * (joined with ", ", RFC 9110 section 5.3); null when there is none.
 */
internal fun Http3Headers.priorityFieldValue(): String? {
    var first: String? = null
    var combined: StringBuilder? = null
    for ((n, v) in fields) {
        if (n != "priority") continue
        if (first == null) {
            first = v
            continue
        }
        val b = combined ?: StringBuilder(first).also { combined = it }
        b.append(", ").append(v)
    }
    return combined?.toString() ?: first
}

/**
 * A strict RFC 8941 Dictionary parser (section 4.2.2, with Inner Lists 4.2.1.2, Items 4.2.3, Parameters 4.2.3.2, Keys
 * 4.2.3.3 and the bare items of sections 4.2.4 to 4.2.8) that keeps only what RFC 9218 section 4 reads: the last `u`
 * and `i` members (a later member of the same key overwrites an earlier one). Every other member, and all parameters,
 * must still be valid. One allocation per field, no regex.
 */
internal class PriorityDictionary private constructor(
    private val s: String,
) {
    private var pos = 0

    /** The urgency of the last `u` member, or -1 when there is none or it is not an Integer in 0..7 (RFC 9218 section 4.1). */
    var urgency: Int = -1
        private set

    /** 1 or 0 for the last `i` member, or -1 when there is none or it is not a Boolean (RFC 9218 section 4.2). */
    var incremental: Int = -1
        private set

    /** The type of the item (or Inner List) parsed last, one of the `KIND_*` constants. */
    private var kind = KIND_OTHER

    /** The value of the Integer or Boolean (1 or 0) parsed last. */
    private var value = 0L

    /** RFC 8941 section 4.2.2, after section 4.2's leading SP; trailing OWS is consumed by the member loop. */
    private fun dictionary(): Boolean {
        skipSp()
        val n = s.length
        while (pos < n) {
            val keyStart = pos
            if (!key()) return false
            val keyLength = pos - keyStart
            if (pos < n && s[pos] == '=') {
                pos++
                if (!itemOrInnerList()) return false
            } else {
                if (!parameters()) return false
                kind = KIND_BOOLEAN
                value = 1
            }
            if (keyLength == 1) {
                when (s[keyStart]) {
                    'u' -> urgency = if (kind == KIND_INTEGER && value in 0L..7L) value.toInt() else -1
                    'i' -> incremental = if (kind == KIND_BOOLEAN) value.toInt() else -1
                }
            }
            skipOws()
            if (pos == n) return true
            if (s[pos] != ',') return false
            pos++
            skipOws()
            if (pos == n) return false // a trailing comma
        }
        return true
    }

    /** RFC 8941 section 4.2.1.1. */
    private fun itemOrInnerList(): Boolean = if (pos < s.length && s[pos] == '(') innerList() else item()

    /** RFC 8941 section 4.2.1.2. */
    private fun innerList(): Boolean {
        pos++
        while (true) {
            skipSp()
            if (pos >= s.length) return false
            if (s[pos] == ')') {
                pos++
                if (!parameters()) return false
                kind = KIND_INNER_LIST
                return true
            }
            if (!item()) return false
            if (pos >= s.length) return false
            val c = s[pos]
            if (c != ' ' && c != ')') return false
        }
    }

    /** RFC 8941 section 4.2.3: a bare item and its parameters; [kind] and [value] describe the bare item. */
    private fun item(): Boolean {
        if (!bareItem()) return false
        val k = kind
        val v = value
        if (!parameters()) return false
        kind = k
        value = v
        return true
    }

    /** RFC 8941 section 4.2.3.1. */
    private fun bareItem(): Boolean {
        if (pos >= s.length) return false
        val c = s[pos]
        return when {
            c == '-' || c in '0'..'9' -> number()
            c == '"' -> string()
            c in 'a'..'z' || c in 'A'..'Z' || c == '*' -> token()
            c == ':' -> byteSequence()
            c == '?' -> boolean()
            else -> false
        }
    }

    /** RFC 8941 section 4.2.3.2. */
    private fun parameters(): Boolean {
        while (pos < s.length && s[pos] == ';') {
            pos++
            skipSp()
            if (!key()) return false
            if (pos < s.length && s[pos] == '=') {
                pos++
                if (!bareItem()) return false
            }
        }
        return true
    }

    /** RFC 8941 section 4.2.3.3. */
    private fun key(): Boolean {
        if (pos >= s.length) return false
        val c = s[pos]
        if (c !in 'a'..'z' && c != '*') return false
        pos++
        while (pos < s.length) {
            val k = s[pos]
            if (k !in 'a'..'z' && k !in '0'..'9' && k != '_' && k != '-' && k != '.' && k != '*') break
            pos++
        }
        return true
    }

    /** RFC 8941 section 4.2.4: at most 15 integer digits, or a Decimal of at most 12 integer and 1 to 3 fraction digits. */
    private fun number(): Boolean {
        var negative = false
        if (s[pos] == '-') {
            negative = true
            pos++
        }
        if (pos >= s.length || s[pos] !in '0'..'9') return false
        var integerDigits = 0
        var fractionDigits = 0
        var decimal = false
        var v = 0L
        while (pos < s.length) {
            val c = s[pos]
            if (c in '0'..'9') {
                if (decimal) {
                    if (++fractionDigits > 3) return false
                } else {
                    if (++integerDigits > 15) return false
                    v = v * 10 + (c - '0')
                }
            } else if (c == '.' && !decimal) {
                if (integerDigits > 12) return false
                decimal = true
            } else {
                break
            }
            pos++
        }
        if (decimal) {
            if (fractionDigits == 0) return false
            kind = KIND_OTHER
        } else {
            kind = KIND_INTEGER
            value = if (negative) -v else v
        }
        return true
    }

    /** RFC 8941 section 4.2.5: printable ASCII, with `\` escaping only `"` and `\`. */
    private fun string(): Boolean {
        pos++
        while (pos < s.length) {
            val c = s[pos++]
            when {
                c == '\\' -> {
                    if (pos >= s.length) return false
                    val e = s[pos++]
                    if (e != '"' && e != '\\') return false
                }

                c == '"' -> {
                    kind = KIND_OTHER
                    return true
                }

                c < ' ' || c > '~' -> {
                    return false
                }
            }
        }
        return false
    }

    /** RFC 8941 section 4.2.6: ALPHA or `*`, then tchar, `:` or `/` ([bareItem] checked the first character). */
    private fun token(): Boolean {
        pos++
        while (pos < s.length) {
            val c = s[pos]
            if (c !in 'a'..'z' && c !in 'A'..'Z' && c !in '0'..'9' && c !in TOKEN_SYMBOLS) break
            pos++
        }
        kind = KIND_OTHER
        return true
    }

    /**
     * RFC 8941 section 4.2.7: base64 between colons. Its decoding fails on `=` before the data ends, more than two `=`,
     * a length of 1 modulo 4, or `=` padding that does not complete a quantum; missing padding is accepted, as the
     * section asks.
     */
    private fun byteSequence(): Boolean {
        pos++
        var data = 0
        var padding = 0
        while (pos < s.length) {
            val c = s[pos++]
            when {
                c == ':' -> {
                    if (data % 4 == 1 || (padding > 0 && (data + padding) % 4 != 0)) return false
                    kind = KIND_OTHER
                    return true
                }

                c == '=' -> {
                    if (++padding > 2) return false
                }

                c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '+' || c == '/' -> {
                    if (padding > 0) return false
                    data++
                }

                else -> {
                    return false
                }
            }
        }
        return false
    }

    /** RFC 8941 section 4.2.8: `?0` or `?1`. */
    private fun boolean(): Boolean {
        pos++
        if (pos >= s.length) return false
        value =
            when (s[pos]) {
                '1' -> 1
                '0' -> 0
                else -> return false
            }
        pos++
        kind = KIND_BOOLEAN
        return true
    }

    private fun skipSp() {
        while (pos < s.length && s[pos] == ' ') pos++
    }

    private fun skipOws() {
        while (pos < s.length && (s[pos] == ' ' || s[pos] == '\t')) pos++
    }

    companion object {
        private const val KIND_OTHER = 0
        private const val KIND_INTEGER = 1
        private const val KIND_BOOLEAN = 2
        private const val KIND_INNER_LIST = 3

        /** tchar (RFC 9110 section 5.6.2) symbols plus `:` and `/`. */
        private const val TOKEN_SYMBOLS = "!#$%&'*+-.^_`|~:/"

        /** The dictionary in [value], or null when it is not a valid one (RFC 8941 section 4.2: the field is then ignored). */
        fun parse(value: String): PriorityDictionary? {
            val d = PriorityDictionary(value)
            return if (d.dictionary()) d else null
        }
    }
}
