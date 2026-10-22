// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

/**
 * The application protocol fields of a WebTransport session (draft-ietf-webtrans-http3-16 section 3.3):
 * `WT-Available-Protocols`, a Structured Field List of Strings the client offers, and `WT-Protocol`, the String the
 * server chose (RFC 9651 sections 3.1, 3.3.3). Parameters on the members are allowed and ignored.
 */
internal object WtProtocols {
    const val AVAILABLE_FIELD: String = "wt-available-protocols"
    const val SELECTED_FIELD: String = "wt-protocol"

    /** What a Structured Field String can carry: printable ASCII (RFC 9651 section 3.3.3). */
    fun isValid(protocol: String): Boolean = protocol.isNotEmpty() && protocol.all { it.code in 0x20..0x7e }

    fun quote(s: String): String = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

    fun formatList(protocols: List<String>): String = protocols.joinToString(", ") { quote(it) }

    /** The Strings of a List field value, or null when it is malformed or has a member that is no String. */
    fun parseList(value: String): List<String>? {
        val out = ArrayList<String>()
        var i = skipSpaces(value, 0)
        if (i == value.length) return out
        while (true) {
            val (s, end) = parseString(value, i) ?: return null
            out += s
            i = skipParameters(value, end) ?: return null
            i = skipSpaces(value, i)
            if (i == value.length) return out
            if (value[i] != ',') return null
            i = skipSpaces(value, i + 1)
            if (i == value.length) return null // a trailing comma
        }
    }

    /** The String of an Item field value, or null when it is malformed or no String. */
    fun parseItem(value: String): String? {
        val start = skipSpaces(value, 0)
        val (s, end) = parseString(value, start) ?: return null
        val after = skipParameters(value, end) ?: return null
        return if (skipSpaces(value, after) == value.length) s else null
    }

    private fun skipSpaces(
        v: String,
        from: Int,
    ): Int {
        var i = from
        while (i < v.length && (v[i] == ' ' || v[i] == '\t')) i++
        return i
    }

    /** `"..."` at [from]: the unescaped text and the index after the closing quote. */
    private fun parseString(
        v: String,
        from: Int,
    ): Pair<String, Int>? {
        if (from >= v.length || v[from] != '"') return null
        val sb = StringBuilder()
        var i = from + 1
        while (i < v.length) {
            val c = v[i]
            when {
                c == '\\' -> {
                    val n = v.getOrNull(i + 1) ?: return null
                    if (n != '"' && n != '\\') return null
                    sb.append(n)
                    i += 2
                }

                c == '"' -> {
                    return sb.toString() to i + 1
                }

                c.code !in 0x20..0x7e -> {
                    return null
                }

                else -> {
                    sb.append(c)
                    i++
                }
            }
        }
        return null
    }

    /** `;key` or `;key=value` parameters after an item; values are tokens, numbers, booleans or Strings. */
    private fun skipParameters(
        v: String,
        from: Int,
    ): Int? {
        var i = from
        while (i < v.length && v[i] == ';') {
            i = skipSpaces(v, i + 1)
            val keyStart = i
            while (i < v.length && (v[i].isLowerCase() || v[i].isDigit() || v[i] in "_-.*")) i++
            if (i == keyStart) return null
            if (i < v.length && v[i] == '=') {
                i++
                if (i < v.length && v[i] == '"') {
                    i = parseString(v, i)?.second ?: return null
                } else {
                    val valueStart = i
                    while (i < v.length && v[i] != ';' && v[i] != ',' && v[i] != ' ' && v[i] != '\t') i++
                    if (i == valueStart) return null
                }
            }
        }
        return i
    }
}
