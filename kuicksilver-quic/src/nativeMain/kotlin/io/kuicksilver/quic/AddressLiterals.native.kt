// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress

internal actual fun InetSocketAddress.ipBytesNoDns(): ByteArray? = parseIpLiteral(hostname)

/** The bytes of an IPv4 dotted quad or an IPv6 literal (RFC 4291 section 2.2, optionally bracketed, a zone ID ignored); null for anything else. */
internal fun parseIpLiteral(text: String): ByteArray? {
    var s = text
    if (s.length >= 2 && s[0] == '[' && s[s.length - 1] == ']') s = s.substring(1, s.length - 1)
    val zone = s.indexOf('%')
    if (zone >= 0) s = s.substring(0, zone)
    return if (s.indexOf(':') < 0) parseIpv4(s) else parseIpv6(s)
}

private fun parseIpv4(s: String): ByteArray? {
    val out = ByteArray(4)
    var part = 0
    var value = -1
    var digits = 0
    for (ch in s) {
        if (ch == '.') {
            if (value < 0 || part == 3) return null
            out[part++] = value.toByte()
            value = -1
            digits = 0
        } else if (ch in '0'..'9') {
            if (++digits > 3) return null
            value = (if (value < 0) 0 else value * 10) + (ch - '0')
            if (value > 255) return null
        } else {
            return null
        }
    }
    if (value < 0 || part != 3) return null
    out[3] = value.toByte()
    return out
}

private fun parseIpv6(s: String): ByteArray? {
    val gap = s.indexOf("::")
    if (gap >= 0 && s.indexOf("::", gap + 1) >= 0) return null
    val head = if (gap >= 0) s.substring(0, gap) else s
    val tail = if (gap >= 0) s.substring(gap + 2) else ""
    val left = groups(head, allowV4 = gap < 0) ?: return null
    val right = if (gap >= 0) groups(tail, allowV4 = true) ?: return null else ArrayList()
    val total = left.size + right.size
    if (gap < 0 && total != 16 || gap >= 0 && total > 14) return null
    val out = ByteArray(16)
    for (i in left.indices) out[i] = left[i]
    for (i in right.indices) out[16 - right.size + i] = right[i]
    return out
}

/** Colon-separated hex groups as bytes (an IPv4 tail as 4 bytes when [allowV4]); empty text is no groups; null when malformed. */
private fun groups(
    s: String,
    allowV4: Boolean,
): ArrayList<Byte>? {
    val out = ArrayList<Byte>(16)
    if (s.isEmpty()) return out
    val parts = s.split(':')
    for ((i, p) in parts.withIndex()) {
        if (allowV4 && i == parts.size - 1 && p.indexOf('.') >= 0) {
            val v4 = parseIpv4(p) ?: return null
            for (b in v4) out += b
            continue
        }
        if (p.isEmpty() || p.length > 4) return null
        var v = 0
        for (ch in p) {
            val d = ch.digitToIntOrNull(16) ?: return null
            v = v * 16 + d
        }
        out += (v ushr 8).toByte()
        out += v.toByte()
    }
    return out
}
