// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress

/**
 * The address bytes of an accepted peer (4 or 16), never through a name lookup: on the JVM and Android the address the
 * socket already holds; on Kotlin/Native its numeric text ([parseIpLiteral]), since `resolveAddress` there calls
 * getaddrinfo on every accept.
 */
internal expect fun peerAddressBytes(remote: InetSocketAddress): ByteArray?

/**
 * The bytes of a numeric IPv4 (dotted quad) or IPv6 address (RFC 4291 section 2.2 text, `::` and a trailing dotted quad
 * included; brackets and a `%zone` are ignored), or null for anything else (a name is never looked up).
 */
internal fun parseIpLiteral(text: String): ByteArray? {
    var s = text
    if (s.startsWith("[") && s.endsWith("]")) s = s.substring(1, s.length - 1)
    s = s.substringBefore('%')
    if (s.isEmpty()) return null
    if (':' !in s) return parseIpv4(s)
    val halves = s.split("::")
    if (halves.size > 2) return null

    fun groups(
        part: String,
        last: Boolean,
    ): List<Int>? {
        if (part.isEmpty()) return emptyList()
        val out = ArrayList<Int>()
        val items = part.split(':')
        for ((i, g) in items.withIndex()) {
            if ('.' in g) {
                // a dotted quad only as the last 32 bits of the whole address (RFC 4291 section 2.2, form 3)
                if (!last || i != items.lastIndex) return null
                val v4 = parseIpv4(g) ?: return null
                out += ((v4[0].toInt() and 0xff) shl 8) or (v4[1].toInt() and 0xff)
                out += ((v4[2].toInt() and 0xff) shl 8) or (v4[3].toInt() and 0xff)
                continue
            }
            if (g.isEmpty() || g.length > 4 || !g.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
            out += g.toInt(16)
        }
        return out
    }
    val head = groups(halves[0], last = halves.size == 1) ?: return null
    val tail = if (halves.size == 2) groups(halves[1], last = true) ?: return null else emptyList()
    val all =
        if (halves.size == 2) {
            if (head.size + tail.size > 7) return null
            head + List(8 - head.size - tail.size) { 0 } + tail
        } else {
            head
        }
    if (all.size != 8) return null
    return ByteArray(16) { i -> (if (i % 2 == 0) all[i / 2] shr 8 else all[i / 2]).toByte() }
}

private fun parseIpv4(s: String): ByteArray? {
    val parts = s.split('.')
    if (parts.size != 4) return null
    val out = ByteArray(4)
    for ((i, p) in parts.withIndex()) {
        if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' }) return null
        val v = p.toInt()
        if (v > 255) return null
        out[i] = v.toByte()
    }
    return out
}
