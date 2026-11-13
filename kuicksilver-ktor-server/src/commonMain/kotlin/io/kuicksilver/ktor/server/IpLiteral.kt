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
 * The key of a client address for the per-address tables of the TCP accept loop (`maxTcpConnectionsPerIp`,
 * [TcpLimits]; `http2RepeatOffenderPenalty`, [RepeatOffenders]): its bytes ([peerAddressBytes], never a name lookup), an
 * IPv4-mapped IPv6 address (RFC 4291 section 2.5.5.2, as a dual-stack listener reports IPv4 peers) as its IPv4 address,
 * and an IPv6 address by its first [ipv6PrefixBytes] bytes (all 16 by default). Null when the address is not known.
 */
internal fun peerIpKey(
    remote: InetSocketAddress?,
    ipv6PrefixBytes: Int = 16,
): String? = remote?.let { peerAddressBytes(it) }?.let { ipKey(it, ipv6PrefixBytes) }

/** [peerIpKey] of address bytes (4 or 16). */
internal fun ipKey(
    bytes: ByteArray,
    ipv6PrefixBytes: Int = 16,
): String {
    val ip = unmappedIp(bytes)
    val n = if (ip.size == 16) ipv6PrefixBytes else ip.size
    val sb = StringBuilder(n * 2 + 3)
    sb.append(ip.size).append(':')
    for (i in 0 until n) {
        val b = ip[i].toInt() and 0xff
        sb.append(HEX[b shr 4]).append(HEX[b and 0xf])
    }
    return sb.toString()
}

/**
 * Address bytes (4 or 16) as a log line names them, never a name: a.b.c.d (IPv4-mapped ones included), or the IPv6 groups,
 * all eight, or with [ipv6PrefixBytes] below 16 the prefix as `2001:db8::/56`.
 */
internal fun describeIp(
    bytes: ByteArray,
    ipv6PrefixBytes: Int = 16,
): String {
    val ip = unmappedIp(bytes)
    if (ip.size != 16) return ip.joinToString(".") { (it.toInt() and 0xff).toString() }
    val prefix = ip.copyOf(ipv6PrefixBytes) + ByteArray(16 - ipv6PrefixBytes)
    val groups = (0 until 8).map { ((prefix[2 * it].toInt() and 0xff) shl 8) or (prefix[2 * it + 1].toInt() and 0xff) }
    if (ipv6PrefixBytes >= 16) return groups.joinToString(":") { it.toString(16) }
    return groups.take((ipv6PrefixBytes + 1) / 2).dropLastWhile { it == 0 }.joinToString(":") { it.toString(16) } +
        "::/${ipv6PrefixBytes * 8}"
}

/** `::ffff:a.b.c.d` (RFC 4291 section 2.5.5.2) as the 4 bytes of a.b.c.d; anything else as it is. */
internal fun unmappedIp(bytes: ByteArray): ByteArray {
    if (bytes.size != 16) return bytes
    for (i in 0 until 10) if (bytes[i].toInt() != 0) return bytes
    if (bytes[10].toInt() != -1 || bytes[11].toInt() != -1) return bytes
    return bytes.copyOfRange(12, 16)
}

private const val HEX = "0123456789abcdef"

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

/**
 * A connection's IP literal as the host of a URI (`serverHost` without a Host field or `:authority`): an IPv6 address in
 * brackets (RFC 3986 section 3.2.2 `IP-literal`, the `uri-host` of RFC 9110 section 7.2), its zone ID as `%25zone` (RFC
 * 6874 section 2); an IPv4 address or a name as it is.
 */
internal fun uriHost(literal: String): String =
    if (':' in literal && !literal.startsWith("[")) "[" + literal.replace("%", "%25") + "]" else literal
