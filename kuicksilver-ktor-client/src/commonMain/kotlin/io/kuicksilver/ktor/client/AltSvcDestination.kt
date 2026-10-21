// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

/**
 * Where an Alt-Svc alternative may send the client's QUIC Initials (RFC 9000 section 21.5, RFC 7838 section 9; threat model
 * 3.14). A verified origin could otherwise aim every client at their own loopback, link-local or private network, as the
 * server-side migration rule refuses for paths (threat model 3.5): such an alternative is kept only when the origin itself is
 * on such an address. Unspecified, multicast and broadcast addresses are never a destination. Only IP literals (and the
 * `localhost` names of RFC 6761) are classified; a DNS name is not resolved here (threat model 3.14, residue).
 *
 * An IPv4 literal is any host the resolvers take as one without DNS, the forms of `inet_aton`: one to four parts, the
 * last filling the remaining bytes (`127.1`, `10.0.1`, `2130706433`). A part in octal or hex (`0177`, `0x7f`) names a
 * different address on different platforms (inet_aton reads it as octal or hex, the JVM as decimal or not at all), and
 * a numeric host that is no address (`256.1.1.1`) is no DNS name either (RFC 1123 section 2.1): both are [Class.Never].
 */
internal object AltSvcDestination {
    enum class Class { Public, Local, Never }

    /** True when an alternative on [altHost] (null: the origin's own host) may be used for an origin on [originHost]. */
    fun allowed(
        originHost: String,
        altHost: String?,
    ): Boolean {
        if (altHost == null) return true
        return when (classify(altHost)) {
            Class.Public -> true
            Class.Never -> false
            Class.Local -> classify(originHost) == Class.Local
        }
    }

    fun classify(host: String): Class {
        val h =
            host
                .removePrefix("[")
                .removeSuffix("]")
                .lowercase()
                .removeSuffix(".")
        if (h == "localhost" || h.endsWith(".localhost")) return Class.Local
        if (numericV4(h)) return inetAton(h)?.let(::classifyV4) ?: Class.Never
        val v6 = ipv6(h.substringBefore('%')) ?: return Class.Public // a DNS name
        return classifyV6(v6)
    }

    private fun classifyV4(b: IntArray): Class {
        val (a, b1) = b[0] to b[1]
        return when {
            a == 0 || a >= 224 -> Class.Never

            // "this network", multicast, reserved, broadcast
            a == 127 || a == 10 -> Class.Local

            // loopback, RFC 1918
            a == 169 && b1 == 254 -> Class.Local

            // link-local
            a == 172 && b1 in 16..31 -> Class.Local

            // RFC 1918
            a == 192 && b1 == 168 -> Class.Local

            // RFC 1918
            a == 100 && b1 in 64..127 -> Class.Local

            // RFC 6598 shared address space (carrier-grade NAT)
            else -> Class.Public
        }
    }

    private fun classifyV6(b: IntArray): Class {
        val mapped = (0 until 10).all { b[it] == 0 } && b[10] == 0xff && b[11] == 0xff
        if (mapped) return classifyV4(intArrayOf(b[12], b[13], b[14], b[15]))
        return when {
            b.all { it == 0 } -> Class.Never

            // unspecified
            b[0] == 0xff -> Class.Never

            // multicast
            (0 until 15).all { b[it] == 0 } && b[15] == 1 -> Class.Local

            // loopback
            b[0] == 0xfe && b[1] and 0xc0 == 0x80 -> Class.Local

            // link-local fe80::/10
            b[0] and 0xfe == 0xfc -> Class.Local

            // unique local fc00::/7
            else -> Class.Public
        }
    }

    /**
     * Whether [s] has the shape of an inet_aton IPv4 literal: dot-separated parts of digits, or `0x` and hex digits. An
     * empty part (`1..2`) keeps that shape, as no DNS name has an empty label; [inetAton] then refuses it.
     */
    private fun numericV4(s: String): Boolean =
        s.any { it in '0'..'9' } &&
            s.split('.').all { p ->
                if (p.startsWith("0x")) {
                    p.drop(2).all { it in '0'..'9' || it in 'a'..'f' }
                } else {
                    p.all { it in '0'..'9' }
                }
            }

    /**
     * The four octets of an IPv4 literal in a form every platform reads alike: inet_aton's one to four decimal parts,
     * the last filling the remaining bytes (`a`, `a.b` with b < 2^24, `a.b.c` with c < 2^16, `a.b.c.d`). Null for a part
     * with a leading zero or `0x` (octal or hex to inet_aton, decimal or refused by the JVM) and for values out of range.
     */
    private fun inetAton(s: String): IntArray? {
        val parts = s.split('.')
        if (parts.size > 4) return null
        val values = LongArray(parts.size)
        for ((i, p) in parts.withIndex()) {
            if (p.isEmpty() || (p.length > 1 && p[0] == '0')) return null // empty, octal, or 0x hex
            if (p.length > 10) return null
            values[i] = p.toLong()
        }
        val lastBits = 8 * (5 - parts.size)
        for (i in 0 until parts.lastIndex) if (values[i] > 255) return null
        if (values.last() >= (1L shl lastBits)) return null
        var address = values.last()
        for (i in 0 until parts.lastIndex) address = address or (values[i] shl (24 - 8 * i))
        return IntArray(4) { ((address shr (24 - 8 * it)) and 0xff).toInt() }
    }

    /** The four octets of a dotted-quad IPv4 literal, or null. */
    private fun ipv4(s: String): IntArray? {
        val p = s.split('.')
        if (p.size != 4) return null
        val out = IntArray(4)
        for (i in 0 until 4) {
            val q = p[i]
            if (q.isEmpty() || q.length > 3 || !q.all { it in '0'..'9' }) return null
            out[i] = q.toInt().takeIf { it <= 255 } ?: return null
        }
        return out
    }

    /** The 16 bytes of an IPv6 literal (with `::` and a trailing dotted quad allowed), or null. */
    private fun ipv6(s: String): IntArray? {
        if (!s.contains(':')) return null
        val halves = s.split("::")
        if (halves.size > 2) return null
        val head = groups(halves[0]) ?: return null
        val tail = if (halves.size == 2) groups(halves[1]) ?: return null else emptyList()
        val n = head.size + tail.size
        if (halves.size == 1 && n != 16) return null
        if (halves.size == 2 && n > 14) return null
        val out = IntArray(16)
        head.forEachIndexed { i, v -> out[i] = v }
        tail.forEachIndexed { i, v -> out[16 - tail.size + i] = v }
        return out
    }

    /** Bytes of colon-separated 16-bit groups, the last of which may be a dotted quad; null when malformed. */
    private fun groups(part: String): List<Int>? {
        if (part.isEmpty()) return emptyList()
        val out = ArrayList<Int>()
        val items = part.split(':')
        for ((i, g) in items.withIndex()) {
            if (i == items.lastIndex && g.contains('.')) {
                val v4 = ipv4(g) ?: return null
                v4.forEach { out += it }
                continue
            }
            if (g.isEmpty() || g.length > 4 || !g.all { it in '0'..'9' || it in 'a'..'f' }) return null
            val v = g.toInt(16)
            out += v shr 8
            out += v and 0xff
        }
        return out
    }
}
