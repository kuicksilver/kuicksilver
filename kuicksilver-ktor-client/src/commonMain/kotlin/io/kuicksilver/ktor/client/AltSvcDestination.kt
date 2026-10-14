// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

/**
 * Where an Alt-Svc alternative may send the client's QUIC Initials (RFC 9000 section 21.5, RFC 7838 section 9; threat model
 * 3.14). A verified origin could otherwise aim every client at their own loopback, link-local or private network, as the
 * server-side migration rule refuses for paths (threat model 3.5): such an alternative is kept only when the origin itself is
 * on such an address. Unspecified, multicast and broadcast addresses are never a destination. Only IP literals (and the
 * `localhost` names of RFC 6761) are classified; a DNS name is not resolved here (threat model 3.14, residue).
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
        ipv4(h)?.let { return classifyV4(it) }
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
