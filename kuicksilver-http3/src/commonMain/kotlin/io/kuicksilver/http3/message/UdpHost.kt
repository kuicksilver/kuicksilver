// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.message

/**
 * A `target_host` of CONNECT-UDP (RFC 9298 section 3): "IPv6address / IPv4address / reg-name" of RFC 3986 section 3.2.2,
 * without brackets and without an IPv6 zone ("IPv6 scoped addressing zone identifiers are not supported"). A reg-name is
 * accepted only as a DNS host name (letters, digits, `-` and `_` in labels of 1 to 63, 253 bytes in all, an optional
 * final dot, a last label that is not all digits): the proxy must resolve it (section 3.1), and a name a resolver could
 * read as a number in another form (`127.1`, `0x7f.1`) never reaches one.
 */
internal sealed class UdpHost {
    /** The host as text: dotted decimal, RFC 5952 for IPv6 (IPv4-mapped in mixed notation), the name as given. */
    abstract val text: String

    class Ipv4(
        val bytes: ByteArray,
    ) : UdpHost() {
        override val text: String get() = bytes.joinToString(".") { (it.toInt() and 0xff).toString() }

        override fun toString(): String = text
    }

    class Ipv6(
        val bytes: ByteArray,
    ) : UdpHost() {
        override val text: String get() = ipv6Text(bytes)

        override fun toString(): String = text
    }

    class Name(
        val name: String,
    ) : UdpHost() {
        override val text: String get() = name

        override fun toString(): String = name
    }

    companion object {
        /** Longest DNS name in its text form without the final dot (RFC 1035 section 2.3.4). */
        private const val MAX_NAME = 253
        private const val MAX_LABEL = 63

        /** [s] as a target host, or null when it is none of the three forms. Never a resolver call. */
        fun parse(s: String): UdpHost? {
            if (s.isEmpty()) return null
            parseIpv4(s)?.let { return Ipv4(it) }
            if (':' in s) return parseIpv6(s)?.let { Ipv6(it) }
            return if (isDnsName(s)) Name(s) else null
        }

        /** RFC 3986 IPv4address: four dec-octets, without leading zeros. */
        fun parseIpv4(s: String): ByteArray? {
            val parts = s.split('.')
            if (parts.size != 4) return null
            val out = ByteArray(4)
            for ((i, p) in parts.withIndex()) {
                if (p.isEmpty() || p.length > 3 || p.any { it !in '0'..'9' }) return null
                if (p.length > 1 && p[0] == '0') return null
                val v = p.toInt()
                if (v > 255) return null
                out[i] = v.toByte()
            }
            return out
        }

        /** RFC 3986 IPv6address (with an IPv4address as its last 32 bits allowed), no zone, no brackets. */
        fun parseIpv6(s: String): ByteArray? {
            if (s.length > 45) return null
            val dc = s.indexOf("::")
            if (dc >= 0 && s.indexOf("::", dc + 1) >= 0) return null
            val head = if (dc >= 0) s.substring(0, dc) else s
            val tail = if (dc >= 0) s.substring(dc + 2) else ""
            val left = groups(head, allowV4 = dc < 0) ?: return null
            val right = if (dc >= 0) groups(tail, allowV4 = true) ?: return null else IntArray(0)
            val total = left.size + right.size
            if (dc < 0 && total != 8) return null
            if (dc >= 0 && total > 7) return null
            val words = IntArray(8)
            left.copyInto(words, 0)
            right.copyInto(words, 8 - right.size)
            val out = ByteArray(16)
            for (i in 0 until 8) {
                out[2 * i] = (words[i] shr 8).toByte()
                out[2 * i + 1] = words[i].toByte()
            }
            return out
        }

        /** The 16-bit groups of one side of `::` (empty for an empty side); an IPv4 tail counts as two groups. */
        private fun groups(
            s: String,
            allowV4: Boolean,
        ): IntArray? {
            if (s.isEmpty()) return IntArray(0)
            val parts = s.split(':')
            val out = ArrayList<Int>(8)
            for ((i, p) in parts.withIndex()) {
                if (i == parts.lastIndex && allowV4 && '.' in p) {
                    val v4 = parseIpv4(p) ?: return null
                    out += ((v4[0].toInt() and 0xff) shl 8) or (v4[1].toInt() and 0xff)
                    out += ((v4[2].toInt() and 0xff) shl 8) or (v4[3].toInt() and 0xff)
                    continue
                }
                if (p.isEmpty() || p.length > 4) return null
                var v = 0
                for (c in p) v = (v shl 4) or (hexValue(c).takeIf { it >= 0 } ?: return null)
                out += v
            }
            return out.toIntArray()
        }

        /** A DNS host name as described on [UdpHost]. */
        fun isDnsName(s: String): Boolean {
            val name = if (s.endsWith('.')) s.dropLast(1) else s
            if (name.isEmpty() || name.length > MAX_NAME) return false
            val labels = name.split('.')
            for (l in labels) {
                if (l.isEmpty() || l.length > MAX_LABEL) return false
                if (l.first() == '-' || l.last() == '-') return false
                if (!l.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' || it == '_' }) return false
            }
            // RFC 3696 section 2: a top-level label is never all digits, so such a name is a mistyped address
            return !labels.last().all { it in '0'..'9' }
        }

        /** RFC 5952: lower case, no leading zeros, the longest run of two or more zero groups as `::` (the first on a tie), IPv4-mapped in mixed notation. */
        fun ipv6Text(b: ByteArray): String {
            val w = IntArray(8) { ((b[2 * it].toInt() and 0xff) shl 8) or (b[2 * it + 1].toInt() and 0xff) }
            if (w[0] == 0 && w[1] == 0 && w[2] == 0 && w[3] == 0 && w[4] == 0 && w[5] == 0xffff) {
                return "::ffff:" + (12 until 16).joinToString(".") { (b[it].toInt() and 0xff).toString() }
            }
            var bestStart = -1
            var bestLen = 1
            var i = 0
            while (i < 8) {
                if (w[i] != 0) {
                    i++
                    continue
                }
                var j = i
                while (j < 8 && w[j] == 0) j++
                if (j - i > bestLen) {
                    bestStart = i
                    bestLen = j - i
                }
                i = j
            }
            if (bestStart < 0) return w.joinToString(":") { it.toString(16) }
            val left = (0 until bestStart).joinToString(":") { w[it].toString(16) }
            val right = (bestStart + bestLen until 8).joinToString(":") { w[it].toString(16) }
            return "$left::$right"
        }
    }
}

/** The value of a hex digit, or -1. */
internal fun hexValue(c: Char): Int =
    when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }
