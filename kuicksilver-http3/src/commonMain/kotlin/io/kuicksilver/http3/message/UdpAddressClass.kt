// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.message

/**
 * Which destination addresses a UDP proxy sends to by default (RFC 9298 section 7: refuse "vulnerable targets, such as the
 * UDP proxy's own addresses and localhost, link-local, multicast, and broadcast addresses"). Only globally reachable
 * unicast passes: every block of the IANA IPv4 and IPv6 Special-Purpose Address Registries (RFC 6890) that is not
 * globally reachable, private and shared space (RFC 1918, RFC 6598), loopback, link-local, multicast, the limited
 * broadcast address and 240.0.0.0/4 are refused; for IPv6 only 2000::/3 is unicast at all. An address that carries an
 * IPv4 address (IPv4-mapped, the NAT64 prefix 64:ff9b::/96, 6to4) is judged by that IPv4 address, so a mapped loopback
 * cannot pass for public. Never a resolver call.
 */
internal object UdpAddressClass {
    /** IPv4 blocks refused: (network, prefix length). */
    private val v4Refused: List<Pair<Long, Int>> =
        listOf(
            "0.0.0.0" to 8, // "this network" (RFC 791)
            "10.0.0.0" to 8, // private (RFC 1918)
            "100.64.0.0" to 10, // shared address space (RFC 6598)
            "127.0.0.0" to 8, // loopback
            "169.254.0.0" to 16, // link-local (RFC 3927)
            "172.16.0.0" to 12, // private
            "192.0.0.0" to 24, // IETF protocol assignments (RFC 6890)
            "192.0.2.0" to 24, // TEST-NET-1 (RFC 5737)
            "192.88.99.0" to 24, // deprecated 6to4 relay anycast (RFC 7526)
            "192.168.0.0" to 16, // private
            "198.18.0.0" to 15, // benchmarking (RFC 2544)
            "198.51.100.0" to 24, // TEST-NET-2
            "203.0.113.0" to 24, // TEST-NET-3
            "224.0.0.0" to 4, // multicast
            "240.0.0.0" to 4, // reserved (RFC 1112), with 255.255.255.255, the limited broadcast address (RFC 919)
        ).map { (a, len) -> v4Value(UdpHost.parseIpv4(a)!!, 0) to len }

    /** IPv6 blocks inside 2000::/3 that are refused: (address, prefix length). */
    private val v6Refused: List<Pair<ByteArray, Int>> =
        listOf(
            "2001::" to 23, // IETF protocol assignments, Teredo among them (RFC 2928, RFC 4380)
            "2001:db8::" to 32, // documentation (RFC 3849)
            "3fff::" to 20, // documentation (RFC 9637)
        ).map { (a, len) -> UdpHost.parseIpv6(a)!! to len }

    /** Whether [address] (4 or 16 bytes) is globally reachable unicast; any other length is refused. */
    fun isPublicUnicast(address: ByteArray): Boolean =
        when (address.size) {
            4 -> isPublicV4(address, 0)
            16 -> isPublicV6(address)
            else -> false
        }

    private fun isPublicV4(
        b: ByteArray,
        off: Int,
    ): Boolean {
        val v = v4Value(b, off)
        return v4Refused.none { (net, len) -> (v ushr (32 - len)) == (net ushr (32 - len)) }
    }

    private fun isPublicV6(b: ByteArray): Boolean {
        // IPv4-mapped ::ffff:0:0/96 and the NAT64 well-known prefix 64:ff9b::/96 (RFC 6052): the IPv4 address decides
        if (hasPrefix(b, MAPPED, 96) || hasPrefix(b, NAT64, 96)) return isPublicV4(b, 12)
        // 6to4 2002::/16 (RFC 3056): the embedded IPv4 address is where the packet really goes
        if ((b[0].toInt() and 0xff) == 0x20 && (b[1].toInt() and 0xff) == 0x02) return isPublicV4(b, 2)
        // global unicast is 2000::/3 (RFC 4291 section 2.4); everything else (::, ::1, fc00::/7, fe80::/10, ff00::/8, 100::/64, 64:ff9b:1::/48, 5f00::/16) is not
        if ((b[0].toInt() and 0xe0) != 0x20) return false
        return v6Refused.none { (net, len) -> hasPrefix(b, net, len) }
    }

    private val MAPPED = UdpHost.parseIpv6("::ffff:0:0")!!
    private val NAT64 = UdpHost.parseIpv6("64:ff9b::")!!

    /** Whether the first [len] bits of [a] are those of [prefix]. */
    fun hasPrefix(
        a: ByteArray,
        prefix: ByteArray,
        len: Int,
    ): Boolean {
        if (a.size != prefix.size || len > a.size * 8) return false
        val full = len / 8
        for (i in 0 until full) if (a[i] != prefix[i]) return false
        val rest = len % 8
        if (rest == 0) return true
        val mask = (0xff shl (8 - rest)) and 0xff
        return (a[full].toInt() and mask) == (prefix[full].toInt() and mask)
    }

    private fun v4Value(
        b: ByteArray,
        off: Int,
    ): Long =
        ((b[off].toLong() and 0xff) shl 24) or ((b[off + 1].toLong() and 0xff) shl 16) or
            ((b[off + 2].toLong() and 0xff) shl 8) or (b[off + 3].toLong() and 0xff)

    /**
     * An address prefix in CIDR notation (`192.0.2.0/24`, `2001:db8::/32`; an address alone is a single host) as its
     * bytes and length; IllegalArgumentException when it is none, or has bits set beyond its length.
     */
    fun parsePrefix(cidr: String): Pair<ByteArray, Int> {
        val slash = cidr.indexOf('/')
        val addr = if (slash < 0) cidr else cidr.substring(0, slash)
        val bytes =
            UdpHost.parseIpv4(addr) ?: UdpHost.parseIpv6(addr)
                ?: throw IllegalArgumentException("not an IP address prefix: '$cidr'")
        val len =
            if (slash < 0) {
                bytes.size * 8
            } else {
                val l = cidr.substring(slash + 1)
                require(l.isNotEmpty() && l.length <= 3 && l.all { it in '0'..'9' }) { "not a prefix length: '$cidr'" }
                l.toInt()
            }
        require(len in 0..bytes.size * 8) { "prefix length out of range: '$cidr'" }
        for (bit in len until bytes.size * 8) {
            require((bytes[bit / 8].toInt() shr (7 - bit % 8)) and 1 == 0) { "'$cidr' has host bits set beyond /$len" }
        }
        return bytes to len
    }

    /** Whether [address] lies in the prefix [prefix]/[len] of the same family; an IPv4-mapped address matches IPv4 prefixes. */
    fun inPrefix(
        address: ByteArray,
        prefix: ByteArray,
        len: Int,
    ): Boolean {
        if (address.size == prefix.size) return hasPrefix(address, prefix, len)
        if (address.size == 16 && prefix.size == 4 && hasPrefix(address, MAPPED, 96)) {
            return hasPrefix(address.copyOfRange(12, 16), prefix, len)
        }
        return false
    }
}
