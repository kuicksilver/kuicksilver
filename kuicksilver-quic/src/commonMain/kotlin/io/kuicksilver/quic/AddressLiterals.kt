// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * The address as an IP literal built from its bytes ([ipText], with an IPv6 zone ID kept as `%zone`), or the host name's
 * text when it is no IP address. Never a resolver call, on any platform: on the JVM and Android `InetSocketAddress.hostname`
 * is `java.net.InetSocketAddress.getHostName()`, a reverse DNS lookup for an address made from a literal (seconds on a
 * device without a resolver), and on Kotlin/Native `resolveAddress()` calls `getaddrinfo`.
 */
@InternalKuicksilverApi
public fun InetSocketAddress.ipLiteral(): String {
    // ipBytesNoDns() is null only for a name: on the JVM and Android an unresolved address, whose hostname is its text
    val b = ipBytesNoDns() ?: return hostname
    val text = ipText(b)
    val zone = if (b.size == 16) ipZoneNoDns() else null
    return if (zone.isNullOrEmpty()) text else "$text%$zone"
}

/**
 * The same host as an IP literal with [port] (the loop group's extra sockets, a resolved connect target). An IP address is
 * never looked up; a host name is resolved here, once (on Kotlin/Native `resolveAddress()` calls `getaddrinfo`). A name that
 * does not resolve (an unresolved java.net address) stays as it is, this same address for the same port.
 */
@InternalKuicksilverApi
public fun InetSocketAddress.withLiteralHost(port: Int = this.port): InetSocketAddress {
    if (ipBytesNoDns() != null) return InetSocketAddress(ipLiteral(), port)
    val resolved = resolveAddress() ?: return if (port == this.port) this else InetSocketAddress(hostname, port)
    return InetSocketAddress(ipText(resolved), port)
}

/**
 * The raw IPv4 (4) or IPv6 (16) address bytes, or null when the address is a host name. Never a resolver call: the endpoint
 * loop asks this for every datagram's source. On the JVM and Android a resolved address carries its bytes (a name was
 * resolved when the address was built); on Kotlin/Native, where `resolveAddress()` calls `getaddrinfo`, an IP literal in
 * `hostname` is parsed instead.
 */
internal expect fun InetSocketAddress.ipBytesNoDns(): ByteArray?

/**
 * The zone ID of a scoped IPv6 address (`fe80::1%en0`: the interface name, or the numeric scope when the address has no
 * interface name), or null; never a resolver call.
 */
internal expect fun InetSocketAddress.ipZoneNoDns(): String?

/**
 * Whether this address and [other] are one IP address and port, however their text was written (Kotlin/Native's
 * InetSocketAddress compares the text it was made with: `::1` against `0:0:0:0:0:0:0:1`): equal addresses at once, else
 * the same port, address bytes and IPv6 zone ID ([sameZoneAs]). An IPv4-mapped IPv6 address (`::ffff:10.0.0.1`, RFC 4291
 * section 2.5.5.2) is its IPv4 address (java.net makes it one; Kotlin/Native keeps 16 bytes). Never a resolver call; a
 * host name only equals the same text.
 */
@InternalKuicksilverApi
public fun InetSocketAddress.sameIpAs(other: InetSocketAddress): Boolean {
    if (port != other.port) return false
    // equal addresses need only the zone checked: java.net's equality leaves the IPv6 scope out
    if (this == other) return sameZoneAs(other)
    val a = ipBytesNoDns() ?: return false
    val b = other.ipBytesNoDns() ?: return false
    return sameUnmapped(a, b) && sameZoneAs(other)
}

/** Whether [a] and [b] (4 or 16 bytes) are one address, an IPv4-mapped one (`::ffff:0:0/96`) counting as its IPv4 address. */
private fun sameUnmapped(
    a: ByteArray,
    b: ByteArray,
): Boolean {
    if (a.size == b.size) return a.contentEquals(b)
    val (v4, v6) = if (a.size == 4) a to b else b to a
    if (v4.size != 4 || v6.size != 16) return false
    for (i in 0 until 10) if (v6[i].toInt() != 0) return false
    if (v6[10].toInt() != -1 || v6[11].toInt() != -1) return false
    for (i in 0 until 4) if (v6[12 + i] != v4[i]) return false
    return true
}

/**
 * Whether both addresses have the same IPv6 zone ID (or none), as [ipZoneNoDns] writes it: the text decides, so
 * `fe80::1%en0` and `fe80::1%4` (en0's index) are two zones here, as their literals differ, and an explicit `%0` is not
 * the absence of a zone. On the JVM and Android an address with no zone builds no text unless both have scope 0 and no
 * interface, where only java.net's text tells `%0` from nothing.
 */
internal expect fun InetSocketAddress.sameZoneAs(other: InetSocketAddress): Boolean

/**
 * Address bytes ([size] of them at [off]: 4 or 16) as text: IPv4 as a dotted quad; IPv6 as RFC 5952 recommends (section 4:
 * lower-case hex without leading zeros, the longest run of two or more zero groups, the first of equal runs, as `::`), and
 * an address under a well-known prefix for an embedded IPv4 address (RFC 5952 section 5: those of RFC 4291 and RFC 2765)
 * in mixed notation: IPv4-mapped `::ffff:0:0/96` (`::ffff:192.0.2.1`), IPv4-translated `::ffff:0:0:0/96`
 * (`::ffff:0:192.0.2.1`), and IPv4-compatible `::/96` (`::192.0.2.1`, RFC 4291 section 2.5.5.1) when its 13th and 14th
 * bytes are not both zero, as `inet_ntop` decides, so `::` and `::1` stay hexadecimal.
 */
internal fun ipText(
    b: ByteArray,
    off: Int = 0,
    size: Int = b.size - off,
): String {
    fun byte(i: Int): Int = b[off + i].toInt() and 0xff

    fun v4(at: Int): String = "${byte(at)}.${byte(at + 1)}.${byte(at + 2)}.${byte(at + 3)}"

    fun zero(
        from: Int,
        to: Int,
    ): Boolean {
        for (i in from until to) if (byte(i) != 0) return false
        return true
    }
    if (size == 4) return v4(0)
    require(size == 16) { "an IP address has 4 or 16 bytes, not $size" }
    if (zero(0, 10) && byte(10) == 0xff && byte(11) == 0xff) return "::ffff:" + v4(12)
    if (zero(0, 8) && byte(8) == 0xff && byte(9) == 0xff && zero(10, 12)) return "::ffff:0:" + v4(12)
    if (zero(0, 12) && (byte(12) != 0 || byte(13) != 0)) return "::" + v4(12)
    val g = IntArray(8) { (byte(2 * it) shl 8) or byte(2 * it + 1) }
    var bestStart = -1
    var bestLen = 0
    var i = 0
    while (i < 8) {
        if (g[i] != 0) {
            i++
            continue
        }
        var j = i
        while (j < 8 && g[j] == 0) j++
        if (j - i > bestLen && j - i >= 2) {
            bestStart = i
            bestLen = j - i
        }
        i = j
    }
    val sb = StringBuilder()
    var k = 0
    while (k < 8) {
        if (k == bestStart) {
            sb.append("::") // "::" absorbs the separators on both sides
            k += bestLen
            continue
        }
        if (sb.isNotEmpty() && !sb.endsWith(':')) sb.append(':')
        sb.append(g[k].toString(16))
        k++
    }
    return sb.toString()
}
