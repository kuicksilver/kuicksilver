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
 * never looked up; a host name is resolved here, once (on Kotlin/Native `resolveAddress()` calls `getaddrinfo`).
 */
@InternalKuicksilverApi
public fun InetSocketAddress.withLiteralHost(port: Int = this.port): InetSocketAddress {
    if (ipBytesNoDns() != null) return InetSocketAddress(ipLiteral(), port)
    val resolved = resolveAddress() ?: return InetSocketAddress(hostname, port)
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
 * Address bytes as text: IPv4 (4 bytes) as a dotted quad; IPv6 (16) as RFC 5952 recommends (section 4: lower-case hex
 * without leading zeros, the longest run of two or more zero groups, the first of equal runs, as `::`), and an IPv4-mapped
 * (`::ffff:0:0/96`, RFC 4291 section 2.5.5.2) or IPv4-translated (`::ffff:0:0:0/96`, RFC 2765 section 2.1) address in the
 * mixed notation of RFC 5952 section 5 (`::ffff:192.0.2.1`).
 */
internal fun ipText(b: ByteArray): String {
    fun v4(off: Int): String = (off until off + 4).joinToString(".") { (b[it].toInt() and 0xff).toString() }
    if (b.size == 4) return v4(0)
    require(b.size == 16) { "an IP address has 4 or 16 bytes, not ${b.size}" }
    val ff = 0xff.toByte()
    if ((0 until 10).all { b[it].toInt() == 0 } && b[10] == ff && b[11] == ff) return "::ffff:" + v4(12)
    if ((0 until 8).all { b[it].toInt() == 0 } && b[8] == ff && b[9] == ff && b[10].toInt() == 0 && b[11].toInt() == 0) {
        return "::ffff:0:" + v4(12)
    }
    val g = IntArray(8) { ((b[2 * it].toInt() and 0xff) shl 8) or (b[2 * it + 1].toInt() and 0xff) }
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
