// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * The address as an IP literal built from its bytes, or the hostname when it does not resolve. Never `hostname` on a hot
 * path: on the JVM and Android `InetSocketAddress.hostname` is `java.net.InetSocketAddress.getHostName()`, which performs a
 * reverse DNS lookup for an address that was created from a literal (seconds on a device without a resolver).
 */
@InternalKuicksilverApi
public fun InetSocketAddress.ipLiteral(): String {
    val b = resolveAddress() ?: return hostname
    return when (b.size) {
        4 -> {
            b.joinToString(".") { (it.toInt() and 0xff).toString() }
        }

        16 -> {
            val g = IntArray(8) { ((b[2 * it].toInt() and 0xff) shl 8) or (b[2 * it + 1].toInt() and 0xff) }
            var bestStart = -1
            var bestLen = 0
            var i = 0 // RFC 5952: the longest run of two or more zero groups becomes "::"
            while (i <
                8
            ) {
                if (g[i] !=
                    0
                ) {
                    i++
                    continue
                }
                var j = i
                while (j < 8 &&
                    g[j] == 0
                ) {
                    j++
                }
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
                    sb.append("::")
                    k += bestLen
                    continue
                } // "::" absorbs the separators on both sides
                if (sb.isNotEmpty() && !sb.endsWith(':')) sb.append(':')
                sb.append(g[k].toString(16))
                k++
            }
            sb.toString()
        }

        else -> {
            hostname
        }
    }
}

/** The same host as an IP literal with [port] (the loop group's extra sockets, a resolved connect target). */
@InternalKuicksilverApi
public fun InetSocketAddress.withLiteralHost(port: Int = this.port): InetSocketAddress = InetSocketAddress(ipLiteral(), port)

/**
 * The raw IPv4 (4) or IPv6 (16) address bytes, or null when the address is a host name. Never a resolver call: the endpoint
 * loop asks this for every datagram's source. On the JVM and Android a resolved address carries its bytes (a name was
 * resolved when the address was built); on Kotlin/Native, where `resolveAddress()` calls `getaddrinfo`, an IP literal in
 * `hostname` is parsed instead.
 */
internal expect fun InetSocketAddress.ipBytesNoDns(): ByteArray?
