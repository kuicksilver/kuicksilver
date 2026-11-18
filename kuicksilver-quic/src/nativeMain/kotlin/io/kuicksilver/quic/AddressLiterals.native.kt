// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress

internal actual fun InetSocketAddress.ipBytesNoDns(): ByteArray? = parseIpLiteral(hostname)

// the literal is the hostname itself on Kotlin/Native: a name stays a name (resolveAddress() would call getaddrinfo)
internal actual fun InetSocketAddress.literalBytesNoDns(): ByteArray? = parseIpLiteral(hostname)

// the zone texts (no allocation without a '%' in either)
internal actual fun InetSocketAddress.sameZoneAs(other: InetSocketAddress): Boolean =
    if ('%' !in hostname && '%' !in other.hostname) true else ipZoneNoDns().orEmpty() == other.ipZoneNoDns().orEmpty()

// the `%zone` of the IPv6 literal the address was made with (RFC 4007 section 11), brackets aside
internal actual fun InetSocketAddress.ipZoneNoDns(): String? {
    val text = hostname.removePrefix("[").removeSuffix("]")
    val at = text.indexOf('%')
    return if (at < 0 || ':' !in text) null else text.substring(at + 1).ifEmpty { null }
}
