// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.toJavaAddress

// a java.net.InetSocketAddress resolved its name when it was built; an unresolved one answers null without a lookup
internal actual fun InetSocketAddress.ipBytesNoDns(): ByteArray? = resolveAddress()

// the scope as java.net's own literal (getHostAddress) writes it: the interface name, else the numeric scope ID whenever one
// was given, an explicit `%0` included (getScopeId() is 0 both for `%0` and for no scope; only the text tells them apart)
internal actual fun InetSocketAddress.sameZoneAs(other: InetSocketAddress): Boolean {
    val a = (toJavaAddress() as? java.net.InetSocketAddress)?.address as? java.net.Inet6Address
    val b = (other.toJavaAddress() as? java.net.InetSocketAddress)?.address as? java.net.Inet6Address
    if (a == null || b == null) return a == null && b == null
    return a.scopeId == b.scopeId && a.scopedInterface?.name == b.scopedInterface?.name
}

internal actual fun InetSocketAddress.ipZoneNoDns(): String? {
    val a = (toJavaAddress() as? java.net.InetSocketAddress)?.address as? java.net.Inet6Address ?: return null
    val text = a.hostAddress ?: return null
    val at = text.indexOf('%')
    return if (at < 0) null else text.substring(at + 1)
}
