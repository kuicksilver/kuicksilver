// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.toJavaAddress

// a java.net.InetSocketAddress resolved its name when it was built; an unresolved one answers null without a lookup
internal actual fun InetSocketAddress.ipBytesNoDns(): ByteArray? = resolveAddress()

// the scope the address carries (an interface, or a bare scope ID), as java.net's own literal (getHostAddress) names it
internal actual fun InetSocketAddress.ipZoneNoDns(): String? {
    val a = (toJavaAddress() as? java.net.InetSocketAddress)?.address as? java.net.Inet6Address ?: return null
    a.scopedInterface?.let { return it.name }
    return a.scopeId.takeIf { it != 0 }?.toString()
}
