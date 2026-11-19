// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * This host's addresses a connection shows: the address the peer reached on its current path (on a wildcard bind, the
 * one the accelerated socket reported; RFC 9000 section 9) and the socket's own when it is bound to a specific address.
 * A wildcard address is left out. Read off the endpoint loop, as a hint: the path may change right after.
 */
@InternalKuicksilverApi
@OptIn(ExperimentalKuicksilverApi::class)
public val QuicConnection.ownAddresses: List<InetSocketAddress>
    get() {
        val out = ArrayList<InetSocketAddress>(2)
        runCatching { core.paths.active.local }.getOrNull()?.let { out += it }
        paths.firstOrNull()?.localAddress?.let { a -> if (!isWildcard(a)) out += a }
        return out
    }

private fun isWildcard(a: InetSocketAddress): Boolean {
    val b = a.ipBytesNoDns() ?: return false
    return b.all { it == 0.toByte() }
}
