// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.interop

import io.ktor.network.sockets.InetSocketAddress

/**
 * The local address a client endpoint binds to reach [remote], whose address is [remoteBytes] (4 or 16 bytes, null when
 * it does not resolve). A loopback server is reached from the loopback of its family: an endpoint on the wildcard
 * address shares its port with a socket another process binds to 127.0.0.1 (BSD sockets, macOS), the kernel may even
 * hand it a port such a socket holds, and the server's replies to 127.0.0.1 then reach that socket instead of the
 * client. Any other server is reached from the wildcard address of its family (the runner's networks).
 */
internal fun clientLocalAddress(remoteBytes: ByteArray?): InetSocketAddress {
    val v6 = (remoteBytes?.size ?: 4) == 16
    val loopback =
        when {
            remoteBytes == null -> false
            v6 -> remoteBytes.sliceArray(0 until 15).all { it == 0.toByte() } && remoteBytes[15] == 1.toByte()
            else -> remoteBytes[0] == 127.toByte()
        }
    val host =
        when {
            loopback && v6 -> "::1"
            loopback -> "127.0.0.1"
            v6 -> "::"
            else -> "0.0.0.0"
        }
    return InetSocketAddress(host, 0)
}
