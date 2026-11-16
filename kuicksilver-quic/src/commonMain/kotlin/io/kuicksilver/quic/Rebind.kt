// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * Moves this client connection to a fresh socket: the recovery after [PathEvent.SocketLost] (iOS took the socket while the app
 * was suspended) or whenever the socket under the active path should be replaced. Opens [DatagramIo.open] at [local] (the
 * by default [rebindLocal]: the loopback address of a loopback peer's family, else the wildcard address of its family, any port; [prefer] picks the transport), [migrates][QuicConnection.migrate]
 * there (RFC 9000 section 9: the new path is validated before the connection sends on it) and closes the path it left, with
 * its socket unless that is the endpoint's own.
 *
 * Throws what [QuicConnection.migrate] throws: IllegalStateException when the new path does not validate (the new socket is
 * closed, the connection stays where it was), the [QuicException.ConnectionLost] of a connection that ended, and for a server
 * connection or a peer that sent `disable_active_migration` the same failures as [QuicConnection.addPath].
 */
@ExperimentalKuicksilverApi
@OptIn(InternalKuicksilverApi::class)
public suspend fun QuicConnection.rebind(
    local: InetSocketAddress? = null,
    prefer: IoPreference = IoPreference.Accelerated,
): PathEvent.Changed {
    val changed = migrate(DatagramIo.open(local ?: rebindLocal(), prefer))
    try {
        changed.old.close()
    } catch (_: IllegalStateException) {
        // the peer's own move made it active again: it stays
    }
    return changed
}

/**
 * Where a new client socket for this connection binds (any port): the loopback address of the peer's family when the peer
 * it talks to now (its active path, else its first) is a loopback address ([loopbackLocalFor]), else the wildcard address
 * of its family. Public for the Ktor client engine's migration hooks only.
 */
@InternalKuicksilverApi
public fun QuicConnection.rebindLocal(): InetSocketAddress {
    val remote = (activePath ?: paths.firstOrNull())?.remoteAddress
    remote?.let { loopbackLocalFor(it) }?.let { return it }
    return InetSocketAddress(if (remote?.ipBytesNoDns()?.size == 16) "::" else "0.0.0.0", 0)
}

/**
 * The loopback address (any port) a client socket binds to reach [peer] when [peer] is a loopback address: 127.0.0.1 for
 * 127.0.0.0/8, ::1 for ::1; null for any other peer (an IPv4-mapped address included) and for a name. A client socket on
 * the wildcard address shares its port with a socket another local process binds to 127.0.0.1 or ::1 (BSD sockets, so
 * macOS and iOS), and the kernel even hands a wildcard bind a port such a socket holds: the peer's replies to the loopback
 * address then reach that socket, not the client. Bound to the loopback, the port is the client's alone there. Public for
 * the Ktor client engine only.
 */
@InternalKuicksilverApi
public fun loopbackLocalFor(peer: InetSocketAddress): InetSocketAddress? {
    val ip = peer.ipBytesNoDns() ?: return null
    return when {
        ip.size == 4 && ip[0] == 127.toByte() -> InetSocketAddress("127.0.0.1", 0)
        ip.size == 16 && (0 until 15).all { ip[it] == 0.toByte() } && ip[15] == 1.toByte() -> InetSocketAddress("::1", 0)
        else -> null
    }
}
