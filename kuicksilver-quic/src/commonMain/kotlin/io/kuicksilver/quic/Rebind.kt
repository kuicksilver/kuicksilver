// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * Moves this client connection to a fresh socket: the recovery after [PathEvent.SocketLost] (iOS took the socket while the app
 * was suspended) or whenever the socket under the active path should be replaced. Opens [DatagramIo.open] at [local] (the
 * by default `rebindLocal`: the loopback address of a loopback peer's family, else the wildcard address of its family, any port; [prefer] picks the transport), [migrates][QuicConnection.migrate]
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
 * it talks to now (its active path, else its first) is a loopback address (`loopbackLocalFor`), else the wildcard address
 * of its family. A peer written as an IPv4-mapped loopback address (`::ffff:127.0.0.1`, Kotlin/Native keeps its 16 bytes)
 * keeps the dual-stack wildcard socket: only an IPv6 socket sends to an address written that way, and an IPv6 socket bound
 * to the loopback (::1) reaches no IPv4 address. Public for the Ktor client engine's migration hooks only.
 */
@InternalKuicksilverApi
public fun QuicConnection.rebindLocal(): InetSocketAddress {
    val remote = (activePath ?: paths.firstOrNull())?.remoteAddress
    val bytes = remote?.ipBytesNoDns()
    if (remote != null && !(bytes != null && bytes.size == 16 && isV4Mapped(bytes))) loopbackLocalFor(remote)?.let { return it }
    return InetSocketAddress(if (bytes?.size == 16) "::" else "0.0.0.0", 0)
}

/**
 * The loopback address (any port) a client socket binds to reach [peer] when [peer] is written as a loopback IP literal:
 * 127.0.0.1 for 127.0.0.0/8 and for its IPv4-mapped form (`::ffff:127.0.0.1`, `::ffff:7f00:1`: IPv4 traffic, sent from
 * an IPv4 socket to `unmappedLiteral` of [peer]), ::1 for ::1; null for any other address and for a name, resolved or not
 * (`localhost` included: no lookup, the same answer on every platform). A client socket on the wildcard address shares its
 * port with a socket another local process binds to 127.0.0.1 or ::1 (BSD sockets: macOS, iOS), and the kernel even hands
 * a wildcard bind a port such a socket holds: the peer's replies to the loopback address then reach that socket, not the
 * client. Bound to the loopback, the port is the client's alone there. Public for the Ktor client engine only.
 */
@InternalKuicksilverApi
public fun loopbackLocalFor(peer: InetSocketAddress): InetSocketAddress? {
    val ip = peer.literalBytesNoDns() ?: return null
    return when {
        ip.size == 4 && ip[0] == 127.toByte() -> InetSocketAddress("127.0.0.1", 0)
        ip.size == 16 && isV4Mapped(ip) && ip[12] == 127.toByte() -> InetSocketAddress("127.0.0.1", 0)
        ip.size == 16 && (0 until 15).all { ip[it] == 0.toByte() } && ip[15] == 1.toByte() -> InetSocketAddress("::1", 0)
        else -> null
    }
}

/**
 * [this] with an IPv4-mapped IP literal (`::ffff:a.b.c.d`) written as its IPv4 address, same port; any other address as it
 * is. An IPv4 socket (127.0.0.1, `loopbackLocalFor`) sends only to an IPv4 address. Public for the Ktor client engine only.
 */
@InternalKuicksilverApi
public fun InetSocketAddress.unmappedLiteral(): InetSocketAddress {
    val ip = literalBytesNoDns() ?: return this
    if (ip.size != 16 || !isV4Mapped(ip)) return this
    return InetSocketAddress(ip.copyOfRange(12, 16).joinToString(".") { (it.toInt() and 0xff).toString() }, port)
}

/** Whether [ip] (16 bytes) is IPv4-mapped, `::ffff:0:0/96` (RFC 4291 section 2.5.5.2). */
private fun isV4Mapped(ip: ByteArray): Boolean =
    (0 until 10).all { ip[it] == 0.toByte() } && ip[10] == 0xff.toByte() && ip[11] == 0xff.toByte()
