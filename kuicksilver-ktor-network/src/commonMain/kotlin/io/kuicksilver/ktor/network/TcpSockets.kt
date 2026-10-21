// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.Socket
import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlin.time.Duration

/**
 * Opens a TCP connection to [remote], trying each address its host resolves to in turn, for the engines' HTTP/1.1.
 *
 * On the JVM and Android this is ktor-network's `aSocket(selector).tcp().connect(remote)`, writing through Kuicksilver's own
 * writer (ktor-network 3.6.0's spins at 100 % CPU while the peer's window is closed; threat model 3.21). On Kotlin/Native it is a socket of
 * this module on [selector]: Ktor 3.6.0's native `NativeIPv6SocketAddress` never copies the address into `sockaddr_in6`, so
 * ktor-network connects every IPv6 address as `::` (the local host on Linux and Apple, WSAEADDRNOTAVAIL on Windows); this
 * socket connects to the resolved address itself (Ktor issue KTOR-10017). An IPv4-mapped IPv6 address
 * (`::ffff:a.b.c.d`) is connected over IPv4, as the JVM does.
 */
@InternalKuicksilverApi
public expect suspend fun connectTcp(
    selector: SelectorManager,
    remote: InetSocketAddress,
): Socket

/**
 * Binds a listening TCP socket on the first address [host] resolves to and [port] (0: the OS picks), for the engines'
 * connectors. On the JVM and Android this is ktor-network's `aSocket(selector).tcp().bind(host, port)`, its accepted sockets
 * writing through Kuicksilver's own writer as [connectTcp]'s do; on Kotlin/Native a
 * socket of this module that binds the exact address: Ktor 3.6.0's native bind used `::` for every IPv6 host, so a connector
 * on `::1` listened on every interface and, dual-stack on Linux and Apple, on IPv4 too (Ktor issue KTOR-10017).
 */
@InternalKuicksilverApi
public expect suspend fun bindTcp(
    selector: SelectorManager,
    host: String,
    port: Int,
): ServerSocket

/**
 * Sets how long [Socket.close] may let what is queued drain to the peer before it drops the rest and closes the socket; null:
 * as long as the peer takes. For the engines, which own the bound of the sockets they open: [connectTcp]'s sockets and
 * [Socket.tls] start at 3 s, [bindTcp]'s accepted sockets and [Socket.tlsServer] with none, so a server's close does not cut a
 * slow reader's last response short (the engine bounds it instead). Applies to a [TlsSocket] and to the JVM's and Android's
 * engine sockets; a Kotlin/Native engine socket has no bound of its own.
 */
@InternalKuicksilverApi
public fun Socket.setCloseTimeout(timeout: Duration?) {
    if (this is TlsSocket) closeTimeout = timeout else setRawCloseTimeout(timeout)
}

internal expect fun Socket.setRawCloseTimeout(timeout: Duration?)
