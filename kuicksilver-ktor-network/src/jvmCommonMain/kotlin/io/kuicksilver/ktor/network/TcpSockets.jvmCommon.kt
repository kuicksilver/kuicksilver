// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.aSocket
import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlin.time.Duration

// The JDK's sockets carry the full address: ktor-network connects and binds as it is, but writes through KslNioSocket
// (ktor 3.6.0's writer spins at 100 % CPU while a peer's window is closed).
@InternalKuicksilverApi
public actual suspend fun connectTcp(
    selector: SelectorManager,
    remote: InetSocketAddress,
): Socket = KslNioSocket(aSocket(selector).tcp().connect(remote), selector, CLIENT_CLOSE_TIMEOUT)

@InternalKuicksilverApi
public actual suspend fun connectTcpAddress(
    selector: SelectorManager,
    address: TcpAddress,
): Socket =
    // a literal: java.net.InetSocketAddress parses it without a lookup
    KslNioSocket(aSocket(selector).tcp().connect(InetSocketAddress(address.hostText, address.port)), selector, CLIENT_CLOSE_TIMEOUT)

internal actual fun platformResolveTcp(
    name: String,
    port: Int,
    numericHost: Boolean,
): List<TcpAddress> {
    // getAllByName parses a host that starts with a hex digit or ':' and contains ':' as an IPv6 literal and fails on an
    // invalid one without a lookup; any other host with a ':' would be looked up, so it is refused here
    if (numericHost && !(name.isNotEmpty() && (name[0] == ':' || Character.digit(name[0], 16) >= 0) && ':' in name)) {
        throw java.net.UnknownHostException("$name: not an IP address literal")
    }
    return java.net.InetAddress.getAllByName(name).map { a ->
        TcpAddress(a.address, port, (a as? java.net.Inet6Address)?.scopeId ?: 0)
    }
}

@InternalKuicksilverApi
public actual suspend fun bindTcp(
    selector: SelectorManager,
    host: String,
    port: Int,
): ServerSocket = KslNioServerSocket(aSocket(selector).tcp().bind(host, port), selector)

internal actual fun Socket.rawBytesSent(): Long? = (this as? KslNioSocket)?.bytesWritten?.get()

internal actual fun Socket.setRawCloseTimeout(timeout: Duration?) {
    if (this is KslNioSocket) closeTimeout = timeout
}

internal actual fun Socket.abortTcp() {
    if (this is KslNioSocket) {
        abort()
    } else {
        close()
        socketContext.cancel()
    }
}
