// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
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
public actual suspend fun bindTcp(
    selector: SelectorManager,
    host: String,
    port: Int,
): ServerSocket = KslNioServerSocket(aSocket(selector).tcp().bind(host, port), selector)

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
