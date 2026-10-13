// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.Socket
import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * Opens a TCP connection to [remote], trying each address its host resolves to in turn, for the engines' HTTP/1.1.
 *
 * On the JVM and Android this is ktor-network's `aSocket(selector).tcp().connect(remote)`. On Kotlin/Native it is a socket of
 * this module on [selector]: Ktor 3.6.0's native `NativeIPv6SocketAddress` never copies the address into `sockaddr_in6`, so
 * ktor-network connects every IPv6 address as `::` (the local host on Linux and Apple, WSAEADDRNOTAVAIL on Windows); this
 * socket connects to the resolved address itself (docs/upstream/ktor-native-ipv6.md). An IPv4-mapped IPv6 address
 * (`::ffff:a.b.c.d`) is connected over IPv4, as the JVM does.
 */
@InternalKuicksilverApi
public expect suspend fun connectTcp(
    selector: SelectorManager,
    remote: InetSocketAddress,
): Socket

/**
 * Binds a listening TCP socket on the first address [host] resolves to and [port] (0: the OS picks), for the engines'
 * connectors. On the JVM and Android this is ktor-network's `aSocket(selector).tcp().bind(host, port)`; on Kotlin/Native a
 * socket of this module that binds the exact address: Ktor 3.6.0's native bind used `::` for every IPv6 host, so a connector
 * on `::1` listened on every interface and, dual-stack on Linux and Apple, on IPv4 too (docs/upstream/ktor-native-ipv6.md).
 */
@InternalKuicksilverApi
public expect suspend fun bindTcp(
    selector: SelectorManager,
    host: String,
    port: Int,
): ServerSocket
