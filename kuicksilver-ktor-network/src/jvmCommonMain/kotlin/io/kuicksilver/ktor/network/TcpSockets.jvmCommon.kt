// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.aSocket
import io.kuicksilver.annotations.InternalKuicksilverApi

// The JDK's sockets carry the full address: ktor-network is used as it is.
@InternalKuicksilverApi
public actual suspend fun connectTcp(
    selector: SelectorManager,
    remote: InetSocketAddress,
): Socket = aSocket(selector).tcp().connect(remote)

@InternalKuicksilverApi
public actual suspend fun bindTcp(
    selector: SelectorManager,
    host: String,
    port: Int,
): ServerSocket = aSocket(selector).tcp().bind(host, port)
