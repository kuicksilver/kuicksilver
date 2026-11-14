// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.sockets.ASocket
import kotlinx.coroutines.delay
import kotlin.time.Duration.Companion.milliseconds

internal actual suspend fun awaitDescriptorClosed(socket: ASocket) {
    val open: () -> Boolean =
        when (socket) {
            is KslNioSocket -> ({ socket.isOpen })
            is KslNioServerSocket -> ({ socket.isOpen })
            else -> error("not one of the engines' sockets: $socket")
        }
    while (open()) delay(1.milliseconds)
}
