// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.Selectable
import io.ktor.network.sockets.ASocket
import kotlinx.coroutines.delay
import kotlin.time.Duration.Companion.milliseconds

// the selector closes the descriptor on its own thread after notifyClosed; until then getsockname still answers. The caller
// opens no descriptor meanwhile, so the number is not reused under the check
internal actual suspend fun awaitDescriptorClosed(socket: ASocket) {
    val fd = (socket as Selectable).descriptor
    while (runCatching { tcpAddressOf(fd, peer = false) }.isSuccess) delay(1.milliseconds)
}
