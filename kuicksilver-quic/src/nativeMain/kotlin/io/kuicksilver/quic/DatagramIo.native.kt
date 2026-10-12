// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress

internal actual suspend fun openPortableDatagramIo(local: InetSocketAddress): DatagramIo = KtorDatagramIo.open(local)

internal actual fun printWarning(line: String) {
    platform.posix.fputs(line + "\n", platform.posix.stderr)
}
