// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.sockets.Socket

internal actual fun kernelBufferBytes(
    writer: Socket,
    reader: Socket,
): Long = sendBufferOf(fd(writer)).toLong() + receiveBufferOf(fd(reader))

private fun fd(s: Socket): Int =
    when (s) {
        is TlsSocket -> fd(s.rawSocket)
        is NativeTcpSocket -> s.descriptor
        else -> error("not one of the engines' sockets: $s")
    }
