// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.sockets.Socket

internal actual fun kernelBufferBytes(
    writer: Socket,
    reader: Socket,
): Long = nio(writer).bufferSizesForTest().first.toLong() + nio(reader).bufferSizesForTest().second

private fun nio(s: Socket): KslNioSocket =
    when (s) {
        is TlsSocket -> nio(s.rawSocket)
        is KslNioSocket -> s
        else -> error("not one of the engines' sockets: $s")
    }
