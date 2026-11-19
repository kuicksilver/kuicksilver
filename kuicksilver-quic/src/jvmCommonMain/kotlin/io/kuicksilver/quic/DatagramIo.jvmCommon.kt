// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress

internal actual suspend fun openPortableDatagramIo(
    local: InetSocketAddress,
    strictDf: Boolean,
): DatagramIo = NioDatagramIo.open(local, strictDf = strictDf)

internal actual fun printWarning(line: String) = System.err.println(line)
