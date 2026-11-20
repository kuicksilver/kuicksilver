// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress

/** The JVM's portable socket binds on its own: a port in use fails its bind, so [acceleratedRefusal] is not needed. */
internal actual suspend fun openPortableDatagramIo(
    local: InetSocketAddress,
    acceleratedRefusal: Throwable?,
): DatagramIo = NioDatagramIo.open(local)

internal actual fun printWarning(line: String) = System.err.println(line)
