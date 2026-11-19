// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress

/**
 * No DF, no QUIC (RFC 9000 section 14): the Kotlin/Native portable socket (ktor-network, [KtorDatagramIo]) gives no access to
 * its descriptor, so DF cannot be set on it, and QUIC is not used there. The accelerated `ksl` socket, linked into every
 * Native binary, sets DF.
 */
internal actual suspend fun openPortableDatagramIo(local: InetSocketAddress): DatagramIo =
    throw QuicException.DontFragmentUnavailable(
        0,
        "the Kotlin/Native portable socket (ktor-network) cannot set DF; the accelerated socket could not be used for $local",
    )

internal actual fun printWarning(line: String) {
    platform.posix.fputs(line + "\n", platform.posix.stderr)
}
