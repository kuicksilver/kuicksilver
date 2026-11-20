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
internal actual suspend fun openPortableDatagramIo(
    local: InetSocketAddress,
    acceleratedRefusal: Throwable?,
): DatagramIo {
    // a refused bind (the port in use, an address not on this host; KslException is not an IOException) would refuse any
    // socket: that failure, as the JVM's portable socket reports it, so a caller trying another port for a taken one can tell
    if (acceleratedRefusal is kotlinx.io.IOException && acceleratedRefusal !is QuicException) throw acceleratedRefusal
    throw QuicException
        .DontFragmentUnavailable(
            null,
            "the Kotlin/Native portable socket (ktor-network) cannot set DF; the accelerated socket could not be used for $local",
            permanent = false, // the accelerated socket may open next time (a refusal under load, out of descriptors)
        ).also { e -> acceleratedRefusal?.let(e::addSuppressed) }
}

internal actual fun printWarning(line: String) {
    platform.posix.fputs(line + "\n", platform.posix.stderr)
}
