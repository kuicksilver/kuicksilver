// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.sockets.Socket
import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * Ends this connection at once and releases its descriptor, without sending what is still buffered: for a peer that does
 * not read, whose graceful `close()` would wait for it for ever (the socket's write loop never drains). Idempotent; a
 * [TlsSocket] is aborted together with the socket under it.
 *
 * Cancelling the socket's job is not an abort: ktor-network (and the Kotlin/Native socket of this module) close the
 * descriptor only once `close()` was called and both loops have ended, so loops cancelled before `close()` leave it open
 * (a TLS socket's raw socket did). This closes the socket first and then ends its loops under it with `SO_LINGER` 0, so
 * the kernel drops the unsent bytes with a reset and the descriptor closes: on the JVM and Android the engine socket's own
 * writer is cancelled, on Kotlin/Native both loops are. The peer sees the connection reset, not a stream that ended. A
 * write loop that fails (a send error, or the application's channel failed mid-stream) ends its connection the same way.
 */
@InternalKuicksilverApi
public fun Socket.abort() {
    if (this is TlsSocket) abortTls() else abortTcp()
}

/** [abort] for a plain TCP socket of the platform. */
internal expect fun Socket.abortTcp()
