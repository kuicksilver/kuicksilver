// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.utils.io.ByteChannel

/**
 * Closes the application's write side of a socket from the socket's close(), which may run while the application still
 * writes: the bytes already queued stay readable for the socket's writer, a write waiting for room returns (what it
 * handed over is queued and sent), and every later write fails with ClosedWriteChannelException.
 *
 * Not ktor-io's suspending flushAndClose: when the channel is full it waits for room in the channel's single write slot,
 * and a write of the application already waiting there is resumed with "Concurrent write attempts"
 * (ConcurrentIOException, an IllegalStateException) instead, which escapes the application's coroutine. The socket keeps
 * the [ByteChannel] it was given in attachForWriting for this: the ReaderJob's channel is ktor-io's close-hook wrapper,
 * whose only hook joins the writer. The caller joins the writer itself where its close depends on the drain having
 * ended (the Native TCP socket cancels its read loop only after it).
 */
internal fun ByteChannel.closeFromSocketClose() {
    close()
}
