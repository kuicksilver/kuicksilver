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
 *
 * Nor ktor-io's close() for an [autoFlush][ByteChannel.autoFlush] channel, such as the client engine's (every write
 * of the application ends with its flush, so between two writes nothing waits in the channel's write buffer): close() first
 * moves that write buffer to the reader (flushWriteBuffer), unsynchronized against a write running on another thread at
 * that moment. The two then change one kotlinx-io Buffer at once: the write's segment moves on to the socket's writer,
 * which sends and recycles it while the write still fills it, and the write buffer is left counting bytes it no longer
 * holds. close() then failed with a NullPointerException (Buffer.write) and lost or corrupted the stream (3 to 8 of
 * 20000 closes under a running write on the JVM), and a segment recycled under a write can come back from kotlinx-io's
 * pool to another channel of the process, whose next flush fails the same way: the signature of run 46118932855, where an
 * HTTP/1.1 read loop's close of its channel failed so under a response head's read. Such a channel is ended with
 * `cancel(null)`: ktor-io's clean end without the move, which touches neither buffer (readers see the queued bytes, then
 * the end). The write running then moves its own bytes with its own flush; the socket's writer sends them if it has not
 * ended yet, which a close concurrent with a write cannot order anyway. A channel without autoFlush may hold bytes its
 * writer wrote and did not flush, which a close after its last write must still send: it keeps close(), and with it the
 * race with a write running at that moment.
 */
internal fun ByteChannel.closeFromSocketClose() {
    // already ended (closed, or cancelled by a failed writer): nothing to move, and close() would still move
    if (isClosedForWrite) return
    if (autoFlush) cancel(null) else close()
}
