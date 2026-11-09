// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import kotlinx.io.Source

/**
 * [this] as the content of a response, read by Ktor's `respondFromChannel`, or as the request body an HTTP/1.1 handler
 * reads: a channel that failed is never at its end. ktor-io's `ByteChannel` reports a channel failed with a cause as
 * "closed for read", and its `copyTo` and `readAvailable` then stop as at an end, without the cause, when the failure was
 * there before the read (they throw it only when they were waiting for content at that moment). The engine ended such a
 * response as complete (the last chunk on HTTP/1.1, a FIN on HTTP/3) for content cut short, a proxied body whose upstream
 * failed; a handler's loop on `readAvailable` took an upload the connection cut for a whole one. Here the failure is
 * thrown from `readBuffer` and the channel is not "closed for read", so every read fails with it.
 */
internal fun ByteReadChannel.failureIsNoEnd(): ByteReadChannel = this as? FailureIsNoEnd ?: FailureIsNoEnd(this)

@OptIn(InternalAPI::class)
private class FailureIsNoEnd(
    private val inner: ByteReadChannel,
) : ByteReadChannel {
    override val closedCause: Throwable? get() = inner.closedCause

    override val isClosedForRead: Boolean get() = inner.closedCause == null && inner.isClosedForRead

    override val readBuffer: Source get() {
        inner.closedCause?.let { throw it }
        return inner.readBuffer
    }

    override suspend fun awaitContent(min: Int): Boolean = inner.awaitContent(min)

    override fun cancel(cause: Throwable?) {
        inner.cancel(cause)
    }
}
