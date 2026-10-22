// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import kotlinx.io.Source

/**
 * The application's side of a body the pump writes into a ktor-io `ByteChannel`. Only the message's end (FIN after its
 * DATA, the trailers decoded) closes that channel cleanly; a reset, a lost connection or a failed request cancels it with
 * the cause. ktor-io reports both as "closed for read" and lets `readAvailable` answer -1 for either, which an application
 * cannot tell from a complete body (0.2.0 release gate: a truncated download passed as complete). Here a body with a cause
 * is not at its end: `readBuffer` throws it, as does `awaitContent`, so `readAvailable` and every other ktor-io read fails
 * with the cause, the way `QuicStream.input` does. [closedCause] still tells why.
 *
 * [onCancel] runs when the application cancels the body: the stream is stopped there and then. The pump only notices a
 * cancelled channel at its next write, which a peer that pauses never brings, so the stream and its flow-control credit
 * stayed held until the peer sent more.
 */
@OptIn(InternalAPI::class)
internal class BodyReadChannel(
    private val inner: ByteReadChannel,
    private val onCancel: () -> Unit = {},
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
        onCancel()
    }
}
