// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.engine.BaseApplicationResponse
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.discard
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.io.IOException
import kotlinx.io.Source

/**
 * [this] as the content of a response ([copyContentFrom]) or as the request body an HTTP/1.1 handler reads: a channel
 * that failed is never at its end. ktor-io's `ByteChannel` reports a channel failed with a cause as "closed for read",
 * and its `copyTo` and `readAvailable` then stop as at an end, without the cause, when the failure was there before the
 * read (they throw it only when they were waiting for content at that moment). The engine ended such a response as
 * complete (the last chunk on HTTP/1.1, a FIN on HTTP/3) for content cut short, a proxied body whose upstream failed; a
 * handler's loop on `readAvailable` took an upload the connection cut for a whole one. Here the failure is thrown from
 * `readBuffer` and the channel is not "closed for read", so every read fails with it. A channel cancelled with a
 * `CancellationException` (a cancelled upstream call, a `writer {}` whose job was cancelled) fails with an IOException
 * that carries it: the reader's own coroutine was not cancelled, and a CancellationException would pass for that.
 */
internal fun ByteReadChannel.failureIsNoEnd(): ByteReadChannel = this as? FailureIsNoEnd ?: FailureIsNoEnd(this)

@OptIn(InternalAPI::class)
private class FailureIsNoEnd(
    private val inner: ByteReadChannel,
) : ByteReadChannel {
    override val closedCause: Throwable? get() = inner.closedCause

    // in this order: a failure between the two reads is then seen as a failure, never as a clean end
    override val isClosedForRead: Boolean get() = inner.isClosedForRead && inner.closedCause == null

    override val readBuffer: Source get() {
        inner.closedCause?.let { throw failure(it) }
        return inner.readBuffer
    }

    override suspend fun awaitContent(min: Int): Boolean =
        try {
            inner.awaitContent(min)
        } catch (e: CancellationException) {
            currentCoroutineContext().ensureActive() // the reader itself was cancelled
            throw failure(inner.closedCause ?: e)
        }

    override fun cancel(cause: Throwable?) {
        inner.cancel(cause)
    }

    private fun failure(cause: Throwable): Throwable =
        if (cause is CancellationException) IOException("the channel was cancelled: ${cause.message}", cause) else cause
}

/**
 * Ktor's `respondFromChannel` copy of [readChannel] into this response channel, through [failureIsNoEnd]: a failed
 * channel fails the copy (the engine cuts the response short) instead of ending it. With a Content-Length of [length], a
 * channel that ends before it fails as in Ktor (`BodyLengthIsTooSmall`), one with more bytes too (`BodyLengthIsTooLong`);
 * a channel that fails after giving all [length] bytes leaves the response as it is on the wire, complete.
 */
internal suspend fun ByteWriteChannel.copyContentFrom(
    readChannel: ByteReadChannel,
    length: Long?,
) {
    val content = readChannel.failureIsNoEnd()
    val copied =
        try {
            withContext(Dispatchers.Unconfined) { content.copyTo(this@copyContentFrom, length ?: Long.MAX_VALUE) }
        } catch (e: IOException) {
            // a channel cancelled together with this call (a writer {} of the call's scope): the call's cancellation, which a
            // failed channel's IOException ([failureIsNoEnd]) would otherwise stand in for
            currentCoroutineContext().ensureActive()
            throw e
        }
    if (length == null) return
    if (copied < length) throw BaseApplicationResponse.BodyLengthIsTooSmall(length, copied)
    val more =
        try {
            content.discard(max = 1) > 0
        } catch (e: CancellationException) {
            throw e
        } catch (_: Throwable) {
            false // failed after the whole declared content: nothing of the response is missing
        }
    if (more) throw BaseApplicationResponse.BodyLengthIsTooLong(length)
}
