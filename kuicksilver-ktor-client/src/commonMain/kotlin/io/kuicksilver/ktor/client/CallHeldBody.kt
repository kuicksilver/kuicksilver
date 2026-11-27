// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.util.AttributeKey
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.Job
import kotlinx.io.Source
import kotlin.coroutines.CoroutineContext

/**
 * An HTTP/2 or HTTP/3 response body that keeps its call going until the body is done: read to its end, failed, or
 * cancelled by its reader. The stream is released when the call's job completes, and Ktor completes that job before some
 * readers start: `HttpStatement.cleanup` completes the call's job and joins it as soon as the response was handed out, which
 * for an SSE session (`ResponseAdapter`) is before the session reads a single event. Ktor's own engines (CIO, OkHttp) and
 * the HTTP/1.1 path keep such a call going with the coroutine that produces the body, a child of the call's job; the
 * HTTP/2 and HTTP/3 bodies are filled by their connection, outside the call, so this child job ([hold]) does that instead:
 * the call's job stays completing, its stream open, until the body is done. Cancelling the call cancels [hold] with it,
 * and the stream is reset as before (RST_STREAM CANCEL, STOP_SENDING H3_REQUEST_CANCELLED).
 *
 * [hold] always completes normally: a body that failed fails its reader, not the call's job.
 */
@OptIn(InternalAPI::class)
internal class CallHeldBody private constructor(
    private val inner: ByteReadChannel,
    private val hold: CompletableJob,
) : ByteReadChannel {
    override val closedCause: Throwable? get() = inner.closedCause.also { if (it != null) hold.complete() }

    override val isClosedForRead: Boolean get() = inner.isClosedForRead.also { if (it) hold.complete() }

    override val readBuffer: Source get() = inner.readBuffer

    override suspend fun awaitContent(min: Int): Boolean =
        try {
            inner.awaitContent(min)
        } finally {
            // the end (or the failure) of the body; a reader cancelled while it waited leaves the body as it is: its owner
            // cancels the channel (an SSE session does when it closes) or the call
            if (inner.isClosedForRead || inner.closedCause != null) hold.complete()
        }

    override fun cancel(cause: Throwable?) {
        try {
            inner.cancel(cause)
        } finally {
            hold.complete()
        }
    }

    internal companion object {
        /** [body] held open for the call of [callContext]; [body] itself for a call without a job or an empty body. */
        fun of(
            body: ByteReadChannel,
            callContext: CoroutineContext,
        ): ByteReadChannel {
            val call = callContext[Job] ?: return body
            if (body === ByteReadChannel.Empty) return body
            return CallHeldBody(body, Job(call))
        }
    }
}

/**
 * Set by an HTTP/3 attempt on its request once it has a response: abandons that response (its held body and its stream)
 * when the engine drops it to send the request again. The next attempt replaces it.
 */
internal val AbandonResponseKey: AttributeKey<(Throwable) -> Unit> = AttributeKey("io.kuicksilver.ktor.client.AbandonResponse")
