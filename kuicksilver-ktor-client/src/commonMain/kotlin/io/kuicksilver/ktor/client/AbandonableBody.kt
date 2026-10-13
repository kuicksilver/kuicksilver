// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.HttpResponseData
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.io.Source
import kotlin.coroutines.CoroutineContext

/**
 * A response body that ends its call when the application leaves it unread (found by the soak harness).
 *
 * `HttpStatement.execute {}` ends a streamed response by cancelling its raw body and then joining the call's job. Ktor's
 * default transformer for `bodyAsChannel()` copies the raw body into a second channel in a coroutine whose completion that
 * job waits for; once the application stopped reading with a megabyte or more buffered in that channel, the copier waits
 * for room forever, cancelling the raw body does not wake it, and `execute` never returns. A cancel that finds the body
 * still open (the application left it) cancels the call's job, so `execute` returns and the engine's own work for the call
 * (the HTTP/1.1 body parser, the HTTP/3 stream) ends with it.
 */
@OptIn(InternalAPI::class)
internal class AbandonableBody(
    private val inner: ByteReadChannel,
    private val call: Job,
) : ByteReadChannel {
    override val closedCause: Throwable? get() = inner.closedCause

    override val isClosedForRead: Boolean get() = inner.isClosedForRead

    override val readBuffer: Source get() = inner.readBuffer

    override suspend fun awaitContent(min: Int): Boolean = inner.awaitContent(min)

    override fun cancel(cause: Throwable?) {
        val abandoned = !inner.isClosedForRead
        inner.cancel(cause)
        if (abandoned) call.cancel(CancellationException("response body left unread", cause))
    }

    companion object {
        /** [response] with its channel body wrapped; other bodies (an upgraded WebSocket session) unchanged. */
        fun guard(
            response: HttpResponseData,
            callContext: CoroutineContext,
        ): HttpResponseData {
            val body = response.body as? ByteReadChannel ?: return response
            val call = callContext[Job] ?: return response
            return HttpResponseData(
                response.statusCode,
                response.requestTime,
                response.headers,
                response.version,
                AbandonableBody(body, call),
                response.callContext,
            )
        }
    }
}
