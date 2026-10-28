// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.url
import io.ktor.util.date.GMTDate
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * What happens to an HTTP/1.1 connection after each kind of response ([readResponse]'s [AfterResponse]): reused only when
 * it persists (RFC 9112 section 9.3) with its body delimited and the request body out; closed after the upload when only
 * the upload is still under way; closed at once otherwise (section 9.5 for an upload under way).
 */
class H1AfterResponseTest {
    private class Case(
        val name: String,
        val response: String,
        val expected: AfterResponse,
        val requestBodySent: Deferred<Boolean>? = null,
        val continueBody: (suspend () -> Unit)? = null,
        /** Bytes the server sends after [response] and then closes; null: the connection stays open. */
        val tail: ByteArray? = null,
        /** Whether the application drops the body without reading it. */
        val abandon: Boolean = false,
    )

    private val cases =
        listOf(
            Case("a delimited HTTP/1.1 body", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", AfterResponse.Reuse),
            Case("a chunked body", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n", AfterResponse.Reuse),
            Case("a 204", "HTTP/1.1 204 No Content\r\n\r\n", AfterResponse.Reuse),
            Case(
                "a request body already out",
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                AfterResponse.Reuse,
                requestBodySent = CompletableDeferred(true),
            ),
            Case(
                "a request body still being sent",
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                AfterResponse.CloseAfterUpload,
                requestBodySent = CompletableDeferred(),
            ),
            Case(
                "a 204 while the request body is still being sent",
                "HTTP/1.1 204 No Content\r\n\r\n",
                AfterResponse.CloseAfterUpload,
                requestBodySent = CompletableDeferred(),
            ),
            Case(
                "a request body that failed",
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                AfterResponse.Close,
                requestBodySent = CompletableDeferred(false),
            ),
            Case("HTTP/1.0", "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok", AfterResponse.Close),
            Case("a close-delimited body", "HTTP/1.1 200 OK\r\n\r\nok", AfterResponse.Close, tail = ByteArray(0)),
            Case("Connection: close", "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok", AfterResponse.Close),
            Case(
                "Connection: close while the request body is still being sent",
                "HTTP/1.1 413 Content Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                AfterResponse.Close,
                requestBodySent = CompletableDeferred(),
            ),
            Case(
                "a body cut by the connection's end",
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nok",
                AfterResponse.Close,
                tail = ByteArray(0),
            ),
            Case(
                "an abandoned body",
                "HTTP/1.1 200 OK\r\nContent-Length: $BIG\r\n\r\n",
                AfterResponse.Close,
                tail = ByteArray(BIG),
                abandon = true,
            ),
            Case(
                "a final response before 100 Continue",
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
                AfterResponse.Close,
                continueBody = {},
            ),
            Case(
                "Content-Length and Transfer-Encoding",
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
                AfterResponse.Close,
            ),
        )

    private suspend fun TestScope.after(case: Case): AfterResponse {
        val input = ByteChannel()
        input.writeStringUtf8(case.response)
        input.flush()
        val call = Job()
        val done = CompletableDeferred<AfterResponse>()
        try {
            val request = HttpRequestBuilder().apply { url("http://127.0.0.1:8080/") }.build()
            val response =
                readResponse(
                    GMTDate(),
                    request,
                    input,
                    ByteChannel(),
                    coroutineContext + call,
                    continueBody = case.continueBody,
                    requestBodySent = { case.requestBodySent },
                ) { done.complete(it) }
            val body = response.body as ByteReadChannel
            if (case.abandon) {
                body.cancel(null)
            } else if (case.tail == null) {
                body.readBuffer()
            }
            case.tail?.let {
                input.writeFully(it)
                input.flushAndClose()
            }
            if (!case.abandon && case.tail != null) runCatching { body.readBuffer() } // a cut body fails
            return done.await()
        } finally {
            call.cancel()
        }
    }

    @Test fun everyKindOfResponse() =
        runTest {
            for (case in cases) assertEquals(case.expected, after(case), case.name)
        }

    private companion object {
        /** More than a body's channel holds (1 MiB): its reader waits for the application. */
        const val BIG = (1 shl 20) + (256 shl 10)
    }
}
