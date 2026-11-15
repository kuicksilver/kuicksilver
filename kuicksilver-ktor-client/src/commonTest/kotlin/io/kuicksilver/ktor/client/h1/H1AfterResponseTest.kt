// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.url
import io.ktor.http.HttpHeaders
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
        /** The Connection field lines of the request. */
        val requestConnection: List<String> = emptyList(),
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
            val request =
                HttpRequestBuilder()
                    .apply {
                        url("http://127.0.0.1:8080/")
                        for (line in case.requestConnection) headers.append(HttpHeaders.Connection, line)
                    }.build()
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

    /**
     * The Connection field is a list (RFC 9110 sections 5.6.1 and 7.6.1): an empty value, or one of only commas and OWS,
     * carries no option and is valid (a recipient MUST parse and ignore empty elements, section 5.6.1.2), with CRLF or a
     * bare LF ending its line; `close` counts in any case, after HTAB, between empty elements and on any field line, of
     * the response or of the request. Before, Ktor's `ConnectionOptions.parse` failed with IllegalArgumentException on the
     * empty value (the response was lost), took `<HTAB>close` for an unknown option and kept the connection, and read only
     * the request's first Connection line.
     */
    @Test fun negative_connectionListsFollowTheListRules() =
        runTest {
            val ok = "Content-Length: 2\r\n\r\nok"
            val listCases =
                listOf(
                    Case("an empty Connection", "HTTP/1.1 200 OK\r\nConnection:\r\n$ok", AfterResponse.Reuse),
                    Case("an empty Connection last", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection:\r\n\r\nok", AfterResponse.Reuse),
                    Case("Connection of only OWS", "HTTP/1.1 200 OK\r\nConnection: \t \r\n$ok", AfterResponse.Reuse),
                    Case("an empty Connection, bare LF", "HTTP/1.1 200 OK\nConnection:\nContent-Length: 2\n\nok", AfterResponse.Reuse),
                    Case("Connection: , ,", "HTTP/1.1 200 OK\r\nConnection: , ,\r\n$ok", AfterResponse.Reuse),
                    Case("two empty Connection lines", "HTTP/1.1 200 OK\r\nConnection:\r\nConnection:\r\n$ok", AfterResponse.Reuse),
                    Case("an empty line then close", "HTTP/1.1 200 OK\r\nConnection:\r\nConnection: close\r\n$ok", AfterResponse.Close),
                    Case("close between empty elements", "HTTP/1.1 200 OK\r\nConnection: , CLOSE ,\r\n$ok", AfterResponse.Close),
                    Case("close after HTAB", "HTTP/1.1 200 OK\r\nConnection: keep-alive,\tclose\r\n$ok", AfterResponse.Close),
                    Case(
                        "an empty request Connection",
                        "HTTP/1.1 200 OK\r\n$ok",
                        AfterResponse.Reuse,
                        requestConnection = listOf(""),
                    ),
                    Case(
                        "close on the request's second Connection line",
                        "HTTP/1.1 200 OK\r\n$ok",
                        AfterResponse.Close,
                        requestConnection = listOf("keep-alive", " close"),
                    ),
                )
            for (case in listCases) assertEquals(case.expected, after(case), case.name)
        }

    private companion object {
        /** More than a body's channel holds (1 MiB): its reader waits for the application. */
        const val BIG = (1 shl 20) + (256 shl 10)
    }
}
