// Copyright 2014-2026 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Vendored from Ktor 3.6.0 ktor-client-cio utils.kt (internal there), adapted: keep-alive release hook, no Unix sockets.
package io.kuicksilver.ktor.client.h1

import io.ktor.client.call.UnsupportedContentTypeException
import io.ktor.client.engine.mergeHeaders
import io.ktor.client.plugins.websocket.WEBSOCKETS_KEY
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.client.request.ResponseAdapterAttributeKey
import io.ktor.http.HeadersImpl
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.HttpStatusCode
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.http.cio.ConnectionOptions
import io.ktor.http.cio.HttpHeadersMap
import io.ktor.http.cio.ParserException
import io.ktor.http.cio.RequestResponseBuilder
import io.ktor.http.cio.encodeChunked
import io.ktor.http.cio.parseResponse
import io.ktor.http.content.OutgoingContent
import io.ktor.http.encodedPath
import io.ktor.http.fullPath
import io.ktor.http.hostWithPort
import io.ktor.http.isSecure
import io.ktor.http.supportsRequestBody
import io.ktor.util.date.GMTDate
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.ClosedReadChannelException
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writePacket
import io.ktor.utils.io.writer
import io.ktor.websocket.RawWebSocket
import io.kuicksilver.ktor.client.withSocketTimeout
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.io.EOFException
import kotlinx.io.IOException
import kotlin.coroutines.CoroutineContext
import kotlin.time.Duration.Companion.seconds

/**
 * Request line and headers (absolute-form through an HTTP proxy, RFC 9112 section 3.2.2). Inside a CONNECT [tunneled]
 * connection the proxy's fields stay out: Proxy-Authorization applies only to the proxy that asked for it (RFC 9110
 * section 11.7.2) and went on the CONNECT ([startTunnel]); the origin must not receive the proxy's credentials.
 */
@OptIn(InternalAPI::class)
internal suspend fun writeHeaders(
    request: HttpRequestData,
    output: ByteWriteChannel,
    overProxy: Boolean,
    tunneled: Boolean = false,
) {
    val builder = RequestResponseBuilder()
    val method = request.method
    val url = request.url
    val headers = request.headers
    val body = request.body
    val contentBody = body.getUnwrapped()

    val contentLength = declaredContentLength(request)
    val hasContent = contentBody !is OutgoingContent.NoContent
    val transferEncoding = if (hasContent) chunkedTransferEncoding(request) else null
    val expected = headers[HttpHeaders.Expect]

    try {
        val normalizedUrl = if (url.rawSegments.isEmpty()) URLBuilder(url).apply { encodedPath = "/" }.build() else url
        // The authority without userinfo (RFC 9110 section 4.2.4: a sender MUST NOT generate it in a target URI), the
        // port only when not the scheme's default (RFC 9112 section 3.2); the same value for Host and the absolute-form.
        val authority = if (url.protocol.defaultPort == url.port) url.host else url.hostWithPort
        // Absolute-form (RFC 9112 section 3.2.2) is scheme "://" authority path-abempty ["?" query], never Url.toString(),
        // which carries the userinfo and the fragment (no fragment in a request-target, RFC 9110 section 7.1).
        val urlString = if (overProxy) "${url.protocol.name}://$authority${normalizedUrl.fullPath}" else normalizedUrl.fullPath

        builder.requestLine(method, urlString, HttpProtocolVersion.HTTP_1_1.toString())
        if (!headers.contains(HttpHeaders.Host)) builder.headerLine(HttpHeaders.Host, authority)

        // never Content-Length with Transfer-Encoding (RFC 9112 section 6.2)
        if (contentLength != null && transferEncoding == null) {
            if (method.supportsRequestBody || hasContent) builder.headerLine(HttpHeaders.ContentLength, contentLength)
        }

        mergeHeaders(headers, body) { key, value ->
            if (key == HttpHeaders.ContentLength || key == HttpHeaders.Expect) return@mergeHeaders
            if (key.equals(HttpHeaders.TransferEncoding, true)) return@mergeHeaders // the framing below
            if (tunneled && (key.equals(HttpHeaders.ProxyAuthorization, true) || key.equals("Proxy-Connection", true))) return@mergeHeaders
            builder.headerLine(key, value)
        }

        transferEncoding?.let { builder.headerLine(HttpHeaders.TransferEncoding, it) }
        if (expected != null && expectsContinue(request)) builder.headerLine(HttpHeaders.Expect, expected)

        builder.emptyLine()
        output.writePacket(builder.build())
        output.flush()
    } finally {
        builder.release()
    }
}

/** Whether the request goes out with its Expect field: only with a body, which then waits for the server's answer. */
internal fun expectsContinue(request: HttpRequestData): Boolean =
    request.headers[HttpHeaders.Expect] != null && request.body !is OutgoingContent.NoContent &&
        !request.attributes.contains(ExpectationFailedKey)

/** Set on a request answered with 417 to its `Expect: 100-continue`: it is sent again without the field. */
internal val ExpectationFailedKey = io.ktor.util.AttributeKey<Unit>("kuicksilver.ExpectationFailed")

/**
 * How long a request with `Expect: 100-continue` waits for the server to answer before it sends its body anyway (RFC 9110
 * section 10.1.1): 1 s, as Ktor's CIO engine and curl.
 */
internal val CONTINUE_TIMEOUT = 1.seconds

/** The request body; the connection's output stays open for the next request (keep-alive). */
internal suspend fun writeBody(
    request: HttpRequestData,
    output: ByteWriteChannel,
    callContext: CoroutineContext,
) {
    val body = request.body.getUnwrapped()
    if (body is OutgoingContent.NoContent) return
    if (body is OutgoingContent.ProtocolUpgrade) throw UnsupportedContentTypeException(body)

    if (chunkedTransferEncoding(request) == null) {
        // the Content-Length sent is the body's length (RFC 9112 section 6.2; section 6.3: the recipient reads that many
        // octets as the body): a body that gives fewer bytes leaves the server waiting for the rest or reading the next
        // request's bytes as them, one that gives more puts its excess where the next request goes. Neither is sent as
        // complete: the request fails (an IllegalStateException, never retried) and the connection is closed
        val declared = declaredContentLength(request)?.toLongOrNull()
        val written = processOutgoingContent(body, output, declared)
        output.flush()
        if (declared != null && written < declared) throw bodyLengthMismatch(longer = false, declared)
        return
    }
    val encoder = encodeChunked(output, callContext)
    try {
        processOutgoingContent(body, encoder.channel)
    } catch (e: Throwable) {
        // a body that failed is not complete: closing the encoder's channel would send the last chunk, and the server
        // would take the cut body for the whole; failed, the encoder ends the connection's output with the failure instead
        encoder.channel.cancel(e)
        throw e
    }
    encoder.channel.flushAndClose()
    encoder.job.join()
    output.flush()
}

private fun OutgoingContent.getUnwrapped(): OutgoingContent =
    if (this is OutgoingContent.ContentWrapper) delegate().getUnwrapped() else this

/** The Content-Length a request goes out with when it is not chunked: its own field, else its body's length. */
internal fun declaredContentLength(request: HttpRequestData): String? =
    request.headers[HttpHeaders.ContentLength] ?: request.body
        .getUnwrapped()
        .contentLength
        ?.toString()

private fun bodyLengthMismatch(
    longer: Boolean,
    declared: Long,
) = IllegalStateException("The request body has ${if (longer) "more" else "fewer"} bytes than its Content-Length $declared")

/**
 * Writes [body] to [channel]; returns the bytes written. With a [limit] (the Content-Length sent), at most [limit] bytes
 * are written, and a body that has more fails without writing the excess; one with fewer returns what it had.
 */
private suspend fun processOutgoingContent(
    body: OutgoingContent,
    channel: ByteWriteChannel,
    limit: Long? = null,
): Long {
    /** Copies [source], up to [limit]: fails when [source] has bytes past it. */
    suspend fun copy(source: ByteReadChannel): Long {
        if (limit == null) return source.copyTo(channel)
        val copied = source.copyTo(channel, limit)
        if (copied == limit && source.awaitContent()) throw bodyLengthMismatch(longer = true, limit)
        return copied
    }
    return when (body) {
        is OutgoingContent.ByteArrayContent -> {
            val bytes = body.bytes()
            if (limit != null && bytes.size.toLong() != limit) throw bodyLengthMismatch(bytes.size > limit, limit)
            channel.writeFully(bytes)
            bytes.size.toLong()
        }

        is OutgoingContent.ReadChannelContent -> {
            // ktor's copyTo ends on a source that failed as on one that ended: only a clean end is the body's end
            val source = body.readFrom()
            val n = copy(source)
            source.closedCause?.let { throw it }
            n
        }

        // writeTo may close the channel it gets: give it its own, the connection's output stays open for keep-alive
        is OutgoingContent.WriteChannelContent -> {
            coroutineScope {
                val own = ByteChannel()
                launch {
                    try {
                        body.writeTo(own)
                    } catch (e: Throwable) {
                        own.cancel(e)
                        throw e
                    } finally {
                        own.flushAndClose()
                    }
                }
                val n = copy(own) // one longer than its Content-Length fails, which cancels its writer
                own.closedCause?.let { throw it }
                n
            }
        }

        is OutgoingContent.ContentWrapper -> {
            processOutgoingContent(body.delegate(), channel, limit)
        }

        is OutgoingContent.ProtocolUpgrade, is OutgoingContent.NoContent -> {
            error("unreachable code")
        }
    }
}

/** No request body is being sent, or all of it went out: a streamed one still under way or failed is not out. */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
private fun Deferred<Boolean>?.isOut(): Boolean = this == null || (isCompleted && !isCancelled && getCompleted())

/** What happens to the connection after a response. */
internal enum class AfterResponse {
    Reuse,
    Close,

    /** an upgraded connection lives as long as the call */
    HandOver,
}

/**
 * The largest response head (status line, header section and their line ends) the client reads: 64 KiB, the default
 * `maxFieldSectionSize` our HTTP/3 client advertises (`Http3Settings`), so both protocols take the same headers, and the
 * server's limit for request heads. Above it the request fails with a [ParserException] and the connection is closed.
 */
internal const val MAX_RESPONSE_HEAD_BYTES: Int = 65_536

/**
 * Interim (1xx) responses skipped before the final one; one more fails the request. Go's net/http stops at the same
 * count (`max1xxResponses = 5`); without a bound a server streaming 103 Early Hints holds the request until a timeout.
 */
internal const val MAX_INTERIM_RESPONSES: Int = 5

/**
 * Parses the response head (interim 1xx heads other than 101 are skipped, at most [MAX_INTERIM_RESPONSES]) and starts the
 * body reader. [onBodyDone] runs when the body was read to its end (reuse allowed) or failed; WebSocket upgrades hand
 * the connection to the session (never reused). With [head], the connection's input under [input], every head is limited
 * to its size limit ([MAX_RESPONSE_HEAD_BYTES] for a pooled connection): a larger one fails with [ParserException],
 * which is not an IOException, so a pooled connection is not retried. With [continueBody] (a request with
 * `Expect: 100-continue` whose body waits) a 100 Continue sends the body; a final response before it is the answer, the
 * body is never sent and the connection, which promised one, is closed after the response.
 *
 * [requestBodySent] is the request body sent while the response is read (a streamed body), completed with whether all of
 * it went out; null when there is none. A reusable connection is given back ([AfterResponse.Reuse]) before the response's
 * body ends, so the application that sees that end, and sends its next request at once, finds it idle; only when that
 * request body is already out. One still being sent when the response ends makes it [AfterResponse.Close] at once: the
 * response never waits for the upload (a duplex application closes it after reading the response, a server that answered
 * early may have stopped reading), and the caller closes the connection once the upload ends.
 */
@OptIn(InternalAPI::class)
internal suspend fun readResponse(
    requestTime: GMTDate,
    request: HttpRequestData,
    input: ByteReadChannel,
    output: ByteWriteChannel,
    callContext: CoroutineContext,
    head: HeadLimitedInput? = null,
    continueBody: (suspend () -> Unit)? = null,
    requestBodySent: () -> Deferred<Boolean>? = { null },
    onBodyDone: (AfterResponse) -> Unit,
): HttpResponseData =
    withContext(callContext) {
        var rawResponse: io.ktor.http.cio.Response
        var interim = 0
        var unsentBody = continueBody
        while (true) {
            rawResponse = readResponseHead(input, head)
                ?: throw ClosedReadChannelException(
                    EOFException("Failed to parse HTTP response: the server prematurely closed the connection"),
                )
            // an interim 1xx (100 Continue, 103 Early Hints) is not the response: drop it and read the next head (RFC 9110 section 15.2)
            if (rawResponse.status / 100 != 1 || rawResponse.status == HttpStatusCode.SwitchingProtocols.value) break
            val continued = rawResponse.status == HttpStatusCode.Continue.value
            rawResponse.release()
            if (++interim > MAX_INTERIM_RESPONSES) {
                throw ParserException("More than $MAX_INTERIM_RESPONSES interim (1xx) responses before the final response")
            }
            val send = unsentBody
            if (continued && send != null) {
                unsentBody = null
                send()
            }
        }

        rawResponse.use {
            val status = HttpStatusCode(rawResponse.status, rawResponse.statusText.toString())
            val version = HttpProtocolVersion.parse(rawResponse.version)
            val framing = ResponseFraming.of(rawResponse.headers, http10 = version == HttpProtocolVersion.HTTP_1_0)
            val connectionType = ConnectionOptions.parse(rawResponse.headers.joined(HttpHeaders.Connection))
            // Transfer-Encoding overrides Content-Length (RFC 9112 section 6.3 item 3): the stale length is not shown to Ktor,
            // which would check the body against it
            val headers =
                HeadersImpl(
                    rawResponse.headers.toMap().let { if (framing.transferEncoding != null) it - HttpHeaders.ContentLength else it },
                )
            // a request that said `Connection: close` is the last one on the connection (RFC 9112 section 9.6); a response
            // with both Content-Length and Transfer-Encoding may be a smuggling or splitting attempt (section 6.3 item 3)
            val keepAlive =
                version == HttpProtocolVersion.HTTP_1_1 && connectionType?.close != true &&
                    ConnectionOptions.parse(request.headers[HttpHeaders.Connection])?.close != true && !framing.lengthAndEncoding &&
                    unsentBody == null

            if (status == HttpStatusCode.SwitchingProtocols) {
                onBodyDone(AfterResponse.HandOver)
                val wsConfig = request.attributes[WEBSOCKETS_KEY]
                val session =
                    RawWebSocket(
                        input = input,
                        output = output,
                        masking = true,
                        coroutineContext = callContext,
                        channelsConfig = wsConfig.channelsConfig,
                    )
                return@withContext HttpResponseData(status, requestTime, headers, version, session, callContext)
            }

            val body =
                when {
                    request.method == HttpMethod.Head || status == HttpStatusCode.NotModified || status == HttpStatusCode.NoContent -> {
                        val reusable = keepAlive && !framing.invalidLength && !framing.invalidEncoding
                        onBodyDone(if (reusable && requestBodySent().isOut()) AfterResponse.Reuse else AfterResponse.Close)
                        ByteReadChannel.Empty
                    }

                    // an invalid Content-Length: the framing is unknown, the response is discarded and the connection
                    // closed (RFC 9112 section 6.3 item 5); not an IOException, so a pooled connection is not retried
                    framing.invalidLength -> {
                        throw ParserException(
                            "Invalid or conflicting Content-Length in the response: " +
                                rawResponse.headers.getAll(HttpHeaders.ContentLength).joinToString(),
                        )
                    }

                    // a valid Content-Length of 10^18 bytes or more (RFC 9110 section 8.6): a limit of this client, not an
                    // invalid length; refused the same way, the body is never read
                    framing.transferEncoding == null && framing.contentLength == CONTENT_LENGTH_TOO_LARGE -> {
                        throw ParserException(
                            "The response's Content-Length is larger than this client reads (10^18 bytes or more): " +
                                rawResponse.headers.getAll(HttpHeaders.ContentLength).joinToString(),
                        )
                    }

                    // an invalid Transfer-Encoding: the framing is unknown, handled as an invalid Content-Length (RFC 9112
                    // sections 6.1 and 6.3 items 4 and 5)
                    framing.invalidEncoding -> {
                        throw ParserException(
                            "Invalid Transfer-Encoding in the response: " +
                                rawResponse.headers.getAll(HttpHeaders.TransferEncoding).joinToString(),
                        )
                    }

                    else -> {
                        val scope = CoroutineScope(callContext + CoroutineName("kuicksilver-h1-body-reader"))
                        // reusable only when the whole body went through and ended by its framing (length or chunks), not
                        // by connection close: a writer whose reader gave up (an abandoned body) can complete without an
                        // exception, and that connection still has the rest of the body on the wire. The connection is
                        // settled before the body's channel closes (the writer closes it after this block): the
                        // application that sees the body's end, and sends its next request at once, finds it idle (or
                        // knows it gone). Settled when the writer completed, the connection could be missing then and the
                        // next request opened another one. [settled] only once onBodyDone returned: one that threw is
                        // settled again, as Close
                        var settled = false
                        val parser =
                            scope.writer(autoFlush = true) {
                                framing.readBody(input.withSocketTimeout(request), channel)
                                onBodyDone(
                                    if (keepAlive && framing.delimited && requestBodySent().isOut()) {
                                        AfterResponse.Reuse
                                    } else {
                                        AfterResponse.Close
                                    },
                                )
                                settled = true
                            }
                        parser.job.invokeOnCompletion { if (!settled) onBodyDone(AfterResponse.Close) }
                        parser.channel
                    }
                }

            val responseBody: Any =
                request.attributes.getOrNull(ResponseAdapterAttributeKey)?.adapt(request, status, headers, body, request.body, callContext)
                    ?: body
            return@withContext HttpResponseData(status, requestTime, headers, version, responseBody, callContext)
        }
    }

/**
 * One response head from [input] ([readResponseHeadBytes]), within [head]'s size limit when there is one; null when the
 * connection ended before it.
 */
@OptIn(InternalAPI::class)
private suspend fun readResponseHead(
    input: ByteReadChannel,
    head: HeadLimitedInput?,
): io.ktor.http.cio.Response? {
    head?.startHead()
    val bytes =
        try {
            readResponseHeadBytes(input, MAX_RESPONSE_HEAD_BYTES)
        } catch (e: Throwable) {
            // a head cut at the limit ends like a closed connection
            if (head?.exceeded == true) throw responseHeadTooLarge()
            throw e
        }
    if (head?.exceeded == true) throw responseHeadTooLarge()
    head?.endHead()
    return bytes?.let { parseResponse(ByteReadChannel(it)) }
}

/**
 * HTTP CONNECT through a proxy (RFC 9110 section 9.3.6), before TLS to the origin. The proxy's response head is limited
 * to [MAX_RESPONSE_HEAD_BYTES] ([ParserException] beyond); interim 1xx heads before it are skipped, at most
 * [MAX_INTERIM_RESPONSES]; any final status but 2xx, 101 included, fails the tunnel.
 */
internal suspend fun startTunnel(
    url: Url,
    userAgent: String?,
    proxyAuthorization: String?,
    output: ByteWriteChannel,
    input: ByteReadChannel,
) {
    val builder = RequestResponseBuilder()
    try {
        val hostWithPort = url.hostWithPort
        builder.requestLine(HttpMethod("CONNECT"), hostWithPort, HttpProtocolVersion.HTTP_1_1.toString())
        builder.headerLine(HttpHeaders.Host, hostWithPort)
        builder.headerLine("Proxy-Connection", "Keep-Alive")
        userAgent?.let { builder.headerLine(HttpHeaders.UserAgent, it) }
        proxyAuthorization?.let { builder.headerLine(HttpHeaders.ProxyAuthorization, it) }
        builder.emptyLine()
        output.writePacket(builder.build())
        output.flush()

        // the proxy's heads within the response-head limit, each read up to its end: the bytes after the final one are
        // the tunnel's; interim 1xx heads before it are skipped as for a request (RFC 9110 section 15.2), 101 is final
        var interim = 0
        var rawResponse: io.ktor.http.cio.Response
        while (true) {
            rawResponse = readResponseHeadBytes(input, MAX_RESPONSE_HEAD_BYTES)?.let { parseResponse(ByteReadChannel(it)) }
                ?: throw ClosedReadChannelException(EOFException("Failed to parse CONNECT response: unexpected EOF"))
            if (rawResponse.status / 100 != 1 || rawResponse.status == HttpStatusCode.SwitchingProtocols.value) break
            rawResponse.release()
            if (++interim > MAX_INTERIM_RESPONSES) {
                throw ParserException("More than $MAX_INTERIM_RESPONSES interim (1xx) responses before the CONNECT response")
            }
        }
        rawResponse.use {
            // a 2xx makes the connection a tunnel at the end of the head: Content-Length and Transfer-Encoding are ignored
            // (RFC 9110 section 9.3.6), the bytes that follow are the origin's
            if (rawResponse.status / 100 != 2) throw IOException("Can not establish tunnel connection: ${rawResponse.status}")
        }
    } finally {
        builder.release()
    }
}

/** All values of [name], comma-joined (RFC 9110 section 5.3), or null when absent. */
private fun HttpHeadersMap.joined(name: String): String? = getAll(name).toList().takeIf { it.isNotEmpty() }?.joinToString(",")

/**
 * How a response body ends (RFC 9112 section 6.3), for a response that has one: by the chunked coding when it is the final
 * transfer coding (item 4), by the connection's close for another transfer coding (item 4) or without any framing (item 8),
 * else by Content-Length (item 6). Content-Length is 1*DIGIT, and several values (repeated fields or a list) must be
 * identical (RFC 9110 section 8.6); anything else is [invalidLength] (item 5). A Transfer-Encoding that is not a list of
 * transfer codings, that applies `chunked` twice (RFC 9112 section 6.1) or gives the final `chunked` parameters is
 * [invalidEncoding]: the framing is unknown, as with an invalid length. OWS is only SP and HTAB (RFC 9110 section
 * 5.6.3): `Content-Length: 5<VT>` or `Transfer-Encoding: chunked<U+00A0>` is invalid, not 5 or `chunked`. In an
 * HTTP/1.0 response ([of] with `http10`) Transfer-Encoding makes the framing faulty, Content-Length included (RFC 9112
 * section 6.1 MUST): neither frames the body, which is read as it is until the close (item 8); HTTP/1.0 is not kept alive.
 */
internal class ResponseFraming private constructor(
    val transferEncoding: String?,
    val contentLength: Long,
    val invalidLength: Boolean,
    val invalidEncoding: Boolean,
    /** Content-Length and Transfer-Encoding together: framed by the coding, the connection is not reused (item 3). */
    val lengthAndEncoding: Boolean,
    private val chunked: Boolean,
) {
    /** Whether the body ends by its own framing, so the connection can carry the next response. */
    val delimited: Boolean get() = chunked || (transferEncoding == null && contentLength >= 0)

    /** Copies the body from [input] to [out]; a body that ends before its framing says is incomplete (RFC 9112 section 8). */
    suspend fun readBody(
        input: ByteReadChannel,
        out: ByteWriteChannel,
    ) {
        when {
            chunked -> {
                decodeChunkedBody(input, out)
            }

            transferEncoding == null && contentLength >= 0 -> {
                val copied = input.copyTo(out, contentLength)
                if (copied < contentLength) {
                    throw EOFException("The connection closed after $copied of $contentLength body bytes")
                }
            }

            // ktor's copyTo ends on a connection that failed (a reset) as on one that closed: only the close ends this body,
            // or a cut one would pass for the whole
            else -> {
                input.copyTo(out, Long.MAX_VALUE)
                input.closedCause?.let { throw it }
            }
        }
    }

    companion object {
        fun of(
            headers: HttpHeadersMap,
            http10: Boolean = false,
        ): ResponseFraming {
            val teValues = headers.getAll(HttpHeaders.TransferEncoding).toList()
            val te = teValues.takeIf { it.isNotEmpty() }?.joinToString(",")
            if (http10 && te != null) {
                return ResponseFraming(te, -1L, invalidLength = false, invalidEncoding = false, lengthAndEncoding = false, chunked = false)
            }
            val codings = if (te == null) emptyList() else transferCodingsOf(teValues)
            val last = codings?.lastOrNull()
            val invalidEncoding =
                te != null &&
                    (codings == null || codings.count { it.name == "chunked" } > 1 || (last?.name == "chunked" && last.hasParameters))
            val values = headers.getAll(HttpHeaders.ContentLength).toList()
            val length = if (values.isEmpty()) -1L else contentLengthOf(values)
            return ResponseFraming(
                transferEncoding = te,
                contentLength = length ?: -1L,
                invalidLength = te == null && length == null,
                invalidEncoding = invalidEncoding,
                lengthAndEncoding = te != null && values.isNotEmpty(),
                chunked = !invalidEncoding && last?.name == "chunked",
            )
        }
    }
}

internal fun HttpHeadersMap.toMap(): Map<String, List<String>> {
    val result = mutableMapOf<String, MutableList<String>>()
    for (offset in offsets()) {
        val key = nameAtOffset(offset).toString()
        val value = valueAtOffset(offset).toString()
        if (result[key]?.add(value) == null) result[key] = mutableListOf(value)
    }
    return result
}

/**
 * The Transfer-Encoding a request with content goes out with, or null when its Content-Length frames it. The codings the
 * application set (the request's and the content's Transfer-Encoding) come first, and `chunked` is added as the final one
 * unless it already is: a sender that applies a coding other than chunked MUST apply chunked last (RFC 9112 section
 * 6.1). With any coding, or without a length, the body is chunk-encoded and Content-Length is not sent (section 6.2:
 * MUST NOT with Transfer-Encoding).
 */
internal fun chunkedTransferEncoding(request: HttpRequestData): String? {
    val body = request.body.getUnwrapped()
    val codings =
        (request.headers.getAll(HttpHeaders.TransferEncoding).orEmpty() + body.headers.getAll(HttpHeaders.TransferEncoding).orEmpty())
            .filter { it.isNotBlank() }
    if (codings.isEmpty()) {
        val length = request.headers[HttpHeaders.ContentLength] ?: body.contentLength?.toString()
        return if (length == null) "chunked" else null
    }
    val value = codings.joinToString(", ")
    return if (transferCodingsOf(codings)?.lastOrNull()?.name == "chunked") value else "$value, chunked"
}

internal fun Url.isHttps(): Boolean = protocol.isSecure()
