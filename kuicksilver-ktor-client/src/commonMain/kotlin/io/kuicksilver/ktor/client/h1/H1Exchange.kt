// Copyright 2014-2026 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Vendored from Ktor 3.6.0 ktor-client-cio utils.kt (internal there), adapted: keep-alive release hook, no Unix sockets,
// WebSocket extension and RSV checks.
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

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
import io.kuicksilver.ktor.client.webSocketRsvAfterHandshake
import io.kuicksilver.ktor.client.withSocketTimeout
import io.kuicksilver.ktor.network.guardWebSocketInput
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.io.EOFException
import kotlinx.io.IOException
import kotlin.coroutines.CoroutineContext

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

    val contentLength = headers[HttpHeaders.ContentLength] ?: contentBody.contentLength?.toString()
    val contentEncoding = headers[HttpHeaders.TransferEncoding]
    val responseEncoding = contentBody.headers[HttpHeaders.TransferEncoding]
    val chunked = isChunked(contentLength, responseEncoding, contentEncoding)
    val expected = headers[HttpHeaders.Expect]

    try {
        val normalizedUrl = if (url.rawSegments.isEmpty()) URLBuilder(url).apply { encodedPath = "/" }.build() else url
        val urlString = if (overProxy) normalizedUrl.toString() else normalizedUrl.fullPath

        builder.requestLine(method, urlString, HttpProtocolVersion.HTTP_1_1.toString())
        if (!headers.contains(HttpHeaders.Host)) {
            builder.headerLine(HttpHeaders.Host, if (url.protocol.defaultPort == url.port) url.host else url.hostWithPort)
        }

        val hasContent = contentBody !is OutgoingContent.NoContent
        if (contentLength != null) {
            if (method.supportsRequestBody || hasContent) builder.headerLine(HttpHeaders.ContentLength, contentLength)
        }

        mergeHeaders(headers, body) { key, value ->
            if (key == HttpHeaders.ContentLength || key == HttpHeaders.Expect) return@mergeHeaders
            if (tunneled && (key.equals(HttpHeaders.ProxyAuthorization, true) || key.equals("Proxy-Connection", true))) return@mergeHeaders
            builder.headerLine(key, value)
        }

        if (chunked && contentEncoding == null && responseEncoding == null &&
            hasContent
        ) {
            builder.headerLine(HttpHeaders.TransferEncoding, "chunked")
        }
        if (expected != null && body !is OutgoingContent.NoContent) builder.headerLine(HttpHeaders.Expect, expected)

        builder.emptyLine()
        output.writePacket(builder.build())
        output.flush()
    } finally {
        builder.release()
    }
}

/** The request body; the connection's output stays open for the next request (keep-alive). */
internal suspend fun writeBody(
    request: HttpRequestData,
    output: ByteWriteChannel,
    callContext: CoroutineContext,
) {
    val body = request.body.getUnwrapped()
    if (body is OutgoingContent.NoContent) return
    if (body is OutgoingContent.ProtocolUpgrade) throw UnsupportedContentTypeException(body)

    val contentLength = request.headers[HttpHeaders.ContentLength] ?: body.contentLength?.toString()
    val chunked = isChunked(contentLength, body.headers[HttpHeaders.TransferEncoding], request.headers[HttpHeaders.TransferEncoding])
    if (!chunked) {
        processOutgoingContent(body, output)
        output.flush()
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

private suspend fun processOutgoingContent(
    body: OutgoingContent,
    channel: ByteWriteChannel,
) {
    when (body) {
        is OutgoingContent.ByteArrayContent -> {
            channel.writeFully(body.bytes())
        }

        is OutgoingContent.ReadChannelContent -> {
            // ktor's copyTo ends on a source that failed as on one that ended: only a clean end is the body's end
            val source = body.readFrom()
            source.copyTo(channel)
            source.closedCause?.let { throw it }
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
                own.copyTo(channel)
                own.closedCause?.let { throw it }
            }
        }

        is OutgoingContent.ContentWrapper -> {
            processOutgoingContent(body.delegate(), channel)
        }

        is OutgoingContent.ProtocolUpgrade, is OutgoingContent.NoContent -> {
            error("unreachable code")
        }
    }
}

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
 * which is not an IOException, so a pooled connection is not retried.
 */
@OptIn(InternalAPI::class)
internal suspend fun readResponse(
    requestTime: GMTDate,
    request: HttpRequestData,
    input: ByteReadChannel,
    output: ByteWriteChannel,
    callContext: CoroutineContext,
    head: HeadLimitedInput? = null,
    onBodyDone: (AfterResponse) -> Unit,
): HttpResponseData =
    withContext(callContext) {
        var rawResponse: io.ktor.http.cio.Response
        var interim = 0
        while (true) {
            rawResponse = readResponseHead(input, head)
                ?: throw ClosedReadChannelException(
                    EOFException("Failed to parse HTTP response: the server prematurely closed the connection"),
                )
            // an interim 1xx (100 Continue, 103 Early Hints) is not the response: drop it and read the next head (RFC 9110 section 15.2)
            if (rawResponse.status / 100 != 1 || rawResponse.status == HttpStatusCode.SwitchingProtocols.value) break
            rawResponse.release()
            if (++interim > MAX_INTERIM_RESPONSES) {
                throw ParserException("More than $MAX_INTERIM_RESPONSES interim (1xx) responses before the final response")
            }
        }

        rawResponse.use {
            val status = HttpStatusCode(rawResponse.status, rawResponse.statusText.toString())
            val framing = ResponseFraming.of(rawResponse.headers)
            val connectionType = ConnectionOptions.parse(rawResponse.headers.joined(HttpHeaders.Connection))
            // Transfer-Encoding overrides Content-Length (RFC 9112 section 6.3 item 3): the stale length is not shown to Ktor,
            // which would check the body against it
            val headers =
                HeadersImpl(
                    rawResponse.headers.toMap().let { if (framing.transferEncoding != null) it - HttpHeaders.ContentLength else it },
                )
            val version = HttpProtocolVersion.parse(rawResponse.version)
            // a request that said `Connection: close` is the last one on the connection (RFC 9112 section 9.6); a response
            // with both Content-Length and Transfer-Encoding may be a smuggling or splitting attempt (section 6.3 item 3)
            val keepAlive =
                version == HttpProtocolVersion.HTTP_1_1 && connectionType?.close != true &&
                    ConnectionOptions.parse(request.headers[HttpHeaders.Connection])?.close != true && !framing.lengthAndEncoding

            if (status == HttpStatusCode.SwitchingProtocols) {
                // an extension the client did not offer fails the handshake before the connection is handed over
                val extensions = headers.getAll(HttpHeaders.SecWebSocketExtensions).orEmpty()
                val allowedRsv = webSocketRsvAfterHandshake(request, extensions)
                onBodyDone(AfterResponse.HandOver)
                val wsConfig = request.attributes[WEBSOCKETS_KEY]
                val session =
                    RawWebSocket(
                        input = guardWebSocketInput(input, allowedRsv, untilClose = false, peerMasks = false, context = callContext),
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
                        onBodyDone(if (keepAlive && !framing.invalidLength) AfterResponse.Reuse else AfterResponse.Close)
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

                    else -> {
                        val scope = CoroutineScope(callContext + CoroutineName("kuicksilver-h1-body-reader"))
                        // set only when the whole body went through: a writer whose reader gave up (an abandoned body) can
                        // complete without an exception, and that connection still has the rest of the body on the wire
                        var bodyComplete = false
                        val parser =
                            scope.writer(autoFlush = true) {
                                framing.readBody(input.withSocketTimeout(request), channel)
                                bodyComplete = true
                            }
                        // reusable only when the body ended by its framing (length or chunks), not by connection close
                        parser.job.invokeOnCompletion { cause ->
                            onBodyDone(
                                if (cause == null && bodyComplete && keepAlive && framing.delimited) {
                                    AfterResponse.Reuse
                                } else {
                                    AfterResponse.Close
                                },
                            )
                        }
                        parser.channel
                    }
                }

            val responseBody: Any =
                request.attributes.getOrNull(ResponseAdapterAttributeKey)?.adapt(request, status, headers, body, request.body, callContext)
                    ?: body
            return@withContext HttpResponseData(status, requestTime, headers, version, responseBody, callContext)
        }
    }

/** One response head from [input], within [head]'s size limit when there is one. */
@OptIn(InternalAPI::class)
private suspend fun readResponseHead(
    input: ByteReadChannel,
    head: HeadLimitedInput?,
): io.ktor.http.cio.Response? {
    if (head == null) return parseResponse(input)
    head.startHead()
    val response =
        try {
            parseResponse(input)
        } catch (e: Throwable) {
            // a head cut at the limit ends like a closed connection: an EOF, a parser error or no response at all
            if (head.exceeded) throw responseHeadTooLarge()
            throw e
        }
    if (head.exceeded) {
        response?.release()
        throw responseHeadTooLarge()
    }
    head.endHead()
    return response
}

private fun responseHeadTooLarge() = ParserException("The response head is larger than $MAX_RESPONSE_HEAD_BYTES bytes")

/**
 * HTTP CONNECT through a proxy (RFC 9110 section 9.3.6), before TLS to the origin. The proxy's response head is limited
 * to [MAX_RESPONSE_HEAD_BYTES] ([ParserException] beyond); any status but 2xx, a 1xx included, fails the tunnel.
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

        // the proxy's head within the response-head limit, read byte by byte: the bytes after it are the tunnel's
        val head = ExactHeadInput(input, MAX_RESPONSE_HEAD_BYTES)
        val rawResponse =
            try {
                parseResponse(head)
            } catch (e: Throwable) {
                if (head.exceeded) throw responseHeadTooLarge()
                throw e
            } ?: throw (
                if (head.exceeded) {
                    responseHeadTooLarge()
                } else {
                    ClosedReadChannelException(EOFException("Failed to parse CONNECT response: unexpected EOF"))
                }
            )
        if (head.exceeded) {
            rawResponse.release()
            throw responseHeadTooLarge()
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
 * identical (RFC 9110 section 8.6); anything else is [invalidLength] (item 5).
 */
internal class ResponseFraming private constructor(
    val transferEncoding: String?,
    val contentLength: Long,
    val invalidLength: Boolean,
    /** Content-Length and Transfer-Encoding together: framed by the coding, the connection is not reused (item 3). */
    val lengthAndEncoding: Boolean,
) {
    private val chunked: Boolean =
        transferEncoding
            ?.split(',')
            ?.lastOrNull { it.isNotBlank() }
            ?.trim()
            .equals("chunked", ignoreCase = true)

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
        fun of(headers: HttpHeadersMap): ResponseFraming {
            val te = headers.joined(HttpHeaders.TransferEncoding)
            val values = headers.getAll(HttpHeaders.ContentLength).toList()
            val length = if (values.isEmpty()) -1L else contentLengthOf(values)
            return ResponseFraming(
                transferEncoding = te,
                contentLength = length ?: -1L,
                invalidLength = te == null && length == null,
                lengthAndEncoding = te != null && values.isNotEmpty(),
            )
        }

        /** The one length that every value states, or null when one is not 1*DIGIT or they differ. */
        fun contentLengthOf(values: List<CharSequence>): Long? {
            var result: Long? = null
            for (v in values) {
                for (part in v.split(',')) {
                    val t = part.trim()
                    if (t.isEmpty() || t.length > 18 || t.any { it !in '0'..'9' }) return null
                    val n = t.toLong()
                    if (result != null && result != n) return null
                    result = n
                }
            }
            return result
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

internal fun isChunked(
    contentLength: String?,
    responseEncoding: String?,
    contentEncoding: String?,
) = contentLength == null || responseEncoding == "chunked" || contentEncoding == "chunked"

internal fun Url.isHttps(): Boolean = protocol.isSecure()
