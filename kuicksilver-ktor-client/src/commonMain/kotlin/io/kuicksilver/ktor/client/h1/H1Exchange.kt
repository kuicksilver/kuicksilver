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
import io.ktor.http.cio.RequestResponseBuilder
import io.ktor.http.cio.encodeChunked
import io.ktor.http.cio.parseHttpBody
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
import io.ktor.utils.io.discard
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writePacket
import io.ktor.utils.io.writer
import io.ktor.websocket.RawWebSocket
import io.kuicksilver.ktor.client.withSocketTimeout
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.io.EOFException
import kotlinx.io.IOException
import kotlin.coroutines.CoroutineContext

/** Request line and headers (absolute-form through an HTTP proxy, RFC 9112 section 3.2.2). */
@OptIn(InternalAPI::class)
internal suspend fun writeHeaders(
    request: HttpRequestData,
    output: ByteWriteChannel,
    overProxy: Boolean,
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
    } finally {
        encoder.channel.flushAndClose()
        encoder.job.join()
        output.flush()
    }
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
            body.readFrom().copyTo(channel)
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
 * Parses the response head (interim 1xx heads other than 101 are skipped) and starts the body reader. [onBodyDone] runs when the body was read to its end (reuse
 * allowed) or failed; WebSocket upgrades hand the connection to the session (never reused).
 */
@OptIn(InternalAPI::class)
internal suspend fun readResponse(
    requestTime: GMTDate,
    request: HttpRequestData,
    input: ByteReadChannel,
    output: ByteWriteChannel,
    callContext: CoroutineContext,
    onBodyDone: (AfterResponse) -> Unit,
): HttpResponseData =
    withContext(callContext) {
        var rawResponse: io.ktor.http.cio.Response
        while (true) {
            rawResponse = parseResponse(input)
                ?: throw ClosedReadChannelException(
                    EOFException("Failed to parse HTTP response: the server prematurely closed the connection"),
                )
            // an interim 1xx (100 Continue, 103 Early Hints) is not the response: drop it and read the next head (RFC 9110 section 15.2)
            if (rawResponse.status / 100 != 1 || rawResponse.status == HttpStatusCode.SwitchingProtocols.value) break
            rawResponse.release()
        }

        rawResponse.use {
            val status = HttpStatusCode(rawResponse.status, rawResponse.statusText.toString())
            val contentLength = rawResponse.headers[HttpHeaders.ContentLength]?.toString()?.toLongOrNull() ?: -1L
            val transferEncoding = rawResponse.headers[HttpHeaders.TransferEncoding]?.toString()
            val connectionType = ConnectionOptions.parse(rawResponse.headers[HttpHeaders.Connection])
            val headers = HeadersImpl(rawResponse.headers.toMap())
            val version = HttpProtocolVersion.parse(rawResponse.version)
            val keepAlive = version == HttpProtocolVersion.HTTP_1_1 && connectionType?.close != true

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
                        onBodyDone(if (keepAlive) AfterResponse.Reuse else AfterResponse.Close)
                        ByteReadChannel.Empty
                    }

                    else -> {
                        val scope = CoroutineScope(callContext + CoroutineName("kuicksilver-h1-body-reader"))
                        // set only when the whole body went through: a writer whose reader gave up (an abandoned body) can
                        // complete without an exception, and that connection still has the rest of the body on the wire
                        var bodyComplete = false
                        val parser =
                            scope.writer(autoFlush = true) {
                                parseHttpBody(
                                    version,
                                    contentLength,
                                    transferEncoding,
                                    connectionType,
                                    input.withSocketTimeout(request),
                                    channel,
                                )
                                bodyComplete = true
                            }
                        // reusable only when the body ended by its framing (length or chunks), not by connection close
                        parser.job.invokeOnCompletion { cause ->
                            onBodyDone(
                                if (cause == null && bodyComplete && keepAlive &&
                                    (contentLength >= 0 || transferEncoding != null)
                                ) {
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

/** HTTP CONNECT through a proxy (RFC 9110 section 9.3.6), before TLS to the origin. */
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

        val rawResponse =
            parseResponse(input) ?: throw ClosedReadChannelException(EOFException("Failed to parse CONNECT response: unexpected EOF"))
        rawResponse.use {
            if (rawResponse.status / 100 != 2) throw IOException("Can not establish tunnel connection: ${rawResponse.status}")
            rawResponse.headers[HttpHeaders.ContentLength]?.let { input.discard(it.toString().toLong()) }
        }
    } finally {
        builder.release()
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
