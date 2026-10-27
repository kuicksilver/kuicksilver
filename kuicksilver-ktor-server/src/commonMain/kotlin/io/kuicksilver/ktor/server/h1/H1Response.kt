// Copyright 2014-2021 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Vendored from Ktor 3.6.0 ktor-server-cio CIOApplicationResponse.kt (internal there), adapted: Alt-Svc for HTTP/3 (RFC 7838),
// `Connection: close` once the server is stopping, WebSocket frames checked against the negotiated extensions.
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server.h1

import io.ktor.http.HeadersBuilder
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.HttpStatusCode
import io.ktor.http.cio.RequestResponseBuilder
import io.ktor.http.cio.encodeChunked
import io.ktor.http.content.OutgoingContent
import io.ktor.server.engine.BaseApplicationResponse
import io.ktor.server.response.ResponseHeaders
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.cancel
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writePacket
import io.kuicksilver.ktor.network.guardWebSocketInput
import io.kuicksilver.ktor.server.webSocketRsv
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.withContext
import kotlin.coroutines.CoroutineContext

internal class H1Response(
    call: H1Call,
    private val output: ByteWriteChannel,
    private val input: ByteReadChannel,
    private val engineDispatcher: CoroutineContext,
    private val userDispatcher: CoroutineContext,
    private val upgraded: CompletableDeferred<Boolean>?,
    private val altSvc: String?,
    /** True once the connection ends after this response (the server is stopping): it then says `Connection: close`. */
    private val closing: () -> Boolean = { false },
    /**
     * Completed as the response head goes out with whether the connection ends after this response: the head says
     * `Connection: close` (RFC 9112 section 9.6), set by the application, by [closing], or because the close delimits
     * the body of a response of unknown length to an HTTP/1.0 request.
     */
    private val endsConnection: CompletableDeferred<Boolean>? = null,
) : BaseApplicationResponse(call) {
    private var statusCode: HttpStatusCode = HttpStatusCode.OK
    private val headersBuilder = HeadersBuilder()

    private var chunkedChannel: ByteWriteChannel? = null

    private var chunkedJob: Job? = null

    override val headers =
        object : ResponseHeaders() {
            override fun engineAppendHeader(
                name: String,
                value: String,
            ) {
                headersBuilder.append(name, value)
            }

            override fun getEngineHeaderNames(): List<String> = headersBuilder.names().toList()

            override fun getEngineHeaderValues(name: String): List<String> = headersBuilder.getAll(name).orEmpty()
        }

    override suspend fun responseChannel(): ByteWriteChannel {
        sendResponseMessage(false)
        return preparedBodyChannel()
    }

    override suspend fun respondUpgrade(upgrade: OutgoingContent.ProtocolUpgrade) {
        sendResponseMessage(contentReady = false)

        // a WebSocket's frames are checked against the extensions negotiated here (RFC 6455 section 5.2); the check
        // ends with the upgrade
        val guard = Job()
        try {
            val upgradedInput =
                if (call.request.headers[HttpHeaders.Upgrade]?.contains("websocket", ignoreCase = true) == true) {
                    val allowedRsv = webSocketRsv(call.request.headers, headersBuilder)
                    guardWebSocketInput(input, allowedRsv, untilClose = false, peerMasks = true, context = engineDispatcher + guard)
                } else {
                    input
                }
            val upgradedJob = upgrade.upgrade(upgradedInput, output, engineDispatcher, userDispatcher)
            upgradedJob.join()
        } finally {
            guard.cancel()
            output.flushAndClose()
            input.cancel()
        }
    }

    override suspend fun respondFromBytes(bytes: ByteArray) {
        sendResponseMessage(contentReady = true)
        val channel = preparedBodyChannel()
        return withContext(Dispatchers.Unconfined) {
            channel.writeFully(bytes)
            channel.flushAndClose()
        }
    }

    override suspend fun respondNoContent(content: OutgoingContent.NoContent) {
        sendResponseMessage(contentReady = true)
        output.flushAndClose()
    }

    override suspend fun respondOutgoingContent(content: OutgoingContent) {
        if (content is OutgoingContent.ProtocolUpgrade) {
            upgraded?.complete(true) ?: throw IllegalStateException(
                "Unable to perform upgrade as it is not requested by the client: " +
                    "request should have Upgrade and Connection headers filled properly",
            )
        } else {
            upgraded?.complete(false)
        }

        super.respondOutgoingContent(content)
        chunkedChannel?.flushAndClose()
        chunkedJob?.join()
    }

    override fun setStatus(statusCode: HttpStatusCode) {
        this.statusCode = statusCode
    }

    private suspend fun sendResponseMessage(contentReady: Boolean) {
        // HTTP/3 on the same port is announced on every response that does not carry its own Alt-Svc (RFC 7838)
        if (altSvc != null && headersBuilder["Alt-Svc"] == null && statusCode.value != 421) headersBuilder.append("Alt-Svc", altSvc)
        // the server is stopping and reads no further request here: say so (RFC 9112 section 9.6), as Go's Shutdown does
        if (closing() && statusCode != HttpStatusCode.SwitchingProtocols) headersBuilder[HttpHeaders.Connection] = "close"
        dropFramingFieldsOfAResponseWithoutContent()
        if (HttpProtocolVersion.parse(call.request.local.version) == HttpProtocolVersion.HTTP_1_0 &&
            headersBuilder.contains(HttpHeaders.TransferEncoding)
        ) {
            // HTTP/1.0 request: a server MUST NOT send Transfer-Encoding (RFC 9112 section 6.1). A body of unknown length
            // (Ktor asked for chunked) goes out raw and the close delimits it (section 6.3 item 8), which `Connection:
            // close` announces (section 9.6), whatever the request's keep-alive
            headersBuilder.remove(HttpHeaders.TransferEncoding)
            headersBuilder[HttpHeaders.Connection] = "close"
        }
        // a server that sends the "close" option MUST initiate the close after this response and MUST NOT process any
        // further request on the connection (RFC 9112 section 9.6); a 101 hands the connection to the new protocol
        endsConnection?.complete(statusCode != HttpStatusCode.SwitchingProtocols && saysClose())
        val builder = RequestResponseBuilder()
        try {
            builder.responseLine("HTTP/1.1", statusCode.value, statusCode.description)
            for (name in headersBuilder.names()) {
                for (value in headersBuilder.getAll(name)!!) {
                    builder.headerLine(name, value)
                }
            }
            builder.emptyLine()
            output.writePacket(builder.build())

            if (!contentReady) {
                output.flush()
            }
        } finally {
            builder.release()
        }
    }

    /**
     * A 1xx or 204 response has no content: a server MUST NOT send Content-Length in it (RFC 9110 section 8.6) nor
     * Transfer-Encoding (RFC 9112 section 6.1). A 304 has none either: no Transfer-Encoding, and Content-Length only
     * when it equals the length a 200 would have had (RFC 9110 section 8.6), which `Content-Length: 0` does not say for a
     * non-empty resource: Ktor adds it for every empty content (`respond(HttpStatusCode.NotModified)`), so it is dropped
     * (a 304 MAY omit it); another value is the application's and stays.
     */
    private fun dropFramingFieldsOfAResponseWithoutContent() {
        val status = statusCode.value
        if (status in 100..199 || status == 204) {
            headersBuilder.remove(HttpHeaders.ContentLength)
            headersBuilder.remove(HttpHeaders.TransferEncoding)
        } else if (status == 304) {
            headersBuilder.remove(HttpHeaders.TransferEncoding)
            if (headersBuilder.getAll(HttpHeaders.ContentLength) == listOf("0")) headersBuilder.remove(HttpHeaders.ContentLength)
        }
    }

    /** Whether a Connection field line of the response carries the `close` option (RFC 9110 section 7.6.1, any case). */
    private fun saysClose(): Boolean =
        headersBuilder.getAll(HttpHeaders.Connection).orEmpty().any { line ->
            line.split(',').any { it.trim().equals("close", ignoreCase = true) }
        }

    private fun preparedBodyChannel(): ByteWriteChannel {
        val chunked = headers[HttpHeaders.TransferEncoding] == "chunked"
        if (!chunked) return output

        val encoderJob = encodeChunked(output, Dispatchers.Unconfined)
        val chunkedOutput = encoderJob.channel

        chunkedChannel = chunkedOutput
        chunkedJob = encoderJob.job

        return chunkedOutput
    }
}
