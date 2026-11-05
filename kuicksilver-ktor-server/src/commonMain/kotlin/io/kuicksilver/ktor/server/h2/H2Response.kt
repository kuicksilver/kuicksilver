// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server.h2

import io.ktor.http.HeadersBuilder
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.server.application.PipelineCall
import io.ktor.server.engine.BaseApplicationResponse
import io.ktor.server.response.ResponseHeaders
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.discard
import io.kuicksilver.http2.runtime.H2ServerStream
import io.kuicksilver.ktor.server.h1.httpDateNow
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.io.IOException

/**
 * Fields that are connection-specific in HTTP/2 (RFC 9113 section 8.2.2: an endpoint MUST NOT generate them) and `te`, a
 * request-only field: dropped from Ktor's response headers.
 */
private val CONNECTION_SPECIFIC = setOf("connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te")

/**
 * The response of an [H2Call]: the head goes out as HEADERS (lowercase names, connection-specific fields dropped, RFC 9113
 * section 8.2), the content as DATA within the client's windows, each wait for window bounded by [sendStallMillis]. A
 * response without content (to HEAD, a 204 or a 304, RFC 9110 sections 9.3.2, 15.3.5, 15.4.5) ends with its HEADERS and
 * the application's content is not sent. The engine's `Alt-Svc` goes on every response that has none, as on HTTP/1.1.
 */
internal class H2Response(
    call: PipelineCall,
    private val h2: H2ServerStream,
    private val sendStallMillis: Long,
    private val altSvc: () -> String?,
) : BaseApplicationResponse(call) {
    private var statusCode: HttpStatusCode = HttpStatusCode.OK
    private val headersBuilder = HeadersBuilder()

    /** The head went out: the engine resets a stream left unanswered at the end of the call. */
    internal var answered: Boolean = false
        private set

    /** Sends the content handed to [responseChannel]; joined before the stream is released. */
    private var pump: Job? = null

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

    private fun hasNoContent(): Boolean {
        val status = statusCode.value
        return call.request.local.method == HttpMethod.Head || status == 204 || status == 304
    }

    /** The head as HTTP/2 fields (RFC 9113 section 8.2): lowercase names, no connection-specific field, values without OWS. */
    private fun fields(): List<Pair<String, String>> =
        buildList {
            for (name in headersBuilder.names()) {
                val n = name.lowercase()
                if (n in CONNECTION_SPECIFIC) continue
                // Ktor allows OWS around a value; field values carry none (RFC 9110 section 5.5)
                for (v in headersBuilder.getAll(name)!!) add(n to v.trim { it == ' ' || it == '\t' })
            }
        }

    /** Sends the head; [endStream] when no content follows. */
    private fun sendHead(endStream: Boolean) {
        check(!answered) { "the response head was sent already" }
        // an alternative is authoritative for its origin and may clear it (RFC 7838 section 2.2): the engine's value on
        // every response without its own, a 421 excepted, as on HTTP/1.1
        if (headersBuilder["Alt-Svc"] == null && statusCode.value != 421) altSvc()?.let { headersBuilder.append("Alt-Svc", it) }
        // RFC 9110 section 6.6.1: an origin server with a clock MUST send Date (2xx to 4xx; MAY in 5xx)
        if (!headersBuilder.contains(HttpHeaders.Date)) headersBuilder.append(HttpHeaders.Date, httpDateNow())
        dropFramingFieldsOfAResponseWithoutContent()
        h2.respond(statusCode.value, fields(), endStream)
        answered = true
    }

    /**
     * A 204 has no Content-Length (RFC 9110 section 8.6); a 304 keeps one only when it is the length a 200 would have had,
     * which Ktor's `Content-Length: 0` for empty content does not say. As on HTTP/1.1.
     */
    private fun dropFramingFieldsOfAResponseWithoutContent() {
        when (statusCode.value) {
            204 -> headersBuilder.remove(HttpHeaders.ContentLength)
            304 -> if (headersBuilder.getAll(HttpHeaders.ContentLength) == listOf("0")) headersBuilder.remove(HttpHeaders.ContentLength)
        }
    }

    private suspend fun send(content: ByteReadChannel) {
        h2.sendBody(content, end = true, stallMillis = sendStallMillis) {
            IOException("the client took no response content for $sendStallMillis ms")
        }
    }

    override suspend fun respondFromBytes(bytes: ByteArray) {
        if (hasNoContent() || bytes.isEmpty()) return sendHead(endStream = true)
        sendHead(endStream = false)
        send(ByteReadChannel(bytes))
    }

    override suspend fun respondNoContent(content: OutgoingContent.NoContent) {
        sendHead(endStream = true)
    }

    /** As on HTTP/1.1: the application's writer does not run for a response without content. */
    override suspend fun respondWriteChannelContent(content: OutgoingContent.WriteChannelContent) {
        if (hasNoContent()) return sendHead(endStream = true)
        super.respondWriteChannelContent(content)
    }

    override suspend fun respondFromChannel(readChannel: ByteReadChannel) {
        if (hasNoContent()) {
            readChannel.cancel(null)
            return sendHead(endStream = true)
        }
        sendHead(endStream = false)
        send(readChannel)
    }

    /**
     * The channel the application writes the content into: a pump sends it as DATA within the client's windows while the
     * application writes, and the stream ends when the application closes it. For a response without content, a sink.
     */
    override suspend fun responseChannel(): ByteWriteChannel {
        val channel = ByteChannel()
        if (hasNoContent()) {
            sendHead(endStream = true)
            pump = CoroutineScope(call.coroutineContext + Dispatchers.Unconfined).launch { runCatching { channel.discard() } }
            return channel
        }
        sendHead(endStream = false)
        pump =
            CoroutineScope(call.coroutineContext).launch {
                try {
                    send(channel)
                } catch (e: Throwable) {
                    // the stream failed (a reset, the stall deadline, the connection): the application's writes fail with it
                    channel.cancel(e)
                }
            }
        return channel
    }

    /** Waits for the content handed to [responseChannel] to go out (or fail). */
    suspend fun awaitContentSent() {
        pump?.join()
    }

    /** An HTTP/1.1 upgrade has no meaning in HTTP/2 (RFC 9113 section 8.6); WebSockets over HTTP/2 (RFC 8441) are not offered. */
    override suspend fun respondUpgrade(upgrade: OutgoingContent.ProtocolUpgrade) {
        statusCode = HttpStatusCode.NotImplemented
        sendHead(endStream = true)
    }

    override fun setStatus(statusCode: HttpStatusCode) {
        this.statusCode = statusCode
    }
}
