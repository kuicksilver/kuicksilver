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
import io.ktor.utils.io.readAvailable
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.runtime.H2ServerStream
import io.kuicksilver.http3.message.PriorityField
import io.kuicksilver.ktor.server.h1.httpDateNow
import io.kuicksilver.quic.StreamPriority
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
 * the application's content is not sent. The engine's `Alt-Svc` goes on a response that has no `Alt-Svc` field of its own,
 * a 421 excepted, as a field (as on HTTP/1.1) and, once per origin and value on the connection, as an ALTSVC frame ahead of
 * it ([H2AltSvc]).
 */
internal open class H2Response(
    call: PipelineCall,
    protected val h2: H2ServerStream,
    protected val sendStallMillis: Long,
    private val altSvc: H2AltSvc,
) : BaseApplicationResponse(call) {
    private var statusCode: HttpStatusCode = HttpStatusCode.OK
    protected val headersBuilder: HeadersBuilder = HeadersBuilder()

    /** The head went out: the engine resets a stream left unanswered at the end of the call. */
    internal var answered: Boolean = false
        private set

    /**
     * RFC 9218 section 8: the response's own Priority field merges into the client's signal for the DATA that follows (a
     * parameter it leaves out keeps the client's value); one that fails to parse is no choice (RFC 8941 section 4.2).
     * Under the connection's lock, so a PRIORITY_UPDATE arriving meanwhile is merged first or no longer applies. Called
     * right before the head goes out, also a WebSocket's.
     */
    protected fun applyOwnPriority() {
        headersBuilder.getAll("Priority")?.joinToString(", ")?.takeIf { PriorityField.isSignal(it) }?.let { field ->
            h2.choosePriority { urgency, incremental ->
                PriorityField.merge(StreamPriority(urgency, incremental), field).let { it.urgency * 2 + if (it.incremental) 1 else 0 }
            }
        }
    }

    /** A head went out by other means than [sendHead] (a WebSocket's `:status 200`). */
    protected fun markAnswered() {
        answered = true
    }

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

    /** The application's final 1xx was replaced by a 500 without content. */
    private var interimReplaced = false

    private fun hasNoContent(): Boolean {
        val status = statusCode.value
        return interimReplaced || status in 100..199 || call.request.local.method == HttpMethod.Head || status == 204 || status == 304
    }

    /** The head as HTTP/2 fields (RFC 9113 section 8.2): lowercase names, no connection-specific field, values without OWS. */
    protected fun fields(): List<Pair<String, String>> =
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
        if (statusCode.value in 100..199) {
            // RFC 9113 section 8.6: no 101 over HTTP/2, and a 1xx is interim, never a final response: an application that
            // answers with one has failed, and the client gets a 500 without content instead of an interim response
            // followed by a stream that never ends
            call.application.environment.log.warn(
                "HTTP/2: the application answered ${call.request.local.uri} with $statusCode as its final response; sent 500 instead",
            )
            status(HttpStatusCode.InternalServerError) // the call's status too: listeners and logs see what was sent
            headersBuilder.clear()
            interimReplaced = true
        }
        // RFC 7838 section 3: "servers SHOULD instead send an ALTSVC frame (Section 4)", and "despite this recommendation,
        // Alt-Svc header fields remain valid in responses delivered over HTTP/2": the frame (once per origin and value)
        // ahead of this head, and the field, one reading of the value for both; unless the application set its own field,
        // and a 421 carries none, as on HTTP/1.1 (an alternative is authoritative for its origin and may clear it, section 2.2)
        if (headersBuilder["Alt-Svc"] == null && statusCode.value != 421) {
            altSvc.advertise(h2.authority) { h2.altSvc(it) }?.let { headersBuilder.append("Alt-Svc", it) }
        }
        // RFC 9110 section 6.6.1: an origin server with a clock MUST send Date (2xx to 4xx; MAY in 5xx)
        if (!headersBuilder.contains(HttpHeaders.Date)) headersBuilder.append(HttpHeaders.Date, httpDateNow())
        dropFramingFieldsOfAResponseWithoutContent()
        declaredLength = if (endStream) -1 else declaredLengthOf()
        applyOwnPriority()
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

    /** The response's content-length, -1 without one (or with one that is not a number, which Ktor refuses earlier). */
    private var declaredLength = -1L

    /**
     * Sends [content] within the client's windows and ends the stream. RFC 9113 section 8.1.1: content that does not
     * match the response's content-length makes it malformed, so a response that would send more stops before the extra
     * bytes and one that ends short is not ended: either way the stream is reset with INTERNAL_ERROR (the client sees a
     * failed response, never a short or long one that looks complete) and the call fails with an IOException. The check
     * is per piece read from [content] (up to 16 KiB): the piece that would cross the declared length is not sent at all,
     * not even its bytes within the length, since the stream is reset either way and those bytes would only make a
     * longer prefix of a response the client must discard.
     */
    private suspend fun send(content: ByteReadChannel) {
        val stall = { IOException("the client took no response content for $sendStallMillis ms") }
        if (declaredLength < 0) return h2.sendBody(content, end = true, stallMillis = sendStallMillis, stallError = stall)
        val buf = ByteArray(SEND_CHUNK)
        var sent = 0L
        while (true) {
            val n = content.readAvailable(buf, 0, buf.size)
            if (n < 0) {
                content.closedCause?.let { throw it }
                break
            }
            if (sent + n > declaredLength) mismatch("more content than its content-length $declaredLength")
            sent += n
            // sendBody reads its source to the end before it returns: the buffer is free again then
            h2.sendBody(ByteReadChannel(buf, 0, n), end = false, stallMillis = sendStallMillis, stallError = stall)
        }
        if (sent != declaredLength) mismatch("$sent bytes of content, content-length $declaredLength")
        h2.sendBody(ByteReadChannel.Empty, end = true, stallMillis = sendStallMillis, stallError = stall)
    }

    private fun mismatch(what: String): Nothing {
        runCatching { h2.reset(Http2ErrorCode.INTERNAL_ERROR) }
        throw IOException("HTTP/2 response of stream ${h2.id}: $what (RFC 9113 section 8.1.1); the stream was reset")
    }

    override suspend fun respondFromBytes(bytes: ByteArray) {
        if (hasNoContent()) return sendHead(endStream = true)
        if (bytes.isEmpty() && declaredLengthOf() <= 0L) return sendHead(endStream = true)
        sendHead(endStream = false)
        sendBytes(bytes)
    }

    /**
     * [send] for content in hand: it goes out in pieces of [SEND_CHUNK] straight from [bytes], never copied whole (a
     * `ByteReadChannel` over the array copies it, so a response of 32 MiB took 64 MiB and ran a 48 MiB Android 10 heap
     * out of memory). A content-length that does not match is caught before anything is sent (RFC 9113 section 8.1.1).
     */
    private suspend fun sendBytes(bytes: ByteArray) {
        val stall = { IOException("the client took no response content for $sendStallMillis ms") }
        if (declaredLength >= 0 && bytes.size.toLong() != declaredLength) {
            mismatch(
                if (bytes.size > declaredLength) {
                    "more content than its content-length $declaredLength"
                } else {
                    "${bytes.size} bytes of content, content-length $declaredLength"
                },
            )
        }
        var off = 0
        while (off < bytes.size) {
            val n = minOf(SEND_CHUNK, bytes.size - off)
            h2.sendBody(ByteReadChannel(bytes, off, n), end = false, stallMillis = sendStallMillis, stallError = stall)
            off += n
        }
        h2.sendBody(ByteReadChannel.Empty, end = true, stallMillis = sendStallMillis, stallError = stall)
    }

    private fun declaredLengthOf(): Long = headersBuilder[HttpHeaders.ContentLength]?.toLongOrNull() ?: -1L

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

    /**
     * An HTTP/1.1 upgrade has no meaning in HTTP/2 (RFC 9113 section 8.6): 501. WebSockets come through Extended CONNECT
     * instead (RFC 8441, [H2UpgradeResponse]).
     */
    override suspend fun respondUpgrade(upgrade: OutgoingContent.ProtocolUpgrade) {
        status(HttpStatusCode.NotImplemented) // the call's status too: listeners and logs see what was sent
        sendHead(endStream = true)
    }

    override fun setStatus(statusCode: HttpStatusCode) {
        this.statusCode = statusCode
    }
}

/** The largest piece of content handed to the stream at a time (one DATA frame of the default size). */
private const val SEND_CHUNK = 16_384
