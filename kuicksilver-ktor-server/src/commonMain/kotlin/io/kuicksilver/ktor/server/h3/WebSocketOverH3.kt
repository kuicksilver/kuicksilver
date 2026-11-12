// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server.h3

import io.ktor.http.Headers
import io.ktor.http.HeadersBuilder
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.server.application.PipelineCall
import io.ktor.utils.io.cancel
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.ktor.server.ServerWebSocketInput
import io.kuicksilver.ktor.server.checkWebSocketRsvConflicts
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlin.coroutines.CoroutineContext
import kotlin.io.encoding.Base64
import kotlin.random.Random

/**
 * WebSockets over HTTP/3 (RFC 9220) for Ktor's `webSocket {}` routes: an Extended CONNECT with
 * `:protocol = websocket` is presented to the pipeline as the HTTP/1.1 upgrade request Ktor knows — `GET` with
 * `Connection: Upgrade`, `Upgrade: websocket` and a `Sec-WebSocket-Key` — and the upgrade is answered with `:status 200`.
 */
internal object WebSocketOverH3 {
    const val PROTOCOL: String = "websocket"

    /** The synthetic HTTP/1.1 upgrade headers for an Extended CONNECT request. */
    fun upgradeHeaders(r: Http3ServerRequest): Headers {
        val b = HeadersBuilder()
        H3Call.appendFields(b, r)
        if (b["host"] == null) r.authority?.let { b.append("host", it) }
        b["connection"] = "Upgrade"
        b["upgrade"] = PROTOCOL
        if (b["sec-websocket-version"] == null) b.append("sec-websocket-version", "13")
        // RFC 9220 has no key: Ktor's handshake needs one
        if (b["sec-websocket-key"] == null) b.append("sec-websocket-key", Base64.encode(Random.nextBytes(16)))
        return b.build()
    }

    /**
     * Headers of the 101 that Ktor produced, minus what RFC 9220 section 3 leaves out of the `:status 200` answer, and
     * `content-length`, which a 2xx to CONNECT never carries (RFC 9110 section 9.3.6).
     */
    val DROPPED: Set<String> =
        setOf("connection", "upgrade", "sec-websocket-accept", "transfer-encoding", "keep-alive", "proxy-connection", "content-length")
}

/** The response of a WebSocket-over-HTTP/3 call: the upgrade becomes `acceptConnect()` and the stream carries the frames. */
internal class H3UpgradeResponse(
    call: PipelineCall,
    h3: Http3ServerRequest,
    private val engineDispatcher: CoroutineContext,
    private val userDispatcher: CoroutineContext,
    private val beforeUpgradeForTest: (() -> Unit)? = null,
) : H3Response(call, h3) {
    override suspend fun respondOutgoingContent(content: OutgoingContent) {
        // before anything is committed, so the refusal can still be an ordinary error response
        if (content is OutgoingContent.ProtocolUpgrade) checkWebSocketRsvConflicts(call.attributes)
        super.respondOutgoingContent(content)
    }

    /**
     * A 2xx that does not come from the upgrade (a route other than `webSocket` answered the CONNECT) would tell the client
     * a WebSocket is open that nobody accepted (RFC 9110 section 9.3.6: "Any 2xx (Successful) response indicates that the
     * sender ... will switch to tunnel mode"): it is answered 501 instead, as RFC 9220 section 3 has an unsupported
     * `:protocol` answered. The upgrade's own 101 and errors pass as they are.
     */
    override fun setStatus(statusCode: HttpStatusCode) {
        super.setStatus(if (statusCode.value in 200..299) HttpStatusCode.NotImplemented else statusCode)
    }

    override suspend fun respondUpgrade(upgrade: OutgoingContent.ProtocolUpgrade) {
        beforeUpgradeForTest?.invoke()
        val headers = Http3Headers(h3Headers().fields.filter { it.first !in WebSocketOverH3.DROPPED })
        val stream = h3.acceptConnect(headers)
        answered = true
        // the frames are checked against the extensions negotiated here (RFC 6455 section 5.2, RFC 9220 section 3); the
        // check ends with the upgrade
        val guard = Job()
        var webSocket: ServerWebSocketInput? = null
        try {
            val input =
                ServerWebSocketInput(stream.input, call.request.headers, headersBuilder, call.attributes, engineDispatcher + guard)
                    .also { webSocket = it }
            upgrade.upgrade(input.channel, stream.output, engineDispatcher, userDispatcher).join()
        } finally {
            webSocket?.done()
            guard.cancel()
            // a call cancelled while the session ran cannot end the stream in order: RFC 9220 section 3 has "RST exceptions"
            // as a stream error of type H3_REQUEST_CANCELLED, so both directions are aborted with it (RFC 9114 section
            // 4.1.1), never left with neither a FIN nor a reset. The receive side first, with that code: nothing here
            // suspends before it, so a cancelled call still stops the client's direction
            val cancelled = !currentCoroutineContext().isActive
            if (cancelled) runCatching { stream.stopSending(Http3ErrorCode.REQUEST_CANCELLED) }
            stream.input.cancel() // after an orderly end: the client's rest is not read (STOP_SENDING H3_NO_ERROR)
            try {
                currentCoroutineContext().ensureActive()
                stream.output.flushAndClose()
            } catch (e: CancellationException) {
                // cancelled now, or while the flush waited
                runCatching { stream.reset(Http3ErrorCode.REQUEST_CANCELLED) }
                throw e
            }
        }
    }
}
