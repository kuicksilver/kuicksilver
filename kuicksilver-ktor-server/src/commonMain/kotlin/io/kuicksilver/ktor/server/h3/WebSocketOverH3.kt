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
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.ktor.network.DEFAULT_WEBSOCKET_MAX_MESSAGE_SIZE
import io.kuicksilver.ktor.server.ServerWebSocket
import io.kuicksilver.ktor.server.checkWebSocketRsvConflicts
import io.kuicksilver.ktor.server.startServerWebSocket
import io.kuicksilver.ktor.server.webSocketHandshakeRefusal
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
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
        // the client's sec-websocket-version is used as defined in RFC 6455 (RFC 8441 section 5): none, or one other than
        // 13, is refused (webSocketHandshakeRefusal), never made up here. RFC 9220 has no key: Ktor's handshake needs one
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
    /** The engine's `webSocketMaxMessageSize`: the largest WebSocket message a client may send (RFC 6455 section 10.4). */
    private val webSocketMaxMessageSize: Long = DEFAULT_WEBSOCKET_MAX_MESSAGE_SIZE,
) : H3Response(call, h3) {
    override suspend fun respondOutgoingContent(content: OutgoingContent) {
        // before anything is committed, so the refusal can still be an ordinary error response: a handshake without
        // sec-websocket-version 13 gets 400 instead of the upgrade (RFC 8441 section 5, RFC 6455 section 4.2.1)
        if (content is OutgoingContent.ProtocolUpgrade) {
            webSocketHandshakeRefusal(call.request.headers, http3 = true)?.let { return super.respondOutgoingContent(it.content) }
            checkWebSocketRsvConflicts(call.attributes)
        }
        super.respondOutgoingContent(content)
    }

    /**
     * A 2xx that does not come from the upgrade (a route other than `webSocket` answered the CONNECT) would tell the client
     * a WebSocket is open that nobody accepted (RFC 9110 section 9.3.6: "Any 2xx (Successful) response indicates that the
     * sender ... will switch to tunnel mode"): it is answered 501 instead, as RFC 9220 section 3 has an unsupported
     * `:protocol` answered. The upgrade's own 101 and errors pass as they are. Mapped in status(), not setStatus(), so
     * that `call.response.status()` reports the 501 that goes out. An accepted upgrade keeps reporting 101: Ktor's model
     * of the switch, which RFC 9220 carries as a 2xx.
     */
    override fun status(value: HttpStatusCode) {
        super.status(if (value.value in 200..299) HttpStatusCode.NotImplemented else value)
    }

    override suspend fun respondUpgrade(upgrade: OutgoingContent.ProtocolUpgrade) {
        beforeUpgradeForTest?.invoke()
        val headers =
            Http3Headers(h3Headers().fields.filter { it.first !in WebSocketOverH3.DROPPED }).let { h ->
                val marked = call.attributes.getOrNull(io.kuicksilver.ktor.server.NeverIndexKey).orEmpty()
                @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                if (marked.isEmpty()) h else h.withNeverIndexed(*marked.toTypedArray())
            }
        val stream =
            try {
                h3.acceptConnect(headers)
            } catch (_: Http3Exception.MessageError) {
                // the client's fault, a request that announces capsules and breaks RFC 9297 section 3.2: acceptConnect
                // answered it with 400 and stopped it with H3_MESSAGE_ERROR, which the engine's reset must not overtake
                status(HttpStatusCode.BadRequest)
                answered = true
                return
            }
        answered = true
        // the frames are checked against the extensions negotiated here (RFC 6455 section 5.2, RFC 9220 section 3) and the
        // limits; the check ends with the upgrade. The server's frames go out unmasked (RFC 6455 section 5.1)
        val guard = Job()
        var webSocket: ServerWebSocket? = null
        try {
            val input =
                startServerWebSocket(
                    stream.input,
                    call.request.headers,
                    headersBuilder,
                    call.attributes,
                    engineDispatcher + guard,
                    webSocketMaxMessageSize,
                    stream.output,
                    call.application.environment.log,
                ) ?: return // a Close with 1011 went out instead
            webSocket = input
            upgrade.upgrade(input.channel, input.output(stream.output), engineDispatcher, userDispatcher).join()
        } finally {
            webSocket?.done()
            guard.cancel()
            // a call cancelled while the session ran, or while the flush below waits, cannot end the stream in order: RFC
            // 9220 section 3 has "RST exceptions" as a stream error of type H3_REQUEST_CANCELLED, so both directions are
            // aborted with it, STOP_SENDING first (RFC 9114 section 4.1.1), never left with neither a FIN nor a reset. The
            // receive side is let go last in every case: after an orderly end the client's unread rest is stopped with
            // H3_NO_ERROR, after an abort the STOP_SENDING above already went out (the first one counts)
            try {
                currentCoroutineContext().ensureActive()
                stream.output.flushAndClose()
            } catch (e: CancellationException) {
                runCatching { stream.stopSending(Http3ErrorCode.REQUEST_CANCELLED) }
                runCatching { stream.reset(Http3ErrorCode.REQUEST_CANCELLED) }
                throw e
            } finally {
                stream.input.cancel()
            }
        }
    }
}
