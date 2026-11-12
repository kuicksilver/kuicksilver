// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server.h2

import io.ktor.http.Headers
import io.ktor.http.HeadersBuilder
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.server.application.PipelineCall
import io.ktor.utils.io.ByteChannel
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.runtime.H2ServerStream
import io.kuicksilver.ktor.network.DEFAULT_WEBSOCKET_MAX_MESSAGE_SIZE
import io.kuicksilver.ktor.server.ServerWebSocket
import io.kuicksilver.ktor.server.checkWebSocketRsvConflicts
import io.kuicksilver.ktor.server.h1.httpDateNow
import io.kuicksilver.ktor.server.startServerWebSocket
import io.kuicksilver.ktor.server.webSocketHandshakeRefusal
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException
import kotlin.coroutines.CoroutineContext
import kotlin.io.encoding.Base64
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds

/**
 * WebSockets over HTTP/2 (RFC 8441) for Ktor's `webSocket {}` routes, as [io.kuicksilver.ktor.server.h3.WebSocketOverH3]
 * does for HTTP/3: an Extended CONNECT with `:protocol = websocket` is presented to the pipeline as the HTTP/1.1 upgrade
 * request Ktor knows (`GET` with `Connection: Upgrade`, `Upgrade: websocket` and a `Sec-WebSocket-Key`), and the upgrade is
 * answered with `:status 200`; the stream then carries the frames (section 5).
 */
internal object WebSocketOverH2 {
    const val PROTOCOL: String = "websocket"

    /**
     * How long a session that ended in order waits, after its END_STREAM, for the client's (RFC 8441 section 5: "Orderly
     * TCP-level closures are represented as END_STREAM flags"); only a client that has not ended by then is stopped with
     * RST_STREAM. As the client engine's wait (RFC 6455 section 7.1.1).
     */
    val CLOSE_WAIT: kotlin.time.Duration = 5.seconds

    /**
     * The synthetic HTTP/1.1 upgrade headers of an Extended CONNECT: its fields (split `cookie` fields joined, section
     * 8.2.3 of RFC 9113), `Host` from `:authority`, the upgrade fields, and a random `Sec-WebSocket-Key`, which Ktor's
     * handshake needs (RFC 8441 section 5: the key and its accept are not part of the exchange; neither goes on the wire).
     */
    fun upgradeHeaders(r: H2ServerStream): Headers {
        val b = HeadersBuilder()
        val cookies = ArrayList<String>()
        for ((n, v) in r.fields) if (n == "cookie") cookies += v else b.append(n, v)
        if (cookies.isNotEmpty()) b.append("cookie", cookies.joinToString("; "))
        if (b["host"] == null) r.authority?.let { b.append("host", it) }
        b[HttpHeaders.Connection] = "Upgrade"
        b[HttpHeaders.Upgrade] = PROTOCOL
        b.remove(HttpHeaders.SecWebSocketKey)
        b.append(HttpHeaders.SecWebSocketKey, Base64.encode(Random.nextBytes(16)))
        return b.build()
    }

    /**
     * Headers of the 101 that Ktor produced which the `:status 200` leaves out: `Sec-WebSocket-Accept` (RFC 8441 section
     * 5), and `content-length`, which a 2xx to CONNECT never carries (RFC 9110 section 9.3.6); the connection-specific
     * ones go anyway (RFC 9113 section 8.2.2).
     */
    val DROPPED: Set<String> = setOf("sec-websocket-accept", "content-length")
}

/**
 * The response of a WebSocket-over-HTTP/2 call: the upgrade is answered `:status 200`, then Ktor's session reads the
 * client's DATA (checked frame by frame against the negotiated extensions, RFC 6455 section 5.2) and writes its frames
 * as DATA within the client's windows, each wait for window bounded by [sendStallMillis]. The session's end is the
 * stream's END_STREAM (RFC 8441 section 5: "Orderly TCP-level closures are represented as END_STREAM flags"); a call
 * cancelled or failed meanwhile resets the stream with CANCEL ("RST exceptions are represented with the RST_STREAM frame
 * ... with the CANCEL error code").
 */
internal class H2UpgradeResponse(
    call: PipelineCall,
    h2: H2ServerStream,
    sendStallMillis: Long,
    private val engineDispatcher: CoroutineContext,
    private val userDispatcher: CoroutineContext,
    /** The engine's `webSocketMaxMessageSize`: the largest WebSocket message a client may send (RFC 6455 section 10.4). */
    private val webSocketMaxMessageSize: Long = DEFAULT_WEBSOCKET_MAX_MESSAGE_SIZE,
) : H2Response(call, h2, sendStallMillis, altSvc = { null }) {
    override suspend fun respondOutgoingContent(content: OutgoingContent) {
        // before anything is committed, so the refusal can still be an ordinary error response: a handshake without one
        // sec-websocket-version 13 gets 400 with `sec-websocket-version: 13` instead of the upgrade (RFC 8441 section 5,
        // RFC 6455 section 4.2.1). As over HTTP/3 (`http3 = true`: no key to check, RFC 8441 section 5, and no 426,
        // whose Upgrade field RFC 9110 section 15.5.22 requires and RFC 9113 section 8.2.2 forbids)
        if (content is OutgoingContent.ProtocolUpgrade) {
            webSocketHandshakeRefusal(call.request.headers, http3 = true)?.let { return super.respondOutgoingContent(it.content) }
            checkWebSocketRsvConflicts(call.attributes)
        }
        super.respondOutgoingContent(content)
    }

    /**
     * A 2xx that does not come from the upgrade (a route other than `webSocket` answered the CONNECT) would tell the client
     * a WebSocket is open that nobody accepted (RFC 9110 section 9.3.6: "Any 2xx (Successful) response indicates that the
     * sender ... will switch to tunnel mode"): it is answered 501, as an Extended CONNECT for a protocol the server does
     * not serve. The upgrade's own 101 and errors pass as they are.
     */
    override fun setStatus(statusCode: HttpStatusCode) {
        super.setStatus(if (statusCode.value in 200..299) HttpStatusCode.NotImplemented else statusCode)
    }

    override suspend fun respondUpgrade(upgrade: OutgoingContent.ProtocolUpgrade) {
        if (!headersBuilder.contains(HttpHeaders.Date)) headersBuilder.append(HttpHeaders.Date, httpDateNow())
        h2.respond(200, fields().filter { it.first !in WebSocketOverH2.DROPPED }, endStream = false)
        markAnswered()
        val output = ByteChannel()
        // the frames go out as DATA within the client's windows; the channel's end is the stream's END_STREAM, its failure
        // (the session failed) a RST_STREAM CANCEL
        val sender =
            CoroutineScope(call.coroutineContext).launch {
                try {
                    h2.sendBody(output, end = true, stallMillis = sendStallMillis, stallError = {
                        IOException("the client took no WebSocket frames for $sendStallMillis ms")
                    })
                } catch (e: Throwable) {
                    output.cancel(e)
                }
            }
        // the frames are checked against the extensions negotiated here (RFC 6455 section 5.2, RFC 8441 section 5); the
        // check ends with the upgrade
        val guard = Job()
        var webSocket: ServerWebSocket? = null
        try {
            val input =
                startServerWebSocket(
                    h2.body,
                    call.request.headers,
                    headersBuilder,
                    call.attributes,
                    engineDispatcher + guard,
                    webSocketMaxMessageSize,
                    output,
                    call.application.environment.log,
                ) ?: return // a Close with 1011 went out instead (the finally ends the stream after it)
            webSocket = input
            // the server's frames go out unmasked, checked as they leave (RFC 6455 section 5.1, the text and compression rules)
            upgrade.upgrade(input.channel, input.output(output), engineDispatcher, userDispatcher).join()
        } finally {
            webSocket?.done()
            guard.cancel()
            // a call cancelled while the session ran cannot end the stream in order: CANCEL both ways (RFC 8441 section 5).
            // Otherwise the session's output ends the stream: END_STREAM once its last frames went out, then the client's
            // END_STREAM is waited for (CLOSE_WAIT), so an orderly close ends with both flags and no RST_STREAM; a client
            // that has not ended by then is stopped when the stream is released (RST_STREAM NO_ERROR after our END_STREAM,
            // RFC 9113 section 8.1)
            if (!currentCoroutineContext().isActive) {
                sender.cancel()
                runCatching { h2.reset(Http2ErrorCode.CANCEL) }
            } else {
                runCatching { output.flushAndClose() }
                try {
                    sender.join()
                    withTimeoutOrNull(WebSocketOverH2.CLOSE_WAIT) { h2.awaitClientEnd() }
                } catch (e: CancellationException) {
                    // cancelled while the last frames waited for window
                    withContext(NonCancellable) { runCatching { h2.reset(Http2ErrorCode.CANCEL) } }
                    throw e
                }
            }
        }
    }
}
