// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server.h3

import io.ktor.http.Headers
import io.ktor.http.HeadersBuilder
import io.ktor.http.content.OutgoingContent
import io.ktor.server.application.PipelineCall
import io.ktor.utils.io.cancel
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.ktor.network.guardWebSocketInput
import io.kuicksilver.ktor.server.webSocketRsv
import kotlinx.coroutines.Job
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

    /** Headers of the 101 that Ktor produced, minus what RFC 9220 section 3 leaves out of the `:status 200` answer. */
    val DROPPED: Set<String> = setOf("connection", "upgrade", "sec-websocket-accept", "transfer-encoding", "keep-alive", "proxy-connection")
}

/** The response of a WebSocket-over-HTTP/3 call: the upgrade becomes `acceptConnect()` and the stream carries the frames. */
internal class H3UpgradeResponse(
    call: PipelineCall,
    h3: Http3ServerRequest,
    private val engineDispatcher: CoroutineContext,
    private val userDispatcher: CoroutineContext,
) : H3Response(call, h3) {
    override suspend fun respondUpgrade(upgrade: OutgoingContent.ProtocolUpgrade) {
        val headers = Http3Headers(h3Headers().fields.filter { it.first !in WebSocketOverH3.DROPPED })
        val stream = h3.acceptConnect(headers)
        // the frames are checked against the extensions negotiated here (RFC 6455 section 5.2, RFC 9220 section 3); the
        // check ends with the upgrade
        val guard = Job()
        try {
            val allowedRsv = webSocketRsv(call.request.headers, headersBuilder)
            val input =
                guardWebSocketInput(
                    stream.input,
                    allowedRsv,
                    untilClose = false,
                    peerMasks = true,
                    context =
                        engineDispatcher + guard,
                )
            upgrade.upgrade(input, stream.output, engineDispatcher, userDispatcher).join()
        } finally {
            guard.cancel()
            stream.output.flushAndClose()
            stream.input.cancel()
        }
    }
}
