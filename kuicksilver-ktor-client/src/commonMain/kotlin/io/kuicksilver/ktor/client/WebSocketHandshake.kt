// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.plugins.websocket.WebSocketException
import io.ktor.client.request.HttpRequestData
import io.ktor.http.HttpHeaders
import io.ktor.websocket.ProtocolViolationException
import io.kuicksilver.ktor.network.negotiatedWebSocketRsv
import io.kuicksilver.ktor.network.webSocketExtensionNames
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.ktor.network.websocket.WebSocketInflate
import io.kuicksilver.ktor.network.websocket.webSocketExtensions
import io.kuicksilver.ktor.network.websocket.webSocketRsvConflict
import kotlinx.coroutines.Job
import kotlin.coroutines.CoroutineContext

/**
 * What the server's frames may carry after a WebSocket handshake: the RSV bits ([allowedRsv]) and, with the engine's
 * own [io.kuicksilver.ktor.network.websocket.PerMessageDeflate] negotiated, how the frame guard decompresses them
 * ([inflate]).
 */
internal class WebSocketHandshake(
    val allowedRsv: Int,
    val inflate: WebSocketInflate?,
)

/**
 * What the server's frames may carry after the WebSocket handshake of [request], whose answer carried [responseExtensions]
 * (the `Sec-WebSocket-Extensions` values of the 101, or of the 2xx of RFC 9220). An extension the request did not offer
 * fails the handshake with [WebSocketException] (RFC 6455 section 4.1: the client fails the connection), before a
 * session is opened; so does an answer to `PerMessageDeflate`'s offer that RFC 7692 section 5 makes the client fail, and
 * one that accepts two installed extensions claiming the same RSV bit (section 5: a PMCE and another user of RSV1).
 * The extension's zlib state is freed when the call ([callContext]) ends.
 */
internal fun webSocketAfterHandshake(
    request: HttpRequestData,
    responseExtensions: List<String>,
    callContext: CoroutineContext,
): WebSocketHandshake {
    val offered = webSocketExtensionNames(request.headers.getAll(HttpHeaders.SecWebSocketExtensions).orEmpty())
    val accepted = webSocketExtensionNames(responseExtensions)
    val unoffered = accepted.filter { it !in offered }
    if (unoffered.isNotEmpty()) {
        throw WebSocketException(
            "Handshake exception: the server accepted WebSocket extensions the client did not offer " +
                "(RFC 6455 section 4.1): ${unoffered.joinToString()}",
        )
    }
    val allowedRsv = negotiatedWebSocketRsv(offered, accepted)
    val installed = request.attributes.webSocketExtensions()
    val inUse = installed.filter { e -> e.protocols.any { it.name.trim().lowercase() in accepted } }
    webSocketRsvConflict(inUse)?.let {
        throw WebSocketException(
            "Handshake exception: the server accepted WebSocket extensions that share an RSV bit (RFC 7692 section 5): $it",
        )
    }
    val deflate = installed.firstNotNullOfOrNull { it as? PerMessageDeflate } ?: return WebSocketHandshake(allowedRsv, inflate = null)
    val inflate =
        try {
            deflate.clientInflate(responseExtensions)
        } catch (e: ProtocolViolationException) {
            throw WebSocketException("Handshake exception: ${e.message}", e)
        }
    callContext[Job]?.invokeOnCompletion { deflate.dispose() }
    return WebSocketHandshake(allowedRsv, inflate)
}
