// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.plugins.websocket.WebSocketException
import io.ktor.client.request.HttpRequestData
import io.ktor.http.HttpHeaders
import io.kuicksilver.ktor.network.negotiatedWebSocketRsv
import io.kuicksilver.ktor.network.webSocketExtensionNames

/**
 * The RSV bits the server's frames may set after the WebSocket handshake of [request], whose answer carried
 * [responseExtensions] (the `Sec-WebSocket-Extensions` values of the 101, or of the 2xx of RFC 9220). An extension the
 * request did not offer fails the handshake with [WebSocketException] (RFC 6455 section 4.1: the client fails the
 * connection), before a session is opened.
 */
internal fun webSocketRsvAfterHandshake(
    request: HttpRequestData,
    responseExtensions: List<String>,
): Int {
    val offered = webSocketExtensionNames(request.headers.getAll(HttpHeaders.SecWebSocketExtensions).orEmpty())
    val accepted = webSocketExtensionNames(responseExtensions)
    val unoffered = accepted.filter { it !in offered }
    if (unoffered.isNotEmpty()) {
        throw WebSocketException(
            "Handshake exception: the server accepted WebSocket extensions the client did not offer " +
                "(RFC 6455 section 4.1): ${unoffered.joinToString()}",
        )
    }
    return negotiatedWebSocketRsv(offered, accepted)
}
