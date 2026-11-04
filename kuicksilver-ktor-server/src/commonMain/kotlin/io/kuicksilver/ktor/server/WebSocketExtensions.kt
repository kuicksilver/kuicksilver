// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.http.Headers
import io.ktor.http.HeadersBuilder
import io.ktor.http.HttpHeaders
import io.ktor.util.Attributes
import io.ktor.utils.io.ByteReadChannel
import io.kuicksilver.ktor.network.guardWebSocketInput
import io.kuicksilver.ktor.network.negotiatedWebSocketRsv
import io.kuicksilver.ktor.network.webSocketExtensionNames
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.ktor.network.websocket.perMessageDeflate
import kotlin.coroutines.CoroutineContext

/**
 * The RSV bits a client's WebSocket frames may set: the extensions of its upgrade [request] that Ktor's `WebSockets`
 * plugin accepted in the [response] (both `Sec-WebSocket-Extensions`); none without extensions (RFC 6455 section 5.2).
 */
internal fun webSocketRsv(
    request: Headers,
    response: HeadersBuilder,
): Int =
    negotiatedWebSocketRsv(
        webSocketExtensionNames(request.getAll(HttpHeaders.SecWebSocketExtensions).orEmpty()),
        webSocketExtensionNames(response.getAll(HttpHeaders.SecWebSocketExtensions).orEmpty()),
    )

/**
 * The input of a WebSocket upgrade, checked frame by frame against what the handshake ([request] and [response])
 * negotiated (RFC 6455 section 5.2), and decompressed there when the call's [attributes] hold a negotiated
 * [PerMessageDeflate] (RFC 7692 section 7.2.2, a message over its limit closed with 1009). [done] frees that extension's
 * zlib state when the session has ended.
 */
internal class ServerWebSocketInput(
    input: ByteReadChannel,
    request: Headers,
    response: HeadersBuilder,
    attributes: Attributes,
    context: CoroutineContext,
) {
    private val deflate: PerMessageDeflate? = attributes.perMessageDeflate()

    val channel: ByteReadChannel =
        guardWebSocketInput(
            input,
            webSocketRsv(request, response),
            untilClose = false,
            peerMasks = true,
            context = context,
            inflate = deflate?.serverInflate(),
        )

    fun done() {
        deflate?.dispose()
    }
}
