// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.http.Headers
import io.ktor.http.HeadersBuilder
import io.ktor.http.HttpHeaders
import io.kuicksilver.ktor.network.negotiatedWebSocketRsv
import io.kuicksilver.ktor.network.webSocketExtensionNames

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
