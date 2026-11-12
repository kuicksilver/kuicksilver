// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.plugins.websocket.WebSocketException
import io.ktor.client.request.HttpRequestData
import io.ktor.http.Headers
import io.ktor.http.HttpHeaders
import io.ktor.http.websocket.websocketServerAccept
import io.ktor.websocket.ProtocolViolationException
import io.kuicksilver.ktor.network.SentCompression
import io.kuicksilver.ktor.network.negotiatedPerMessageDeflate
import io.kuicksilver.ktor.network.negotiatedWebSocketRsv
import io.kuicksilver.ktor.network.webSocketExtensionNames
import io.kuicksilver.ktor.network.webSocketTextCheckable
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.ktor.network.websocket.WebSocketInflate
import io.kuicksilver.ktor.network.websocket.negotiatedWebSocketInflate
import io.kuicksilver.ktor.network.websocket.sentCompression
import io.kuicksilver.ktor.network.websocket.webSocketExtensions
import io.kuicksilver.ktor.network.websocket.webSocketRsvConflict
import io.kuicksilver.tls.KslCrypto
import kotlinx.coroutines.Job
import kotlin.coroutines.CoroutineContext
import kotlin.io.encoding.Base64

/**
 * What the frames may carry after a WebSocket handshake: the RSV bits of the server's ([allowedRsv]; [perMessageDeflate]
 * when RFC 7692 section 6.1 governs RSV1), whether text is checked as UTF-8 ([checkText]), how the frame guard
 * decompresses the server's permessage-deflate messages ([inflate], whichever extension negotiated it), and how the
 * client's own messages are compressed, for the output guard ([sentCompression]).
 */
internal class WebSocketHandshake(
    val allowedRsv: Int,
    val perMessageDeflate: Boolean,
    val checkText: Boolean,
    val inflate: WebSocketInflate?,
    val sentCompression: SentCompression,
)

/**
 * A new `Sec-WebSocket-Key` (RFC 6455 section 4.1: "a randomly selected 16-byte value that has been base64-encoded"; "The
 * nonce MUST be selected randomly for each connection"), from OpenSSL's CSPRNG. The engine draws one for every attempt
 * to connect, so a request sent again (a followed redirect, a retry on a new connection) never repeats the key of
 * Ktor's request body.
 */
internal fun newWebSocketKey(): String = Base64.encode(KslCrypto.randomBytes(16))

/**
 * RFC 6455 section 4.1, steps 2 to 4 of the client's check of the server's 101 over HTTP/1.1, for a request sent with
 * [key]: an `Upgrade` field whose value is `websocket` (ASCII case-insensitive), a `Connection` field with the token
 * `Upgrade` (the same), and exactly one `Sec-WebSocket-Accept` (section 11.3.3: it MUST NOT appear more than once) whose
 * value, without leading and trailing whitespace, is the base64-encoded SHA-1 of [key] and the GUID
 * `258EAFA5-E914-47DA-95CA-C5AB0DC85B11`. Anything else fails the handshake with [WebSocketException] ("the client MUST
 * _Fail the WebSocket Connection_"), before a session is opened. Over HTTP/3 (RFC 9220, RFC 8441 section 5) none of
 * these fields exists.
 */
internal fun checkWebSocketUpgrade(
    key: String,
    headers: Headers,
) {
    val upgrade = headers.getAll(HttpHeaders.Upgrade).orEmpty()
    if (upgrade.size != 1 || !upgrade[0].trim().equals("websocket", ignoreCase = true)) {
        handshakeFailure("the 101 response's Upgrade is ${upgrade.describe()}, not websocket (RFC 6455 section 4.1)")
    }
    val connection =
        headers
            .getAll(HttpHeaders.Connection)
            .orEmpty()
            .flatMap { it.split(',') }
            .map { it.trim() }
    if (connection.none { it.equals("upgrade", ignoreCase = true) }) {
        handshakeFailure("the 101 response's Connection has no Upgrade token (RFC 6455 section 4.1)")
    }
    val accept = headers.getAll(HttpHeaders.SecWebSocketAccept).orEmpty()
    if (accept.size != 1) {
        handshakeFailure("the 101 response has ${accept.size} Sec-WebSocket-Accept fields, not one (RFC 6455 sections 4.1, 11.3.3)")
    }
    if (accept[0].trim() != websocketServerAccept(key)) {
        handshakeFailure("the 101 response's Sec-WebSocket-Accept does not answer the request's key (RFC 6455 section 4.1)")
    }
}

/**
 * What the server's frames may carry after the WebSocket handshake of [request], whose answer carried
 * [responseExtensions] and [responseProtocols] (the `Sec-WebSocket-Extensions` and `Sec-WebSocket-Protocol` values of the
 * 101, or of the 2xx of RFC 9220, where RFC 8441 section 5 keeps both "as defined in [RFC6455]"). Fails the handshake
 * with [WebSocketException] (RFC 6455 section 4.1: the client fails the connection), before a session is opened, when
 * the answer has more than one of either field (section 11.3: they MUST NOT appear more than once in a response), an
 * extension the request did not offer (step 5), or a subprotocol the request did not offer (step 6), more than one
 * included; also for an answer to `PerMessageDeflate`'s offer that RFC 7692 section 7 makes the client fail, and one that
 * accepts two installed extensions claiming the same RSV bit (section 5: a PMCE and another user of RSV1). The
 * extension's zlib state is freed when the call ([callContext]) ends.
 */
internal fun webSocketAfterHandshake(
    request: HttpRequestData,
    responseExtensions: List<String>,
    responseProtocols: List<String>,
    callContext: CoroutineContext,
): WebSocketHandshake {
    if (responseExtensions.size > 1) {
        handshakeFailure(
            "the response has ${responseExtensions.size} Sec-WebSocket-Extensions fields, not at most one (RFC 6455 section 11.3.2)",
        )
    }
    checkSubprotocol(request, responseProtocols)
    val offered = webSocketExtensionNames(request.allHeaders(HttpHeaders.SecWebSocketExtensions))
    val accepted = webSocketExtensionNames(responseExtensions)
    val unoffered = accepted.filter { it !in offered }
    if (unoffered.isNotEmpty()) {
        handshakeFailure(
            "the server accepted WebSocket extensions the client did not offer (RFC 6455 section 4.1): ${unoffered.joinToString()}",
        )
    }
    val installed = request.attributes.webSocketExtensions()
    val allowedRsv = negotiatedWebSocketRsv(offered, accepted, installed)
    val perMessageDeflate = negotiatedPerMessageDeflate(offered, accepted)
    val inUse = installed.filter { e -> e.protocols.any { it.name.trim().lowercase() in accepted } }
    webSocketRsvConflict(inUse)?.let {
        handshakeFailure("the server accepted WebSocket extensions that share an RSV bit (RFC 7692 section 5): $it")
    }
    val deflate = installed.firstNotNullOfOrNull { it as? PerMessageDeflate }
    // permessage-deflate is decompressed by the engine whichever extension negotiated it (RFC 7692 section 6): this
    // library's with its own limit and checks, another one (Ktor's) by the parameters of the answer
    val inflate =
        try {
            when {
                deflate != null && perMessageDeflate -> deflate.clientInflate(responseExtensions)
                perMessageDeflate -> negotiatedWebSocketInflate(responseExtensions, client = true, maxMessageSize = Long.MAX_VALUE)
                else -> null
            }
        } catch (e: ProtocolViolationException) {
            throw WebSocketException("Handshake exception: ${e.message}", e)
        }
    if (deflate != null) callContext[Job]?.invokeOnCompletion { deflate.dispose() }
    val checkText = webSocketTextCheckable(offered, accepted)
    return WebSocketHandshake(allowedRsv, perMessageDeflate, checkText, inflate, sentCompression(installed, perMessageDeflate))
}

/** RFC 6455 section 4.1 step 6 and section 11.3.4: at most one subprotocol in the answer, and one the client offered. */
private fun checkSubprotocol(
    request: HttpRequestData,
    responseProtocols: List<String>,
) {
    if (responseProtocols.isEmpty()) return
    if (responseProtocols.size > 1) {
        handshakeFailure(
            "the response has ${responseProtocols.size} Sec-WebSocket-Protocol fields, not at most one (RFC 6455 section 11.3.4)",
        )
    }
    val chosen = responseProtocols[0].trim()
    val offered =
        request
            .allHeaders(
                HttpHeaders.SecWebSocketProtocol,
            ).flatMap { it.split(',') }
            .map { it.trim() }
            .filter { it.isNotEmpty() }
    if (chosen !in offered) {
        handshakeFailure(
            "the server chose the subprotocol \"$chosen\", which the client did not offer (RFC 6455 section 4.1)" +
                if (offered.isEmpty()) "" else ": ${offered.joinToString()}",
        )
    }
}

/** The values of [name] the request carries, from its headers and from its body's (Ktor puts some fields on the body). */
private fun HttpRequestData.allHeaders(name: String): List<String> = headers.getAll(name).orEmpty() + body.headers.getAll(name).orEmpty()

private fun List<String>.describe(): String = if (isEmpty()) "missing" else joinToString(prefix = "\"", postfix = "\"")

private fun handshakeFailure(what: String): Nothing = throw WebSocketException("Handshake exception: $what")
