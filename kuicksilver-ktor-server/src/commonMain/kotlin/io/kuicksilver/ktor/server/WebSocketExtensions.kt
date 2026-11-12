// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.http.ContentType
import io.ktor.http.Headers
import io.ktor.http.HeadersBuilder
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.http.headersOf
import io.ktor.http.withCharset
import io.ktor.util.Attributes
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.charsets.Charsets
import io.ktor.utils.io.writeFully
import io.ktor.websocket.ProtocolViolationException
import io.kuicksilver.ktor.network.SentCompression
import io.kuicksilver.ktor.network.guardWebSocketInput
import io.kuicksilver.ktor.network.guardWebSocketOutput
import io.kuicksilver.ktor.network.negotiatedPerMessageDeflate
import io.kuicksilver.ktor.network.negotiatedWebSocketRsv
import io.kuicksilver.ktor.network.webSocketExtensionNames
import io.kuicksilver.ktor.network.webSocketTextCheckable
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.ktor.network.websocket.negotiatedWebSocketInflate
import io.kuicksilver.ktor.network.websocket.perMessageDeflate
import io.kuicksilver.ktor.network.websocket.sentCompression
import io.kuicksilver.ktor.network.websocket.webSocketExtensions
import io.kuicksilver.ktor.network.websocket.webSocketRsvConflict
import kotlin.coroutines.CoroutineContext
import kotlin.io.encoding.Base64

/**
 * The two directions of a WebSocket upgrade, checked against what the handshake ([request] and [response]) negotiated.
 * [channel] is the input: checked frame by frame (RFC 6455 section 5.2) and against [maxMessageSize] (section 10.4),
 * its text and Close reasons checked as UTF-8 (section 8.1), and permessage-deflate messages decompressed there,
 * whichever extension negotiated it (RFC 7692 section 7.2.2: the call's [attributes] hold this library's
 * [PerMessageDeflate], or another one such as Ktor's, read from the answer); see `guardWebSocketInput`. [output] wraps
 * the output: no frame of the server is masked, whatever Ktor's `WebSockets { masking }` says (RFC 6455 section 5.1: "A
 * server MUST NOT mask any frames that it sends to the client"), no Close goes out with a code an endpoint must not send
 * (section 7.4.1) and no text that is not UTF-8 (section 5.6); see `guardWebSocketOutput`. [done] frees the extension's
 * zlib state when the session has ended.
 */
internal class ServerWebSocket(
    input: ByteReadChannel,
    request: Headers,
    response: HeadersBuilder,
    attributes: Attributes,
    context: CoroutineContext,
    maxMessageSize: Long,
) {
    private val deflate: PerMessageDeflate? = attributes.perMessageDeflate()
    private val checkText: Boolean
    private val sentCompression: SentCompression

    val channel: ByteReadChannel

    init {
        val offered = webSocketExtensionNames(request.getAll(HttpHeaders.SecWebSocketExtensions).orEmpty())
        val answer = response.getAll(HttpHeaders.SecWebSocketExtensions).orEmpty()
        val accepted = webSocketExtensionNames(answer)
        val perMessageDeflate = negotiatedPerMessageDeflate(offered, accepted)
        val own = deflate?.serverInflate()
        val inflate = own ?: if (perMessageDeflate) negotiatedWebSocketInflate(answer, client = false, Long.MAX_VALUE) else null
        checkText = webSocketTextCheckable(offered, accepted)
        sentCompression = sentCompression(attributes.webSocketExtensions(), perMessageDeflate)
        channel =
            guardWebSocketInput(
                input,
                negotiatedWebSocketRsv(offered, accepted, attributes.webSocketExtensions()),
                untilClose = false,
                peerMasks = true,
                context = context,
                inflate = inflate,
                perMessageDeflate = perMessageDeflate,
                maxMessageSize = maxMessageSize,
                checkText = checkText,
            )
    }

    /** The upgrade's [output], as the frames must go out; [onClose] runs once the server's own Close was written. */
    fun output(
        output: ByteWriteChannel,
        onClose: () -> Unit = {},
    ): ByteWriteChannel = guardWebSocketOutput(output, masking = false, checkText, sentCompression, onClose)

    fun done() {
        deflate?.dispose()
    }
}

/**
 * [ServerWebSocket] for an upgrade whose 101 (or RFC 9220 2xx) already went out; null when the engine cannot read that
 * answer's own `Sec-WebSocket-Extensions` (an extension's answer that is not RFC 7692's): the session cannot be checked,
 * so it does not start. In its place the client gets a Close frame with 1011 (RFC 6455 section 7.4.1: "an unexpected
 * condition that prevented it from fulfilling the request") on [output], and [log] a warning, instead of a connection
 * that ends without a word.
 */
internal suspend fun startServerWebSocket(
    input: ByteReadChannel,
    request: Headers,
    response: HeadersBuilder,
    attributes: Attributes,
    context: CoroutineContext,
    maxMessageSize: Long,
    output: ByteWriteChannel,
    log: io.ktor.util.logging.Logger,
): ServerWebSocket? =
    try {
        ServerWebSocket(input, request, response, attributes, context, maxMessageSize)
    } catch (e: ProtocolViolationException) {
        log.warn("WebSocket upgrade: the answer's Sec-WebSocket-Extensions cannot be read (${e.message}); closing with 1011")
        output.writeFully(byteArrayOf(0x88.toByte(), 0x02, 0x03, 0xF3.toByte()))
        output.flush()
        null
    }

/**
 * Refuses a WebSocket upgrade whose negotiated extensions (in the call's [attributes]) claim the same RSV bit, before
 * anything of the answer is sent: RFC 7692 section 5, a server MUST NOT accept a PMCE together with another extension
 * that uses RSV1. Ktor's plugin accepts every installed extension that agrees on its own; the call fails with
 * [IllegalStateException] (Ktor answers 500), which names the extensions.
 */
internal fun checkWebSocketRsvConflicts(attributes: Attributes) {
    webSocketRsvConflict(attributes.webSocketExtensions())?.let {
        throw IllegalStateException(
            "WebSocket extensions that share an RSV bit were negotiated, which a server must not accept (RFC 7692 section 5): $it; " +
                "install only one of them",
        )
    }
}

/**
 * The error response that replaces the application's WebSocket upgrade when the client's opening handshake [request] does
 * not match RFC 6455 section 4.2.1, or null when it does. "The server MUST stop processing the client's handshake and
 * return an HTTP response with an appropriate error code (such as 400 Bad Request)": over HTTP/1.1, unless there is
 * exactly one `Sec-WebSocket-Key` (section 11.3.1: it MUST NOT appear more than once) whose value decodes from base64 to
 * 16 bytes (item 5); and, on both protocols, unless there is exactly one `Sec-WebSocket-Version` (section 11.3.5).
 * A version other than 13 is one this server does not understand (section 4.2.2, /version/): it "MUST abort the
 * WebSocket handshake ... and instead send an appropriate HTTP error code (such as 426 Upgrade Required) and a
 * |Sec-WebSocket-Version| header field indicating the version(s) the server is capable of understanding": 426 over
 * HTTP/1.1 (`WebSocketRefusal.upgradeRequired`; RFC 9110 section 15.5.22 then needs an `Upgrade` field, which the
 * engine adds), 400 over HTTP/2 and HTTP/3, which have no `Upgrade` (RFC 9113 section 8.2.2, RFC 9114 section 4.2).
 * Every refusal carries `Sec-WebSocket-Version: 13`. Over HTTP/2 and HTTP/3 ([http3]; RFC 8441 section 5, RFC 9220)
 * the key is not processed; the version is used "as defined in RFC 6455".
 */
internal fun webSocketHandshakeRefusal(
    request: Headers,
    http3: Boolean,
): WebSocketRefusal? {
    if (!http3) {
        val keys = request.getAll(HttpHeaders.SecWebSocketKey).orEmpty()
        if (keys.size != 1) return WebSocketRefusal(HttpStatusCode.BadRequest, "${keys.size} Sec-WebSocket-Key fields, not one")
        val decoded = runCatching { Base64.decode(keys[0].trim()) }.getOrNull()
        if (decoded?.size != 16) {
            return WebSocketRefusal(HttpStatusCode.BadRequest, "a Sec-WebSocket-Key that is not 16 bytes in base64")
        }
    }
    val versions = request.getAll(HttpHeaders.SecWebSocketVersion).orEmpty()
    if (versions.size != 1) return WebSocketRefusal(HttpStatusCode.BadRequest, "${versions.size} Sec-WebSocket-Version fields, not one")
    if (versions[0].trim() != WEBSOCKET_VERSION) {
        return WebSocketRefusal(
            if (http3) HttpStatusCode.BadRequest else HttpStatusCode.UpgradeRequired,
            "WebSocket version ${versions[0].trim()}; this server speaks version $WEBSOCKET_VERSION",
        )
    }
    return null
}

/** A WebSocket opening handshake the server refuses with [status] ([webSocketHandshakeRefusal]) because of [problem]. */
internal class WebSocketRefusal(
    val status: HttpStatusCode,
    problem: String,
) {
    /** A 426 names the protocol to upgrade to in an `Upgrade` field (RFC 9110 section 15.5.22). */
    val upgradeRequired: Boolean get() = status == HttpStatusCode.UpgradeRequired

    /** The response: [status], `Sec-WebSocket-Version: 13`, and a short text. */
    val content: OutgoingContent =
        object : OutgoingContent.ByteArrayContent() {
            private val text = "Invalid WebSocket handshake (RFC 6455 section 4.2.1): $problem\n".encodeToByteArray()
            override val status: HttpStatusCode = this@WebSocketRefusal.status
            override val headers: Headers = headersOf(HttpHeaders.SecWebSocketVersion, WEBSOCKET_VERSION)
            override val contentType: ContentType = ContentType.Text.Plain.withCharset(Charsets.UTF_8)
            override val contentLength: Long = text.size.toLong()

            override fun bytes(): ByteArray = text
        }
}

/** RFC 6455 section 4.1: the version of the protocol this server speaks. */
private const val WEBSOCKET_VERSION = "13"
