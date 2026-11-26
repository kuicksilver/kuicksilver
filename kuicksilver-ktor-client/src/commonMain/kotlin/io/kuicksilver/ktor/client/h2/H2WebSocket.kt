// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    io.kuicksilver.annotations.InternalKuicksilverApi::class,
    io.kuicksilver.annotations.ExperimentalKuicksilverApi::class,
    kotlin.concurrent.atomics.ExperimentalAtomicApi::class,
)

package io.kuicksilver.ktor.client.h2

import io.ktor.client.plugins.websocket.WEBSOCKETS_KEY
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HeadersBuilder
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.HttpStatusCode
import io.ktor.http.isSecure
import io.ktor.util.date.GMTDate
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.discard
import io.ktor.websocket.RawWebSocket
import io.kuicksilver.http2.runtime.H2ClientStream
import io.kuicksilver.http2.runtime.H2StreamOutput
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.ktor.client.EngineEvents
import io.kuicksilver.ktor.client.HeldTransportEnd
import io.kuicksilver.ktor.client.WEBSOCKET_CLOSE_WAIT_MILLIS
import io.kuicksilver.ktor.client.WebSocketLifetime
import io.kuicksilver.ktor.client.h3.H3Pool
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.authority
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.h3Path
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.headersOf
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.unwrap
import io.kuicksilver.ktor.client.priority
import io.kuicksilver.ktor.client.socketTimeoutMillis
import io.kuicksilver.ktor.client.webSocketAfterHandshake
import io.kuicksilver.ktor.client.withSocketTimeout
import io.kuicksilver.ktor.network.WebSocketPongs
import io.kuicksilver.ktor.network.guardWebSocketInput
import io.kuicksilver.ktor.network.guardWebSocketOutput
import io.kuicksilver.ktor.network.isAtWebSocketFrameBoundary
import io.kuicksilver.tls.completedWithin
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.CoroutineContext
import kotlin.time.Duration.Companion.milliseconds

/** The upgrade token of RFC 8441 section 5 (`:protocol`). */
private const val WEBSOCKET = "websocket"

/**
 * A WebSocket over HTTP/2 (RFC 8441) on a stream of [conn], reserved by the caller on a connection whose server enabled
 * Extended CONNECT (section 3): CONNECT with `:protocol = websocket`, `:scheme` `https` (a `wss` URI, section 5), the
 * WebSocket URI's path and authority, and the handshake's other fields (Sec-WebSocket-Version, -Protocol, -Extensions,
 * Origin, cookies). A 2xx answer opens the session on the stream, reported as 101 so Ktor's plugin accepts it, after the
 * answer's extensions and subprotocol were checked against the offer (RFC 6455 section 4.1); any other answer is an
 * ordinary response, whose status fails Ktor's handshake as an HTTP/1.1 answer without 101 does.
 *
 * The session's frames go out as DATA within the server's windows and come in through the stream's own window (flow
 * control follows the session's reading, RFC 9113 section 5.2). The stream ends as RFC 8441 section 5 maps RFC 6455's TCP
 * close onto it ("Orderly TCP-level closures are represented as END_STREAM flags ... RST exceptions are represented with
 * the RST_STREAM frame ... with the CANCEL error code"), in the order RFC 6455 section 7.1.1 wants of a client, the
 * server's first ("when a client is instructed to do the same, it SHOULD wait for a TCP Close from the server"; RFC 9113
 * section 8.5: "A client is expected to send a DATA frame with the END_STREAM flag set after receiving a frame with the
 * END_STREAM flag set"). A session that ended in order (both Closes) keeps its END_STREAM back until the server's
 * END_STREAM, whatever the server still sends being read and dropped, at most T2 ([WebSocketLifetime]: the close wait from
 * the session's end); then sends it. A server still silent at T2 gets END_STREAM then, and the stream is reset with CANCEL
 * only when its END_STREAM has not come one more close wait later. Anything else (a failed or cancelled call, a handshake
 * refused here, a session without the server's Close within the close wait from its own, T1) resets the stream with
 * CANCEL.
 *
 * Throws [H2NotProcessed] when the server provably did not process the CONNECT, [H2Http11Required] for
 * HTTP_1_1_REQUIRED (the caller then opens the WebSocket over HTTP/1.1), as [h2Exchange] does.
 */
@OptIn(InternalAPI::class)
internal suspend fun h2WebSocket(
    conn: H2Conn,
    data: HttpRequestData,
    callContext: CoroutineContext,
    events: EngineEvents,
    closeWaitMillis: Long = WEBSOCKET_CLOSE_WAIT_MILLIS,
    /** The engine's `webSocketMaxMessageSize` (RFC 6455 section 10.4). */
    maxMessageSize: Long = io.kuicksilver.ktor.network.DEFAULT_WEBSOCKET_MAX_MESSAGE_SIZE,
    /** Tests: the session's output, once it exists. */
    onOutput: (H2StreamOutput) -> Unit = {},
    /** Tests: the stream waits for the server's END_STREAM ("waiting"); ours is about to go after it ("server ended") or at T2 ("T2"). */
    webSocketClosingForTest: (String) -> Unit = {},
    /** Tests: runs once the server's end (its END_STREAM or reset) was read, still inside T2. */
    serverEndForTest: (suspend () -> Unit)? = null,
    onReleased: (kept: Boolean) -> Unit,
): HttpResponseData {
    val requestTime = GMTDate()
    val url = data.url
    // RFC 8441 section 5: "Implementations using this extended CONNECT to bootstrap WebSockets do not do the processing of
    // the Sec-WebSocket-Key and Sec-WebSocket-Accept header fields", as RFC 9220 (WS_HOP_BY_HOP); `connection`, `upgrade`
    // and `host` ("MUST NOT be included in the CONNECT request") are connection-specific and never sent ([headersOf])
    val fields =
        headersOf(data, data.body.unwrap()).fields.filter { it.first !in H3Pool.WS_HOP_BY_HOP } +
            listOfNotNull(
                data.priority
                    ?.let {
                        io.kuicksilver.http3.message.PriorityField
                            .format(it)
                    }?.let { "priority" to it },
            )
    val scheme = if (url.protocol.isSecure()) "https" else "http"
    val stream: H2ClientStream =
        try {
            conn.client.open(
                "CONNECT",
                scheme,
                url.authority(),
                url.h3Path(),
                fields,
                endStream = false,
                protocol = WEBSOCKET,
                neverIndexed = data.attributes.getOrNull(io.kuicksilver.ktor.client.NeverIndexKey).orEmpty(),
            )
        } catch (e: Http2Exception) {
            onReleased(conn.client.isUsable)
            if (e.notProcessed) throw H2NotProcessed(e, bodyConsumed = false)
            throw e
        } catch (e: Throwable) {
            onReleased(conn.client.isUsable)
            throw e
        }
    val released = kotlin.concurrent.atomics.AtomicBoolean(false)

    fun release() {
        if (!released.compareAndSet(false, true)) return
        try {
            stream.release()
        } finally {
            // a release that throws gave the stream back all the same: connectionReleased goes out for it too
            onReleased(conn.client.isUsable)
        }
    }
    val job = callContext[Job]
    if (job == null) {
        val e = IllegalStateException("a call without a Job")
        releaseUnder(events, stream, e) { release() }
        throw e
    }
    var made: WebSocketLifetime? = null
    try {
        val head = stream.response()
        if (head.neverIndexed.isNotEmpty()) data.attributes.put(io.kuicksilver.ktor.client.NeverIndexedReceivedKey, head.neverIndexed)
        val headers = HeadersBuilder().apply { for ((n, v) in head.fields) append(n, v) }.build()
        if (head.status !in 200..299) {
            // RFC 9110 section 9.3.6: only a 2xx switches to tunnel mode; the rest is a response like any other, read until
            // the call ends
            job.invokeOnCompletion { releaseLogged(events, stream) { release() } }
            val status = HttpStatusCode.fromValue(head.status)
            return HttpResponseData(
                status,
                requestTime,
                headers,
                HttpProtocolVersion.HTTP_2_0,
                stream.body.withSocketTimeout(data),
                callContext,
            )
        }

        // RFC 6455 section 4.1 (RFC 8441 section 5 keeps it): an extension or a subprotocol the client did not offer fails
        // the WebSocket connection before a session opens; the stream is reset below
        fun values(name: String) = head.fields.filter { it.first == name }.map { it.second }
        // the session runs under a job of its own, so that a Close it queued is written even when the call is cancelled
        // right after (Ktor's webSocketSession() always ends so; WebSocketLifetime); the extensions' state lives as long
        val lifetime = WebSocketLifetime(data, callContext, closeWaitMillis)
        made = lifetime
        val handshake =
            webSocketAfterHandshake(data, values("sec-websocket-extensions"), values("sec-websocket-protocol"), lifetime.context)
        // the frames go out within the server's windows, at most H2StreamOutput.DEFAULT_LIMIT ahead of the stream (the
        // session's writer waits beyond that, RFC 9113 section 5.2); a stream that fails under the session (a reset, the
        // connection, the socket timeout while it waits for window) fails the session's writes with it
        val output =
            H2StreamOutput(CoroutineScope(callContext.minusKey(Job) + CoroutineName("kuicksilver-h2-websocket"))) { source, end ->
                stream.sendBody(source, end, data.socketTimeoutMillis()) {
                    io.ktor.client.plugins
                        .SocketTimeoutException(data, null)
                }
            }
        onOutput(output)
        val sender = output.done
        // the server's Close arrived (the input ends there) or its side of the stream ended
        val serverClosing = CompletableDeferred<Unit>()
        // the session's channel to the stream: its end (END_STREAM) is sent here, after the session, in the order above
        val held = HeldTransportEnd(output)

        // RFC 6455 section 7.1.1: once the client sent its Close it may close when the server does not close "in a
        // reasonable time period": the session's own Close starts the close wait (T1, WebSocketLifetime), and a session
        // still without the server's Close then is cancelled, which resets the stream with CANCEL below (OkHttp cancels its
        // WebSocket 60 s after its Close). The lead is released as at the server's Close: the Close must not wait behind a
        // window the server may never open again
        fun onOwnClose() {
            output.releaseLead()
        }
        var guard: io.ktor.utils.io.ByteWriteChannel? = null
        lifetime.invokeOnEnd { cause ->
            // a call that failed or was cancelled before the session's own Close, or a session cut at T1 or failed, is
            // reset with CANCEL at once; so is one whose frame guard is inside a frame (a writer that ended says nothing:
            // Ktor's ends its channel in order also when cancelled inside a frame), never ended with END_STREAM
            if (cause != null || !held.endRequested || output.closedCause != null || guard?.isAtWebSocketFrameBoundary() != true) {
                sender.cancel()
                releaseLogged(events, stream) { release() }
                return@invokeOnEnd
            }
            try {
                // T2: the server's END_STREAM (what it still sends after its Close is read and dropped), then ours
                webSocketClosingForTest("waiting")
                // an end read as T2 fires is the end: dropped, a reset stream got END_STREAM and a further close wait
                val serverEnded =
                    completedWithin(lifetime.remainingTransportWaitMillis().milliseconds) {
                        serverClosing.await()
                        discardToEnd(stream.body)
                        stream.awaitServerEnd().also { serverEndForTest?.invoke() }
                    }
                if (serverEnded != false) {
                    webSocketClosingForTest(if (serverEnded == true) "server ended" else "T2")
                    output.flushAndClose()
                    // after T2 the server has one close wait more to end its side, then the stream is reset with CANCEL
                    withTimeoutOrNull(lifetime.closeWait) {
                        sender.join()
                        if (serverEnded == null) {
                            discardToEnd(stream.body)
                            stream.awaitServerEnd()
                        }
                    }
                }
            } finally {
                sender.cancel()
                releaseLogged(events, stream) { release() }
            }
        }
        val pongs = WebSocketPongs() // the engine answers Pings itself (RFC 6455 section 5.5.2)
        val raw =
            RawWebSocket(
                // the input ends at the server's Close (or with the stream): the session is closing, and its last frames, its
                // Close reply among them, must not wait for a window the server may never open again; the close wait bounds
                // them from there (RFC 6455 section 7.1.1)
                guardWebSocketInput(
                    stream.body,
                    handshake.allowedRsv,
                    untilClose = true,
                    peerMasks = false,
                    context = lifetime.context,
                    inflate = handshake.inflate,
                    perMessageDeflate = handshake.perMessageDeflate,
                    maxMessageSize = maxMessageSize,
                    checkText = handshake.checkText,
                    onEnd = {
                        output.releaseLead()
                        serverClosing.complete(Unit)
                    },
                    pongs = pongs,
                ),
                // Ktor writes unmasked frames; the guard masks each with a key from the CSPRNG (RFC 6455 section 5.3)
                // its own Close is also seen here, once written, whichever way it was sent (see WebSocketLifetime.watch)
                guardWebSocketOutput(
                    held,
                    masking = true,
                    handshake.checkText,
                    handshake.sentCompression,
                    onClose = ::onOwnClose,
                    pongs = pongs,
                ).also { guard = it },
                masking = false,
                coroutineContext = lifetime.context,
                channelsConfig = data.attributes[WEBSOCKETS_KEY].channelsConfig,
            )
        val session = lifetime.watch(raw, ::onOwnClose)
        return HttpResponseData(HttpStatusCode.SwitchingProtocols, requestTime, headers, HttpProtocolVersion.HTTP_2_0, session, callContext)
    } catch (e: Throwable) {
        made?.abandon(e) // nothing waits for a session that was never made
        releaseUnder(events, stream, e) { release() } // the handshake fails with e (or goes again for it) whatever the release throws
        if (e !is Http2Exception) throw e
        if (e.notProcessed) throw H2NotProcessed(e, bodyConsumed = false)
        if (isHttp11Required(e, conn)) throw H2Http11Required(e, bodyConsumed = false, mayRepeat = true)
        throw e
    }
}

/** HTTP_1_1_REQUIRED on this stream or for the whole connection (RFC 9113 section 7), as [h2Exchange] reads it. */
private fun isHttp11Required(
    e: Http2Exception,
    conn: H2Conn,
): Boolean =
    (e is Http2Exception.StreamReset && e.byPeer && e.code == io.kuicksilver.http2.Http2ErrorCode.HTTP_1_1_REQUIRED) ||
        (
            (e is Http2Exception.StreamReset || e is Http2Exception.ConnectionClosed) &&
                conn.client.goAwayCode == io.kuicksilver.http2.Http2ErrorCode.HTTP_1_1_REQUIRED
        )

/** Reads and drops [input] to its end; a failed input (a reset) ends it too. */
private suspend fun discardToEnd(input: io.ktor.utils.io.ByteReadChannel) {
    try {
        input.discard()
    } catch (e: kotlinx.coroutines.CancellationException) {
        throw e
    } catch (_: Throwable) {
        // the stream failed: awaitServerEnd says so
    }
}
