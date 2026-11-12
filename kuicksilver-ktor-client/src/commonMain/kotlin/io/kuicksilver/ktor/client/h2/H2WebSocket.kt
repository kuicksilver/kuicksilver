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
import io.ktor.websocket.Frame
import io.ktor.websocket.RawWebSocket
import io.ktor.websocket.WebSocketSession
import io.kuicksilver.http2.runtime.H2ClientStream
import io.kuicksilver.http2.runtime.H2StreamOutput
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.ktor.client.EngineEvents
import io.kuicksilver.ktor.client.h3.H3Pool
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.authority
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.h3Path
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.headersOf
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.unwrap
import io.kuicksilver.ktor.client.priority
import io.kuicksilver.ktor.client.socketTimeoutMillis
import io.kuicksilver.ktor.client.webSocketAfterHandshake
import io.kuicksilver.ktor.client.withSocketTimeout
import io.kuicksilver.ktor.network.guardWebSocketInput
import io.kuicksilver.ktor.network.guardWebSocketOutput
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.ChannelResult
import kotlinx.coroutines.channels.SendChannel
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.CoroutineContext

/** The upgrade token of RFC 8441 section 5 (`:protocol`). */
private const val WEBSOCKET = "websocket"

/**
 * How long a WebSocket whose session ended in order (its Close sent, its output closed) waits for its last frames and
 * END_STREAM to go out and for the server's END_STREAM before the stream is reset: RFC 6455 section 7.1.1, the client
 * "SHOULD wait for the server to close the connection but MAY close the connection at any time after sending and
 * receiving a Close message, e.g., if it has not received a TCP Close from the server in a reasonable time period".
 */
internal const val H2_WEBSOCKET_CLOSE_WAIT_MILLIS: Long = 5_000

/**
 * A WebSocket over HTTP/2 (RFC 8441) on a stream of [conn], reserved by the caller on a connection whose server enabled
 * Extended CONNECT (section 3): CONNECT with `:protocol = websocket`, `:scheme` `https` (a `wss` URI, section 5), the
 * WebSocket URI's path and authority, and the handshake's other fields (Sec-WebSocket-Version, -Protocol, -Extensions,
 * Origin, cookies). A 2xx answer opens the session on the stream, reported as 101 so Ktor's plugin accepts it, after the
 * answer's extensions and subprotocol were checked against the offer (RFC 6455 section 4.1); any other answer is an
 * ordinary response, whose status fails Ktor's handshake as an HTTP/1.1 answer without 101 does.
 *
 * The session's frames go out as DATA within the server's windows and come in through the stream's own window (flow
 * control follows the session's reading, RFC 9113 section 5.2). When the call ends, a session that ended in order has its
 * END_STREAM out and waits up to [closeWaitMillis] (5 s) for its last frames to go out and the server's; anything else (a failed or cancelled call, a handshake
 * refused here) resets the stream with CANCEL (section 5: "RST exceptions are represented with the RST_STREAM frame ...
 * with the CANCEL error code"). A close the client starts is bounded as well: [closeWaitMillis] from the session's own
 * Close, a server that sent neither its Close nor END_STREAM has the stream reset with CANCEL (RFC 6455 section 7.1.1).
 *
 * Throws [H2NotProcessed] when the server provably did not process the CONNECT, [H2Http11Required] for
 * HTTP_1_1_REQUIRED (the caller then opens the WebSocket over HTTP/1.1), as [h2Exchange] does.
 */
@OptIn(InternalAPI::class, DelicateCoroutinesApi::class)
internal suspend fun h2WebSocket(
    conn: H2Conn,
    data: HttpRequestData,
    callContext: CoroutineContext,
    events: EngineEvents,
    closeWaitMillis: Long = H2_WEBSOCKET_CLOSE_WAIT_MILLIS,
    /** The engine's `webSocketMaxMessageSize` (RFC 6455 section 10.4). */
    maxMessageSize: Long = io.kuicksilver.ktor.network.DEFAULT_WEBSOCKET_MAX_MESSAGE_SIZE,
    /** Tests: the session's output, once it exists. */
    onOutput: (H2StreamOutput) -> Unit = {},
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
            conn.client.open("CONNECT", scheme, url.authority(), url.h3Path(), fields, endStream = false, protocol = WEBSOCKET)
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
        stream.release()
        onReleased(conn.client.isUsable)
    }
    val job = callContext[Job]
    if (job == null) {
        release()
        throw IllegalStateException("a call without a Job")
    }
    try {
        val head = stream.response()
        val headers = HeadersBuilder().apply { for ((n, v) in head.fields) append(n, v) }.build()
        if (head.status !in 200..299) {
            // RFC 9110 section 9.3.6: only a 2xx switches to tunnel mode; the rest is a response like any other, read until
            // the call ends
            job.invokeOnCompletion { release() }
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
        val handshake =
            webSocketAfterHandshake(data, values("sec-websocket-extensions"), values("sec-websocket-protocol"), callContext)
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
        val ownClose = kotlin.concurrent.atomics.AtomicBoolean(false)

        // RFC 6455 section 7.1.1: once the client sent its Close it may close "at any time after sending ... a Close
        // message" when the server does not close "in a reasonable time period": the close wait starts with the session's
        // own Close, and a server that answers neither with its Close nor with END_STREAM by then has the stream reset with
        // CANCEL, which ends the session's input and the call (OkHttp cancels its WebSocket 60 s after its Close). The lead
        // is released as at the server's Close: the Close must not wait behind a window the server may never open again
        fun onOwnClose() {
            if (!ownClose.compareAndSet(false, true)) return
            output.releaseLead()
            if (serverClosing.isCompleted) return
            GlobalScope.launch(callContext.minusKey(Job) + CoroutineName("kuicksilver-h2-websocket-close")) {
                val answered =
                    withTimeoutOrNull(closeWaitMillis) {
                        select {
                            serverClosing.onAwait { true }
                            job.onJoin { true } // the call ended: its own handler decides
                        }
                    }
                if (answered == null) {
                    sender.cancel()
                    release()
                }
            }
        }
        job.invokeOnCompletion { cause ->
            // a session that ended in order closed its output: its last frames and END_STREAM go out, and the server's
            // END_STREAM is waited for (RFC 6455 section 7.1.1); a call that failed or was cancelled (its output may still
            // have been closed without a cause) is reset with CANCEL at once
            if (cause != null || !output.isClosedForWrite || output.closedCause != null) {
                sender.cancel()
                release()
                return@invokeOnCompletion
            }
            // one bound for both: the last frames may wait for a window the server never opens again
            GlobalScope.launch(callContext.minusKey(Job) + CoroutineName("kuicksilver-h2-websocket-close")) {
                try {
                    withTimeoutOrNull(closeWaitMillis) {
                        sender.join()
                        stream.awaitServerEnd()
                    }
                } finally {
                    sender.cancel()
                    release()
                }
            }
        }
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
                    context = callContext,
                    inflate = handshake.inflate,
                    perMessageDeflate = handshake.perMessageDeflate,
                    maxMessageSize = maxMessageSize,
                    checkText = handshake.checkText,
                    onEnd = {
                        output.releaseLead()
                        serverClosing.complete(Unit)
                    },
                ),
                // Ktor writes unmasked frames; the guard masks each with a key from the CSPRNG (RFC 6455 section 5.3)
                // its own Close is also seen here, once written, whichever way it was sent (see OwnCloseWatch)
                guardWebSocketOutput(output, masking = true, handshake.checkText, handshake.sentCompression, onClose = ::onOwnClose),
                masking = false,
                coroutineContext = callContext,
                channelsConfig = data.attributes[WEBSOCKETS_KEY].channelsConfig,
            )
        val session = OwnCloseWatch(raw, ::onOwnClose)
        return HttpResponseData(HttpStatusCode.SwitchingProtocols, requestTime, headers, HttpProtocolVersion.HTTP_2_0, session, callContext)
    } catch (e: Throwable) {
        release()
        if (e !is Http2Exception) throw e
        if (e.notProcessed) throw H2NotProcessed(e, bodyConsumed = false)
        if (isHttp11Required(e, conn)) throw H2Http11Required(e, bodyConsumed = false, mayRepeat = true)
        throw e
    }
}

/**
 * [raw] with its outgoing frames watched: [onClose] runs when the session sends its own Close (Ktor's session sends it
 * through [outgoing], its `close()` through [send]), before the Close is queued behind the frames ahead of it. Every send
 * path of the channel is watched but `onSend`, a select clause, which cannot be wrapped without kotlinx.coroutines'
 * internal API (Ktor's sessions never select on it). A Close sent that way is still seen when it is written: the output
 * guard calls [onClose] too, only later if the writer is held behind a frame larger than the lead.
 */
private class OwnCloseWatch(
    private val raw: WebSocketSession,
    private val onClose: () -> Unit,
) : WebSocketSession by raw {
    override val outgoing: SendChannel<Frame> =
        object : SendChannel<Frame> by raw.outgoing {
            override suspend fun send(element: Frame) {
                if (element is Frame.Close) onClose()
                raw.outgoing.send(element)
            }

            override fun trySend(element: Frame): ChannelResult<Unit> {
                if (element is Frame.Close) onClose()
                return raw.outgoing.trySend(element)
            }

            @Deprecated("Use trySend", level = DeprecationLevel.ERROR)
            @Suppress("DEPRECATION_ERROR", "OVERRIDE_DEPRECATION")
            override fun offer(element: Frame): Boolean {
                if (element is Frame.Close) onClose()
                return raw.outgoing.offer(element)
            }
        }

    override suspend fun send(frame: Frame) {
        outgoing.send(frame)
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
