// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class, io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client.h2

import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.client.request.ResponseAdapterAttributeKey
import io.ktor.http.HeadersBuilder
import io.ktor.http.HttpMethod
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.HttpStatusCode
import io.ktor.util.date.GMTDate
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.runtime.H2ClientStream
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.http3.message.PriorityField
import io.kuicksilver.ktor.client.Activity
import io.kuicksilver.ktor.client.ConsumedBody
import io.kuicksilver.ktor.client.EngineEvents
import io.kuicksilver.ktor.client.h1.CONTINUE_TIMEOUT
import io.kuicksilver.ktor.client.h1.expectsContinue
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.authority
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.bodyChannel
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.h3Path
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.headersOf
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.isReplayable
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.unwrap
import io.kuicksilver.ktor.client.priority
import io.kuicksilver.ktor.client.socketTimeoutMillis
import io.kuicksilver.ktor.client.withSocketInactivityTimeout
import io.kuicksilver.ktor.client.withSocketTimeout
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlin.coroutines.CoroutineContext

/** The server did not process the request ([cause] says how): it may go again on another connection (RFC 9113 section 8.7). */
internal class H2NotProcessed(
    override val cause: Http2Exception,
    /** A body that cannot be produced again was (partly) taken: the request cannot go again. */
    val bodyConsumed: Boolean,
) : Exception(cause.message, cause)

/** The server asked for HTTP/1.1 (HTTP_1_1_REQUIRED, RFC 9113 section 7). */
internal class H2Http11Required(
    override val cause: Http2Exception,
    /** As [H2NotProcessed.bodyConsumed]. */
    val bodyConsumed: Boolean,
) : Exception(cause.message, cause)

/** Whether [e] is the server's HTTP_1_1_REQUIRED, on the stream or for the whole connection. */
internal fun isHttp11Required(e: Http2Exception): Boolean =
    when (e) {
        is Http2Exception.StreamReset -> e.byPeer && e.code == Http2ErrorCode.HTTP_1_1_REQUIRED
        is Http2Exception.ConnectionClosed -> e.byPeer && e.code == Http2ErrorCode.HTTP_1_1_REQUIRED
        else -> false
    }

/**
 * The request's regular fields for HTTP/2 (RFC 9113 section 8.2): lowercase names, no connection-specific fields and no
 * `host` (`:authority` carries it, section 8.3.1), `content-length` when the body knows its length; the request's own
 * priority as the end-to-end `priority` field (RFC 9218 section 5; ADR-0017: no PRIORITY_UPDATE and no RFC 7540
 * priorities on HTTP/2).
 */
private fun h2Fields(data: HttpRequestData): List<Pair<String, String>> {
    val fields = headersOf(data, data.body.unwrap()).fields
    val p = data.priority?.let { PriorityField.format(it) } ?: return fields
    return fields + ("priority" to p)
}

/**
 * One exchange on a stream of [conn] (reserved by the caller, which also emitted `connectionAcquired`). The request body
 * goes in its own coroutine while the response head is awaited, within the server's flow-control windows; the socket
 * timeout covers both as inactivity (a body that keeps moving never times out) and bounds every wait for window after
 * that. The stream is released when the call ends (its body read or abandoned): an unfinished one is reset with CANCEL.
 *
 * Throws [H2NotProcessed] when the server provably did not process the request (only after the body could be sent
 * again) and [H2Http11Required] for HTTP_1_1_REQUIRED; any other failure is the call's.
 */
@OptIn(InternalAPI::class, DelicateCoroutinesApi::class)
internal suspend fun h2Exchange(
    conn: H2Conn,
    data: HttpRequestData,
    callContext: CoroutineContext,
    events: EngineEvents,
    onReleased: (kept: Boolean) -> Unit,
): HttpResponseData {
    val requestTime = GMTDate()
    val url = data.url
    val body = data.body.unwrap()
    val hasBody = body !is io.ktor.http.content.OutgoingContent.NoContent && body !is io.ktor.http.content.OutgoingContent.ProtocolUpgrade
    val stream: H2ClientStream =
        try {
            conn.client.open(data.method.value, url.protocol.name, url.authority(), url.h3Path(), h2Fields(data), endStream = !hasBody)
        } catch (e: Http2Exception) {
            onReleased(conn.client.isUsable)
            if (e.notProcessed) throw H2NotProcessed(e, bodyConsumed = false)
            throw e
        } catch (e: Throwable) {
            onReleased(conn.client.isUsable)
            throw e
        }
    val job = callContext[Job]
    if (job == null) {
        stream.release()
        onReleased(conn.client.isUsable)
        throw IllegalStateException("a call without a Job")
    }
    // in use until the call ends (its body read or abandoned), not just until the response head
    job.invokeOnCompletion {
        stream.release()
        onReleased(conn.client.isUsable)
    }
    val activity = data.socketTimeoutMillis()?.let { Activity() }
    var bodyStarted = false
    try {
        val head =
            withSocketInactivityTimeout(data, activity, onExpiry = { stream.cancel() }) {
                if (hasBody) {
                    // RFC 9110 section 10.1.1: with `Expect: 100-continue` the body waits for an answer, at most CONTINUE_TIMEOUT
                    if (expectsContinue(data)) stream.awaitAnswer(CONTINUE_TIMEOUT.inWholeMilliseconds)
                    // a final response that came first does not want the body: the stream is reset when the call ends
                    if (!stream.hasResponse) {
                        bodyStarted = true
                        val source = bodyChannel(body, callContext)
                        if (source != null) {
                            val counted = activity?.let { ConsumedBody(source, it) } ?: source
                            GlobalScope
                                .launch(callContext.minusKey(Job) + CoroutineName("kuicksilver-h2-request-body")) {
                                    try {
                                        stream.sendBody(counted, data.socketTimeoutMillis()) {
                                            io.ktor.client.plugins
                                                .SocketTimeoutException(data, null)
                                        }
                                    } catch (e: CancellationException) {
                                        throw e
                                    } catch (e: Throwable) {
                                        // the stream is reset with it, so the response read fails with it too (unless it was complete)
                                        runCatching {
                                            if (events.logger.isEnabled(io.kuicksilver.quic.LogLevel.Debug)) {
                                                events.logger.log(
                                                    io.kuicksilver.quic.LogLevel.Debug,
                                                    "HTTP/2 request body of stream ${stream.id} failed",
                                                    e,
                                                )
                                            }
                                        }
                                    }
                                }.also { sender -> job.invokeOnCompletion { sender.cancel() } }
                        }
                    }
                }
                stream.response()
            }
        val status = HttpStatusCode.fromValue(head.status)
        val headers = HeadersBuilder().apply { for ((n, v) in head.fields) append(n, v) }.build()
        val noBody = data.method == HttpMethod.Head || status == HttpStatusCode.NoContent || status == HttpStatusCode.NotModified
        val bodyChannel: ByteReadChannel = if (noBody) ByteReadChannel.Empty else stream.body.withSocketTimeout(data)
        val responseBody: Any =
            data.attributes.getOrNull(ResponseAdapterAttributeKey)?.adapt(data, status, headers, bodyChannel, data.body, callContext)
                ?: bodyChannel
        return HttpResponseData(status, requestTime, headers, HttpProtocolVersion.HTTP_2_0, responseBody, callContext)
    } catch (e: Http2Exception) {
        val consumed = bodyStarted && !body.isReplayable()
        // on the stream, or for the whole connection: a GOAWAY with HTTP_1_1_REQUIRED reports the streams above its last
        // one as refused (not processed), and those below it as lost with the connection
        if (isHttp11Required(e) || conn.client.goAwayCode == Http2ErrorCode.HTTP_1_1_REQUIRED) throw H2Http11Required(e, consumed)
        // REFUSED_STREAM twice on one connection retires it (OkHttp RealConnection.trackFailure)
        if (e is Http2Exception.StreamReset && e.byPeer && e.code == Http2ErrorCode.REFUSED_STREAM && ++conn.refusedStreams >= 2) {
            conn.client.shutdown()
        }
        if (e.notProcessed) throw H2NotProcessed(e, consumed)
        throw e
    }
}
