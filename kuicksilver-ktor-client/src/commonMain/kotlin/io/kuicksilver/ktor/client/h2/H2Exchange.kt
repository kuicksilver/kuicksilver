// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    io.kuicksilver.annotations.InternalKuicksilverApi::class,
    io.kuicksilver.annotations.ExperimentalKuicksilverApi::class,
    kotlin.concurrent.atomics.ExperimentalAtomicApi::class,
)

package io.kuicksilver.ktor.client.h2

import io.ktor.client.plugins.ConnectTimeoutException
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
import io.kuicksilver.ktor.client.NeverIndexKey
import io.kuicksilver.ktor.client.NeverIndexedReceivedKey
import io.kuicksilver.ktor.client.PriorityUpdater
import io.kuicksilver.ktor.client.PriorityUpdaterKey
import io.kuicksilver.ktor.client.h1.CONTINUE_TIMEOUT
import io.kuicksilver.ktor.client.h1.expectsContinue
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.authority
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.bodyChannel
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.h3Path
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.headersOf
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.isReplayable
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.unwrap
import io.kuicksilver.ktor.client.isIdempotent
import io.kuicksilver.ktor.client.priority
import io.kuicksilver.ktor.client.socketTimeoutMillis
import io.kuicksilver.ktor.client.withSocketInactivityTimeout
import io.kuicksilver.ktor.client.withSocketTimeout
import io.kuicksilver.quic.StreamPriority
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
    /**
     * The request may go again over HTTP/1.1: the server provably did not process it, or it is idempotent with a body
     * that can be sent again (RFC 9110 section 9.2.2), whether the server answered on its stream (RST_STREAM) or for the
     * whole connection (GOAWAY). Otherwise the call fails with [io.kuicksilver.ktor.client.Http11RequiredException]; the
     * route is marked either way.
     */
    val mayRepeat: Boolean,
) : Exception(cause.message, cause)

/** The server reset this stream with HTTP_1_1_REQUIRED. */
private fun isStreamHttp11Required(e: Http2Exception): Boolean =
    e is Http2Exception.StreamReset && e.byPeer && e.code == Http2ErrorCode.HTTP_1_1_REQUIRED

/** The request's priority: [priority] (the builder's), else a valid raw `Priority` header, else the defaults. */
private fun localPriority(data: HttpRequestData): StreamPriority =
    data.priority
        ?: data.headers
            .getAll("Priority")
            ?.joinToString(", ")
            ?.takeIf { PriorityField.isSignal(it) }
            ?.let { PriorityField.parse(it) }
        ?: StreamPriority.Default

/**
 * The request's regular fields for HTTP/2 (RFC 9113 section 8.2): lowercase names, no connection-specific fields and no
 * `host` (`:authority` carries it, section 8.3.1), `content-length` when the body knows its length; the request's own
 * priority as the end-to-end `priority` field (RFC 9218 section 5; the core adds the RFC 7540 signal of section 2.1.1).
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
    // the request's own priority: its DATA (RFC 9218 section 9) and the RFC 7540 signal before the server's SETTINGS (2.1.1)
    val local = localPriority(data)
    val stream: H2ClientStream =
        try {
            conn.client.open(
                data.method.value,
                url.protocol.name,
                url.authority(),
                url.h3Path(),
                h2Fields(data),
                endStream = !hasBody,
                urgency = local.urgency,
                incremental = local.incremental,
                neverIndexed = data.attributes.getOrNull(NeverIndexKey).orEmpty(),
            )
        } catch (e: Http2Exception) {
            onReleased(conn.client.isUsable)
            if (e.notProcessed) throw H2NotProcessed(e, bodyConsumed = false)
            throw e
        } catch (e: Throwable) {
            onReleased(conn.client.isUsable)
            throw e
        }
    // the stream (and its reservation) goes back once: when the call ends, or at once when this attempt fails, so a
    // repeat never waits for the stream or the connection its own first attempt still holds
    // for HttpResponse.updatePriority: our own DATA follows the new priority in any case (as over HTTP/3), and the server
    // gets the signals it uses (RFC 9218 section 2.1.1: PRIORITY_UPDATE, an RFC 7540 PRIORITY frame, or both)
    data.attributes.put(
        PriorityUpdaterKey,
        PriorityUpdater { p ->
            stream.setPriority(p.urgency, p.incremental)
            stream.priorityUpdate(PriorityField.format(p) ?: "u=3", p.urgency)
        },
    )
    val released = kotlin.concurrent.atomics.AtomicBoolean(false)
    var sender: Job? = null

    fun release() {
        if (!released.compareAndSet(false, true)) return
        sender?.cancel()
        stream.release()
        onReleased(conn.client.isUsable)
    }
    val job = callContext[Job]
    if (job == null) {
        release()
        throw IllegalStateException("a call without a Job")
    }
    // in use until the call ends (its body read or abandoned), not just until the response head
    job.invokeOnCompletion { release() }
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
                            sender =
                                GlobalScope
                                    .launch(callContext.minusKey(Job) + CoroutineName("kuicksilver-h2-request-body")) {
                                        try {
                                            stream.sendBody(counted, stallMillis = data.socketTimeoutMillis()) {
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
                                    }
                        }
                    }
                }
                stream.response()
            }
        val status = HttpStatusCode.fromValue(head.status)
        val headers = HeadersBuilder().apply { for ((n, v) in head.fields) append(n, v) }.build()
        if (head.neverIndexed.isNotEmpty()) data.attributes.put(NeverIndexedReceivedKey, head.neverIndexed)
        val noBody = data.method == HttpMethod.Head || status == HttpStatusCode.NoContent || status == HttpStatusCode.NotModified
        val bodyChannel: ByteReadChannel = if (noBody) ByteReadChannel.Empty else stream.body.withSocketTimeout(data)
        val responseBody: Any =
            data.attributes.getOrNull(ResponseAdapterAttributeKey)?.adapt(data, status, headers, bodyChannel, data.body, callContext)
                ?: bodyChannel
        return HttpResponseData(status, requestTime, headers, HttpProtocolVersion.HTTP_2_0, responseBody, callContext)
    } catch (e: Throwable) {
        release() // this attempt is over: its stream must not hold the connection or a stream slot for the repeat
        if (e !is Http2Exception) throw e
        // RFC 9113 section 3.4: the request's HEADERS went out before the server's preface, which never came within the
        // connect timeout (the connection ended with SETTINGS_TIMEOUT). A request without content, or whose content had not
        // started, fails as a connect timeout (HttpRequestRetry may send it again: a server that never spoke HTTP/2 to us
        // took nothing more than its head); one whose content had started fails with the connection's end itself, so that
        // nothing takes it for a request that never left
        if (conn.client.serverPrefaceMissed && stream.openedBeforeServerSettings && !bodyStarted) {
            throw ConnectTimeoutException(data, e)
        }
        val consumed = bodyStarted && !body.isReplayable()
        // on the stream, or for the whole connection: a GOAWAY with HTTP_1_1_REQUIRED reports the streams above its last
        // one as refused (not processed), and those up to it as lost with the connection: those may have been processed
        // (RFC 9113 section 8.7) and go again only when that is safe anyway. Only a reset or a lost connection counts: a
        // malformed or too large response on such a connection is the response's failure.
        val onStream = isStreamHttp11Required(e)
        val onConnection =
            (e is Http2Exception.StreamReset || e is Http2Exception.ConnectionClosed) &&
                conn.client.goAwayCode == Http2ErrorCode.HTTP_1_1_REQUIRED
        if (onStream || onConnection) {
            // RFC 9110 section 9.2.2 (owner decision 2026-11-05): even a reset of our own stream does not prove the server
            // did not act on the request, so a POST is not sent twice behind the application's back
            val mayRepeat = e.notProcessed || (data.method.isIdempotent() && body.isReplayable())
            throw H2Http11Required(e, consumed, mayRepeat)
        }
        // REFUSED_STREAM twice on one connection retires it (OkHttp RealConnection.trackFailure); the streams a GOAWAY
        // refuses are not counted (the connection is going away already, and one GOAWAY may refuse many), nor the stream
        // opened before the server's SETTINGS (RFC 9113 section 3.4): it went out before the server's limit was known, and
        // section 5.1.2 lets the server refuse it under a limit of 0
        if (e is Http2Exception.StreamReset && e.byPeer && e.code == Http2ErrorCode.REFUSED_STREAM && conn.client.goAwayCode == null &&
            !stream.openedBeforeServerSettings &&
            conn.refusedStreams.addAndFetch(1) >= 2
        ) {
            conn.client.shutdown()
        }
        if (e.notProcessed) throw H2NotProcessed(e, consumed)
        throw e
    }
}
