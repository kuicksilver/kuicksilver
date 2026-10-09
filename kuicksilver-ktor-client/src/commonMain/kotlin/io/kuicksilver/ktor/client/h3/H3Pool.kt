// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h3

import io.ktor.client.engine.mergeHeaders
import io.ktor.client.plugins.ConnectTimeoutException
import io.ktor.client.plugins.SocketTimeoutException
import io.ktor.client.plugins.websocket.WEBSOCKETS_KEY
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.client.request.ResponseAdapterAttributeKey
import io.ktor.http.HeadersBuilder
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.http.fullPath
import io.ktor.http.hostWithPort
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.util.date.GMTDate
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.writer
import io.ktor.websocket.RawWebSocket
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3Request
import io.kuicksilver.http3.Http3Response
import io.kuicksilver.ktor.client.H3BodyConsumed
import io.kuicksilver.ktor.client.KuicksilverEngineConfig
import io.kuicksilver.ktor.client.connectTimeoutMillis
import io.kuicksilver.ktor.client.socketTimeoutMillis
import io.kuicksilver.ktor.client.tlsConfigFor
import io.kuicksilver.ktor.client.withSocketTimeout
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlin.coroutines.CoroutineContext

/** Where an HTTP/3 request goes: the origin (for `:authority`, SNI and verification) and the UDP endpoint (origin or alternative). */
internal class H3Target(
    val originHost: String,
    val host: String,
    val port: Int,
) {
    val key: String get() = "$originHost|$host:$port"
}

/** A failure that happened before the request could have reached the server: safe to repeat on HTTP/1.1. */
internal class H3NotSent(
    cause: Throwable,
) : Exception(cause.message, cause)

/** HTTP/3 connections of one engine: one client endpoint, one connection per (origin, alternative) reused while it is open. */
@OptIn(InternalAPI::class)
internal class H3Pool(
    private val config: KuicksilverEngineConfig,
) {
    private val lock = Mutex()
    private var endpoint: Http3Endpoint? = null
    private val connections = HashMap<String, CompletableDeferred<Http3Connection>>()

    private suspend fun endpoint(): Http3Endpoint =
        lock.withLock {
            endpoint
                ?: Http3Endpoint.bind(InetSocketAddress("0.0.0.0", 0), config.http3.endpoint, config.http3.settings).also { endpoint = it }
        }

    fun close() {
        endpoint?.close()
        endpoint = null
    }

    /** An open connection to [t], connecting (once, shared by concurrent callers) when needed. */
    suspend fun connection(
        t: H3Target,
        data: HttpRequestData,
    ): Http3Connection {
        val ep = endpoint()
        val (d, connect) =
            lock.withLock {
                val existing = connections[t.key]
                if (existing != null &&
                    !(
                        existing.isCompleted &&
                            existing.getCompletedOrNull()?.let { it.closed.isCompleted || it.goAwayReceived.value != null } == true
                    )
                ) {
                    existing to
                        false
                } else {
                    CompletableDeferred<Http3Connection>().also { connections[t.key] = it } to true
                }
            }
        if (connect) {
            try {
                val c =
                    withTimeout(data.connectTimeoutMillis(config)) {
                        ep.connect(
                            InetSocketAddress(t.host, t.port),
                            config.tlsConfigFor(t.originHost, listOf(Http3Endpoint.H3)),
                            config.quic,
                            config.http3.settings,
                        )
                    }
                d.complete(c)
            } catch (
                e: TimeoutCancellationException,
            ) {
                val x = ConnectTimeoutException(data, e)
                d.completeExceptionally(x)
                forget(t, d)
            } catch (
                e: CancellationException,
            ) {
                d.cancel(e)
                forget(t, d)
                throw e
            } catch (e: Throwable) {
                d.completeExceptionally(e)
                forget(t, d)
            }
        }
        return d.await()
    }

    /** The open, usable connection to [t], if one exists (no connection attempt). */
    suspend fun existing(t: H3Target): Http3Connection? =
        lock.withLock { connections[t.key] }?.getCompletedOrNull()?.takeIf {
            !it.closed.isCompleted &&
                it.goAwayReceived.value == null
        }

    /** Whether an open connection to [t] exists and its peer accepts Extended CONNECT (WebSockets over HTTP/3, RFC 9220). */
    suspend fun canConnectProtocol(t: H3Target): Boolean =
        lock.withLock { connections[t.key] }?.getCompletedOrNull()?.let {
            !it.closed.isCompleted &&
                it.peerSettings.value?.enableConnectProtocol == true
        } ==
            true

    private suspend fun forget(
        t: H3Target,
        d: CompletableDeferred<Http3Connection>,
    ) = lock.withLock {
        if (connections[t.key] ===
            d
        ) {
            connections.remove(t.key)
        }
    }

    /**
     * One exchange over HTTP/3. Requests the server did not process (GOAWAY, H3_REQUEST_REJECTED) are repeated on a new
     * connection, at most twice. Failures before the request could reach the server are [H3NotSent].
     */
    suspend fun execute(
        t: H3Target,
        data: HttpRequestData,
        callContext: CoroutineContext,
        extraHeaders: List<Pair<String, String>> = emptyList(),
    ): HttpResponseData {
        var attempts = 0
        while (true) {
            val conn =
                try {
                    connection(t, data)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    throw H3NotSent(e)
                }
            try {
                return if (data.attributes.contains(
                        WEBSOCKETS_KEY,
                    )
                ) {
                    webSocket(conn, data, callContext, extraHeaders)
                } else {
                    exchange(conn, data, callContext, extraHeaders)
                }
            } catch (e: Http3Exception.RequestNotProcessed) {
                lock.withLock {
                    connections[t.key]?.let {
                        if (it.getCompletedOrNull() === conn) connections.remove(t.key)
                    }
                } // a new connection for the retry (RFC 9114 section 5.2)
                if (!data.body.isReplayable()) {
                    throw H3BodyConsumed(
                        "the server did not process the request and its streamed body was already consumed",
                        e,
                    )
                }
                if (++attempts > 2) throw H3NotSent(e)
            }
        }
    }

    @OptIn(InternalAPI::class)
    private suspend fun exchange(
        conn: Http3Connection,
        data: HttpRequestData,
        callContext: CoroutineContext,
        extraHeaders: List<Pair<String, String>>,
    ): HttpResponseData {
        val requestTime = GMTDate()
        val body = data.body.unwrap()
        val response: Http3Response =
            withSocketTimeout(data) {
                conn.request(
                    Http3Request(
                        data.method.value,
                        "https",
                        data.url.authority(),
                        data.url.fullPath.ifEmpty { "/" },
                        headersOf(data, body) + Http3Headers(extraHeaders),
                        bodyChannel(body, callContext),
                    ),
                )
            }
        callContext[Job]?.invokeOnCompletion { cause ->
            // the call is over: an unread rest of the body is abandoned (STOP_SENDING); a reader still waiting sees why
            // (the request timeout, the caller's exception), not the stream's cancellation (found by the vendored contract)
            if (cause != null) response.body.cancel(cause) // as the HTTP/1.1 body: closed with the call's own cancellation
            response.cancel()
        }
        val status = HttpStatusCode.fromValue(response.status)
        val headers = HeadersBuilder().apply { for ((n, v) in response.headers.fields) append(n, v) }.build()
        val noBody = data.method == HttpMethod.Head || status == HttpStatusCode.NoContent || status == HttpStatusCode.NotModified
        val bodyChannel: ByteReadChannel = if (noBody) ByteReadChannel.Empty else response.body.withSocketTimeout(data)
        val responseBody: Any =
            data.attributes.getOrNull(ResponseAdapterAttributeKey)?.adapt(data, status, headers, bodyChannel, data.body, callContext)
                ?: bodyChannel
        return HttpResponseData(status, requestTime, headers, HttpProtocolVersion.HTTP_3_0, responseBody, callContext)
    }

    /** RFC 9220: Extended CONNECT with `:protocol = websocket`; the 2xx is reported as 101 so Ktor's plugin accepts it. */
    @OptIn(InternalAPI::class)
    private suspend fun webSocket(
        conn: Http3Connection,
        data: HttpRequestData,
        callContext: CoroutineContext,
        extraHeaders: List<Pair<String, String>>,
    ): HttpResponseData {
        val requestTime = GMTDate()
        val headers = Http3Headers(headersOf(data, data.body.unwrap()).fields.filter { it.first !in WS_HOP_BY_HOP } + extraHeaders)
        val stream =
            conn.connect(
                Http3Request("CONNECT", "https", data.url.authority(), data.url.fullPath.ifEmpty { "/" }, headers),
                "websocket",
            )
        // a session that closed cleanly both ways ends with its FIN; a late RESET_STREAM could overtake it and discard the Close reply
        callContext[Job]?.invokeOnCompletion { cause ->
            val clean =
                cause == null && stream.output.isClosedForWrite && stream.output.closedCause == null && stream.input.isClosedForRead &&
                    stream.input.closedCause == null
            if (!clean) stream.reset(io.kuicksilver.http3.Http3ErrorCode.REQUEST_CANCELLED)
        }
        val session =
            RawWebSocket(
                stream.input,
                stream.output,
                masking = true,
                coroutineContext = callContext,
                channelsConfig = data.attributes[WEBSOCKETS_KEY].channelsConfig,
            )
        // e.g. sec-websocket-protocol
        val responseHeaders = HeadersBuilder().apply { for ((n, v) in stream.headers.fields) append(n, v) }.build()
        return HttpResponseData(
            HttpStatusCode.SwitchingProtocols,
            requestTime,
            responseHeaders,
            HttpProtocolVersion.HTTP_3_0,
            session,
            callContext,
        )
    }

    private suspend fun <T> withSocketTimeout(
        data: HttpRequestData,
        block: suspend () -> T,
    ): T {
        val t = data.socketTimeoutMillis() ?: return block()
        return try {
            withTimeout(t) { block() }
        } catch (e: TimeoutCancellationException) {
            throw SocketTimeoutException(data, e)
        }
    }

    internal companion object {
        /** Connection-specific fields (RFC 9114 section 4.2) and HTTP/1.1 WebSocket handshake fields RFC 9220 drops. */
        val HOP_BY_HOP = setOf("connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "host", "te")
        val WS_HOP_BY_HOP = setOf("sec-websocket-key", "sec-websocket-accept")

        fun io.ktor.http.Url.authority(): String = if (port == protocol.defaultPort) host else hostWithPort

        fun OutgoingContent.unwrap(): OutgoingContent = if (this is OutgoingContent.ContentWrapper) delegate().unwrap() else this

        /** Whether the body can be sent again after a failed attempt: in-memory, absent, or produced by a writer that runs afresh. A [OutgoingContent.ReadChannelContent] hands out one channel that a first attempt may have consumed. */
        fun OutgoingContent.isReplayable(): Boolean =
            when (unwrap()) {
                is OutgoingContent.NoContent, is OutgoingContent.ByteArrayContent, is OutgoingContent.WriteChannelContent -> true
                else -> false
            }

        fun headersOf(
            data: HttpRequestData,
            body: OutgoingContent,
        ): Http3Headers {
            val out = ArrayList<Pair<String, String>>()
            mergeHeaders(data.headers, data.body) { k, v ->
                val n = k.lowercase()
                if (n !in HOP_BY_HOP) out += n to v
            }
            if (out.none { it.first == "content-length" }) {
                body.contentLength?.let {
                    if (body !is OutgoingContent.NoContent) {
                        out +=
                            "content-length" to it.toString()
                    }
                }
            }
            return Http3Headers(out)
        }

        fun bodyChannel(
            body: OutgoingContent,
            callContext: CoroutineContext,
        ): ByteReadChannel? =
            when (body) {
                is OutgoingContent.NoContent, is OutgoingContent.ProtocolUpgrade -> {
                    null
                }

                is OutgoingContent.ByteArrayContent -> {
                    ByteReadChannel(body.bytes())
                }

                is OutgoingContent.ReadChannelContent -> {
                    body.readFrom()
                }

                is OutgoingContent.WriteChannelContent -> {
                    CoroutineScope(callContext + CoroutineName("kuicksilver-h3-body"))
                        .writer {
                            body.writeTo(channel)
                        }.channel
                }

                is OutgoingContent.ContentWrapper -> {
                    bodyChannel(body.delegate(), callContext)
                }
            }

        @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
        fun <T> CompletableDeferred<T>.getCompletedOrNull(): T? =
            if (isCompleted &&
                !isCancelled
            ) {
                runCatching { getCompleted() }.getOrNull()
            } else {
                null
            }
    }
}
