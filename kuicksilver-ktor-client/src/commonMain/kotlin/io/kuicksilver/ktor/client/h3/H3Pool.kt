// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client.h3

import io.ktor.client.engine.mergeHeaders
import io.ktor.client.plugins.ConnectTimeoutException
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
import io.kuicksilver.http3.Http3Response
import io.kuicksilver.http3.http3Request
import io.kuicksilver.ktor.client.Activity
import io.kuicksilver.ktor.client.ConsumedBody
import io.kuicksilver.ktor.client.EngineEvents
import io.kuicksilver.ktor.client.H3BodyConsumed
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.ktor.client.KuicksilverEngineConfig
import io.kuicksilver.ktor.client.RequestDns
import io.kuicksilver.ktor.client.connectTimeoutMillis
import io.kuicksilver.ktor.client.h1.toMillisOrMax
import io.kuicksilver.ktor.client.newRequestDns
import io.kuicksilver.ktor.client.socketTimeoutMillis
import io.kuicksilver.ktor.client.tlsConfigFor
import io.kuicksilver.ktor.client.withSocketInactivityTimeout
import io.kuicksilver.ktor.client.withSocketTimeout
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlin.coroutines.CoroutineContext
import kotlin.time.Duration.Companion.milliseconds

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

/**
 * One pooled HTTP/3 connection (or the attempt to set it up) and its use: requests in flight, and since when it has none.
 * [active] changes under [H3Pool]'s lock when it rises and from a call's completion handler when it falls.
 */
@OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
internal class H3Entry(
    val deferred: CompletableDeferred<Http3Connection>,
    val createdAt: Long,
) {
    val active = kotlin.concurrent.atomics.AtomicInt(0)
    val idleSince = kotlin.concurrent.atomics.AtomicLong(createdAt)
    private val retiredFlag = kotlin.concurrent.atomics.AtomicInt(0)

    fun release(now: Long) {
        if (active.addAndFetch(-1) == 0) {
            idleSince.store(now)
            if (retiredFlag.load() != 0) closeConnection()
        }
    }

    /** Past its lifetime: no new requests; closed as soon as it has none (now, or at the last [release]). */
    fun retire() {
        retiredFlag.store(1)
        if (active.load() == 0) closeConnection()
    }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    private fun closeConnection() {
        if (deferred.isCompleted && deferred.getCompletionExceptionOrNull() == null) deferred.getCompleted().close()
    }
}

/**
 * HTTP/3 connections of one engine: one client endpoint, one connection per (origin, alternative) reused while it is open.
 * That is the per-origin cap: requests multiplex on it, and when the peer's MAX_STREAMS credit is used up a request waits
 * for the next StreamsAvailable inside `openBidi` (bounded by the request timeout) instead of opening another
 * connection or failing. A connection without requests for `idleTimeout`, or past `maxConnectionLifetime` once its
 * requests finished, is closed by [evictExpired], which also drops entries of connections that ended.
 */
@OptIn(InternalAPI::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
internal class H3Pool(
    private val config: KuicksilverEngineConfig,
    private val events: EngineEvents = EngineEvents(null, io.kuicksilver.quic.KuicksilverLogger.None),
    private val clock: () -> Long =
        io.kuicksilver.ktor.client.h1
            .monotonicMillis(),
) {
    private val lock = Mutex()

    /**
     * The connection ID length of the engine's endpoint and connections, which must agree (the endpoint parses short headers
     * with it): whichever of `quic` and `http3.endpoint` left the default follows the other; two different explicit values
     * are refused here, when the engine is created.
     */
    private val connectionIdLength: Int =
        resolveConnectionIdLength(config.quic.connectionIdLength, config.http3.endpoint.connectionIdLength)

    /** The engine's endpoint with its logger, connection listener and [connectionIdLength]. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private val endpointConfig: io.kuicksilver.quic.QuicEndpointConfig =
        config.http3.endpoint.let { e ->
            if (config.logger == null && config.http3.connectionListener == null && e.connectionIdLength == connectionIdLength) {
                e
            } else {
                e
                    .toBuilder()
                    .apply {
                        config.logger?.let { logger = it }
                        config.http3.connectionListener?.let { listener = it }
                        connectionIdLength = this@H3Pool.connectionIdLength
                    }.build()
            }
        }

    /** The engine's QUIC settings with its qlog sink and [connectionIdLength]. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private val quic: io.kuicksilver.quic.QuicConfig =
        config.quic.let { q ->
            if (config.http3.qlog == null && q.connectionIdLength == connectionIdLength) {
                q
            } else {
                q
                    .toBuilder()
                    .apply {
                        config.http3.qlog?.let { qlog = it }
                        connectionIdLength = this@H3Pool.connectionIdLength
                    }.build()
            }
        }

    init {
        // RFC 9114 section 6.2: refused when the engine is created, not clamped (Http3Endpoint.connect refuses it too)
        if (config.http3.discovery != Http3DiscoveryMode.H1Only) {
            require(quic.maxUniStreams >= 3) {
                "HTTP/3 needs quic.maxUniStreams >= 3 (RFC 9114 section 6.2: the server opens its control and QPACK streams), " +
                    "not ${quic.maxUniStreams}; Http3DiscoveryMode.H1Only does not use HTTP/3"
            }
        }
    }

    private var endpoint: Http3Endpoint? = null
    private val connections = HashMap<String, H3Entry>()

    /** [quic] with its handshake timeout cut to [connectTimeoutMillis] when that is shorter (a 0-RTT connect returns early). */
    private fun quicWithin(connectTimeoutMillis: Long): io.kuicksilver.quic.QuicConfig {
        val limit = connectTimeoutMillis.milliseconds
        return if (quic.handshakeTimeout <= limit) quic else quic.toBuilder().apply { handshakeTimeout = limit }.build()
    }

    /**
     * Whether [data] goes out in 0-RTT on a connection still handshaking (as `Http3Request.allowEarlyData` admits it: the
     * engine's `earlyData`, a safe method, no body; never a WebSocket). Every other request waits for the handshake first.
     */
    private fun goesEarly(data: HttpRequestData): Boolean =
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        config.http3.earlyData && !data.attributes.contains(WEBSOCKETS_KEY) &&
            data.method.value in io.kuicksilver.http3.Http3EarlyDataPolicy.SAFE_METHODS &&
            data.body.unwrap() is OutgoingContent.NoContent

    /** Connections past their lifetime that still carry requests: closed once they have none. */
    private val retired = ArrayList<H3Entry>()

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private val idleTimeoutMillis = config.idleTimeout.toMillisOrMax()

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private val maxLifetimeMillis = config.maxConnectionLifetime.toMillisOrMax()

    /** Connections set up and not yet used by an exchange: the first one to use it reports it as new (under [lock]). */
    private val fresh = HashSet<Http3Connection>()

    private suspend fun endpoint(): Http3Endpoint =
        lock.withLock {
            endpoint
                ?: Http3Endpoint.bind(InetSocketAddress("0.0.0.0", 0), endpointConfig, config.http3.settings).also { endpoint = it }
        }

    /** Test hook: the open connections, then forgets them so the next request connects again (a 0-RTT resumption). */
    internal suspend fun dropConnectionsForTest(): List<Http3Connection> =
        lock.withLock {
            val l = connections.values.mapNotNull { it.deferred.getCompletedOrNull() }
            connections.clear()
            l
        }

    /** Test hook: the open connections. */
    internal suspend fun connectionsForTest(): List<Http3Connection> =
        lock.withLock {
            connections.values.mapNotNull { it.deferred.getCompletedOrNull() }
        }

    /** Entries of the connection map, retired ones included, open or not (the resource probe). */
    internal suspend fun connectionsForProbe(): Int = lock.withLock { connections.size + retired.size }

    /** Test hook: the (origin, alternative) entries tracked, retired ones included. */
    internal suspend fun entryCountForTest(): Int = lock.withLock { connections.size + retired.size }

    fun close() {
        endpoint?.close()
        endpoint = null
        fresh.clear()
    }

    private fun Http3Connection.usable(): Boolean = !closed.isCompleted && goAwayReceived.value == null

    private fun H3Entry.pastLifetime(now: Long): Boolean = now - createdAt >= maxLifetimeMillis

    /** An open connection to [t], connecting (once, shared by concurrent callers) when needed. */
    suspend fun connection(
        t: H3Target,
        data: HttpRequestData,
        dns: RequestDns = config.newRequestDns(),
    ): Http3Connection = connectionEntry(t, data, dns).second

    private suspend fun connectionEntry(
        t: H3Target,
        data: HttpRequestData,
        dns: RequestDns,
    ): Pair<H3Entry, Http3Connection> {
        while (true) {
            try {
                return connectionEntryOnce(t, data, dns)
            } catch (_: SetupAbandoned) {
                // the caller that was setting the connection up was cancelled: not a failure of the origin, so this caller
                // starts (or joins) a new setup instead of failing or falling back
            }
        }
    }

    /** Test hook: runs in the caller that sets up a connection, before it connects. */
    internal var beforeSetupForTest: (suspend () -> Unit)? = null

    /** Test hook: callers that waited for a setup another caller started. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal val setupWaitersForTest = kotlin.concurrent.atomics.AtomicInt(0)

    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private suspend fun connectionEntryOnce(
        t: H3Target,
        data: HttpRequestData,
        dns: RequestDns,
    ): Pair<H3Entry, Http3Connection> {
        val ep = endpoint()
        val (e, connect) =
            lock.withLock {
                val existing = connections[t.key]
                val done = existing?.deferred?.takeIf { it.isCompleted }?.getCompletedOrNull()
                if (existing != null &&
                    (!existing.deferred.isCompleted || (done != null && done.usable() && !existing.pastLifetime(clock())))
                ) {
                    existing to false
                } else {
                    // past its lifetime with requests in flight: it finishes them first ([evictExpired] closes it)
                    if (existing != null && done != null && done.usable()) {
                        retired += existing
                        existing.retire()
                    }
                    H3Entry(CompletableDeferred(), clock()).also { connections[t.key] = it } to true
                }
            }
        val d = e.deferred
        if (connect) {
            try {
                beforeSetupForTest?.invoke()
                val c =
                    withTimeout(data.connectTimeoutMillis(config)) {
                        // the first address of the request's resolution (the h3/h1 race covers a broken family; no
                        // race between addresses over QUIC), as a literal the endpoint does not look up again
                        val remote = dns.lookup(t.host, t.port).first().let { InetSocketAddress(it.hostText, it.port) }
                        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                        if (config.http3.earlyData) {
                            // returns as soon as 0-RTT keys exist: the connect timeout still bounds the setup, through
                            // the handshake timer (a request sent early then fails, and falls back, at that time)
                            ep.connectEarly(
                                remote,
                                config.tlsConfigFor(t.originHost, listOf(Http3Endpoint.H3)),
                                quicWithin(data.connectTimeoutMillis(config)),
                                config.http3.settings,
                            )
                        } else {
                            ep.connect(
                                remote,
                                config.tlsConfigFor(t.originHost, listOf(Http3Endpoint.H3)),
                                quic,
                                config.http3.settings,
                            )
                        }
                    }
                e.idleSince.store(clock())
                if (events.enabled) {
                    lock.withLock {
                        fresh.removeAll { it.closed.isCompleted } // closed before any exchange used them
                        fresh += c
                    }
                }
                d.complete(c)
            } catch (
                x: TimeoutCancellationException,
            ) {
                d.completeExceptionally(ConnectTimeoutException(data, x))
                forget(t, e)
            } catch (
                x: CancellationException,
            ) {
                // only this caller is cancelled: the others waiting on d start a new setup (cancelling d would cancel them too)
                d.completeExceptionally(SetupAbandoned(x))
                withContext(NonCancellable) { forget(t, e) }
                throw x
            } catch (x: Throwable) {
                d.completeExceptionally(x)
                forget(t, e)
            }
        } else {
            setupWaitersForTest.addAndFetch(1)
        }
        return e to d.await()
    }

    /** The caller setting up a shared connection was cancelled; the callers waiting for it try again. */
    private class SetupAbandoned(
        cause: CancellationException,
    ) : Exception("the connection setup was abandoned by the cancelled caller that started it", cause)

    /**
     * [connection] counted as in use until [H3Entry.release]: [evictExpired] never closes a connection a request was
     * handed. A connection that ended or was replaced between the two steps is looked up again.
     */
    private suspend fun acquire(
        t: H3Target,
        data: HttpRequestData,
        dns: RequestDns,
    ): Pair<H3Entry, Http3Connection> {
        while (true) {
            val (e, c) = connectionEntry(t, data, dns)
            val counted =
                lock.withLock {
                    if ((connections[t.key] === e || e in retired) && !c.closed.isCompleted) {
                        e.active.addAndFetch(1)
                        true
                    } else {
                        false
                    }
                }
            if (counted) return e to c
        }
    }

    /**
     * Closes connections idle for `idleTimeout`, retired ones without requests, and drops entries of connections that
     * ended; returns the milliseconds until the next connection may expire, or null when none is idle.
     */
    suspend fun evictExpired(): Long? {
        val toClose = ArrayList<Http3Connection>()
        var next: Long? = null
        lock.withLock {
            val now = clock()
            val it = connections.values.iterator()
            while (it.hasNext()) {
                val e = it.next()
                if (!e.deferred.isCompleted) continue
                val c = e.deferred.getCompletedOrNull()
                if (c == null || c.closed.isCompleted) {
                    it.remove()
                    continue
                }
                if (e.active.load() > 0) continue
                val idleEnd = saturatedAdd(e.idleSince.load(), idleTimeoutMillis)
                if (now >= idleEnd) {
                    it.remove()
                    toClose += c
                } else {
                    val d = idleEnd - now
                    next = next?.let { n -> minOf(n, d) } ?: d
                }
            }
            retired.removeAll { e ->
                val c = e.deferred.getCompletedOrNull()
                when {
                    c == null || c.closed.isCompleted -> {
                        true
                    }

                    e.active.load() == 0 -> {
                        toClose += c
                        true
                    }

                    else -> {
                        false
                    }
                }
            }
        }
        toClose.forEach { it.close() }
        return next
    }

    /** The open, usable connection to [t], if one exists (no connection attempt). */
    suspend fun existing(t: H3Target): Http3Connection? =
        lock.withLock { connections[t.key] }?.deferred?.getCompletedOrNull()?.takeIf {
            !it.closed.isCompleted &&
                it.goAwayReceived.value == null
        }

    /** Whether an open connection to [t] exists and its peer accepts Extended CONNECT (WebSockets over HTTP/3, RFC 9220). */
    suspend fun canConnectProtocol(t: H3Target): Boolean =
        lock.withLock { connections[t.key] }?.deferred?.getCompletedOrNull()?.let {
            !it.closed.isCompleted &&
                it.peerSettings.value?.enableConnectProtocol == true
        } ==
            true

    private suspend fun forget(
        t: H3Target,
        e: H3Entry,
    ) = lock.withLock {
        if (connections[t.key] ===
            e
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
        dns: RequestDns = config.newRequestDns(),
    ): HttpResponseData {
        var attempts = 0
        while (true) {
            val (entry, conn) =
                try {
                    acquire(t, data, dns)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    throw H3NotSent(e)
                }
            var reported = false // connectionAcquired went out: a failure below reports the release too
            try {
                // a request that cannot go in 0-RTT waits for the handshake here, before any stream is opened or its body
                // touched: a handshake that fails leaves it provably unsent (RFC 8470 section 4 — the client starts over)
                @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                if (!conn.quic.isHandshakeComplete && !goesEarly(data)) {
                    try {
                        conn.quic.awaitHandshake()
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Throwable) {
                        throw H3NotSent(e)
                    }
                }
                // inside the try: a cancellation while taking the lock must still release the entry's count
                if (events.enabled) {
                    val reused = lock.withLock { !fresh.remove(conn) }
                    events.emit("connectionAcquired") { connectionAcquired(data, HttpProtocolVersion.HTTP_3_0, reused) }
                    reported = true
                }
                val r =
                    if (data.attributes.contains(
                            WEBSOCKETS_KEY,
                        )
                    ) {
                        webSocket(conn, data, callContext, extraHeaders)
                    } else {
                        exchange(conn, data, callContext, extraHeaders)
                    }
                // in use until the call ends (its body read or abandoned), not just until the response head
                val job = callContext[Job]
                if (job == null) entry.release(clock()) else job.invokeOnCompletion { entry.release(clock()) }
                return r
            } catch (e: Throwable) {
                entry.release(clock())
                // every connectionAcquired gets its connectionReleased, also when the exchange failed before a response
                if (reported) {
                    events.emit(
                        "connectionReleased",
                    ) { connectionReleased(data, HttpProtocolVersion.HTTP_3_0, kept = !conn.closed.isCompleted) }
                }
                if (e !is Http3Exception.RequestNotProcessed) throw e
                lock.withLock {
                    connections[t.key]?.let {
                        if (it === entry) connections.remove(t.key)
                    }
                } // a new connection for the retry (RFC 9114 section 5.2)
                if (!data.body.isReplayable()) {
                    throw H3BodyConsumed(
                        "the server did not process the request and its streamed body was already consumed",
                        e,
                    )
                }
                if (++attempts > 2) throw H3NotSent(e)
                events.emit("retry") { retry(data, attempts + 1, e) }
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
        // the socket timeout measures inactivity (Ktor: "maximum time of inactivity between two data packets"): the body
        // goes out while the response is awaited, and every piece of it the stream takes restarts the timer
        val activity = data.socketTimeoutMillis()?.let { Activity() }
        val response: Http3Response =
            withSocketInactivityTimeout(data, activity) {
                conn.request(
                    http3Request(data.method.value, data.url.authority(), data.url.h3Path()) {
                        headers = headersOf(data, body) + Http3Headers(extraHeaders)
                        this.body = bodyChannel(body, callContext)?.let { b -> activity?.let { ConsumedBody(b, it) } ?: b }
                        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                        allowEarlyData = config.http3.earlyData
                    },
                )
            }
        callContext[Job]?.invokeOnCompletion { cause ->
            // the call is over: an unread rest of the body is abandoned (STOP_SENDING); a reader still waiting sees why
            // (the request timeout, the caller's exception), not the stream's cancellation (found by the vendored contract)
            if (cause != null) response.body.cancel(cause) // as the HTTP/1.1 body: closed with the call's own cancellation
            response.cancel()
            events.emit("connectionReleased") { connectionReleased(data, HttpProtocolVersion.HTTP_3_0, kept = !conn.closed.isCompleted) }
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
                http3Request("CONNECT", data.url.authority(), data.url.h3Path()) { this.headers = headers },
                "websocket",
            )
        // each direction on its own when the call is over. A send side the session closed cleanly ends with its FIN (the Close
        // reply may still be on its way to the stream): a RESET_STREAM could overtake it and discard that reply. The closing
        // handshake can end before the peer's FIN arrives (it may trail the peer's Close frame): only the read side is abandoned
        callContext[Job]?.invokeOnCompletion { cause ->
            val sentCleanly = cause == null && stream.output.isClosedForWrite && stream.output.closedCause == null
            val readToEnd = stream.input.isClosedForRead && stream.input.closedCause == null
            if (!sentCleanly) stream.reset(io.kuicksilver.http3.Http3ErrorCode.REQUEST_CANCELLED)
            if (!readToEnd) stream.stopSending(io.kuicksilver.http3.Http3ErrorCode.REQUEST_CANCELLED)
            events.emit("connectionReleased") { connectionReleased(data, HttpProtocolVersion.HTTP_3_0, kept = !conn.closed.isCompleted) }
        }
        val session =
            RawWebSocket(
                webSocketInputUntilClose(stream.input, callContext),
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

    internal companion object {
        /** See [connectionIdLength]: the explicit one of the two lengths, or the common one. */
        fun resolveConnectionIdLength(
            quic: Int,
            endpoint: Int,
        ): Int {
            val default = io.kuicksilver.quic.QuicConfig.Default.connectionIdLength
            return when {
                quic == endpoint -> quic

                endpoint == default -> quic

                quic == default -> endpoint

                else -> throw IllegalArgumentException(
                    "quic.connectionIdLength ($quic) and http3.endpoint.connectionIdLength ($endpoint) differ: " +
                        "set one of them, the other follows",
                )
            }
        }

        /** Connection-specific fields (RFC 9114 section 4.2) and HTTP/1.1 WebSocket handshake fields RFC 9220 drops. */
        val HOP_BY_HOP = setOf("connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "host", "te")
        val WS_HOP_BY_HOP = setOf("sec-websocket-key", "sec-websocket-accept")

        fun io.ktor.http.Url.authority(): String = if (port == protocol.defaultPort) host else hostWithPort

        /** `:path`: an http(s) URI without a path is sent as "/" (RFC 9114 section 4.3.1), also before a query (`?a=1` -> `/?a=1`). */
        fun io.ktor.http.Url.h3Path(): String = fullPath.let { if (it.startsWith('/')) it else "/$it" }

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

        fun saturatedAdd(
            a: Long,
            b: Long,
        ): Long = if (b > Long.MAX_VALUE - a) Long.MAX_VALUE else a + b

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
