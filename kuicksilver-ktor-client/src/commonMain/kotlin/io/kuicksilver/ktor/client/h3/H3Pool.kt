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
import io.ktor.util.AttributeKey
import io.ktor.util.date.GMTDate
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.writer
import io.ktor.websocket.RawWebSocket
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3ErrorCode
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
import io.kuicksilver.ktor.client.PriorityUpdaterKey
import io.kuicksilver.ktor.client.RequestDns
import io.kuicksilver.ktor.client.connectTimeoutMillis
import io.kuicksilver.ktor.client.h1.toMillisOrMax
import io.kuicksilver.ktor.client.newRequestDns
import io.kuicksilver.ktor.client.originKeyOf
import io.kuicksilver.ktor.client.priority
import io.kuicksilver.ktor.client.priorityUpdater
import io.kuicksilver.ktor.client.socketTimeoutMillis
import io.kuicksilver.ktor.client.tlsConfigFor
import io.kuicksilver.ktor.client.webSocketAfterHandshake
import io.kuicksilver.ktor.client.withSocketInactivityTimeout
import io.kuicksilver.ktor.client.withSocketTimeout
import io.kuicksilver.ktor.network.guardWebSocketInput
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.MigrationEvent
import io.kuicksilver.quic.MigrationRefusedException
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TransportError
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.update
import kotlin.coroutines.CoroutineContext
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

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
 * Set on a request whose HTTP/3 connection the server closed with H3_NO_ERROR after it had sent GOAWAY ([H3Pool.execute]): the engine's
 * fallback for it does not mark the alternative broken (RFC 9114 section 5.2, RFC 7838 section 2.4).
 */
internal val H3ClosedAfterGoAwayKey: AttributeKey<Unit> = AttributeKey("io.kuicksilver.ktor.client.H3ClosedAfterGoAway")

/**
 * Whether [e] is the peer ending the whole connection the way a graceful shutdown does (RFC 9114 section 5.2: "An
 * endpoint that completes a graceful shutdown SHOULD use the H3_NO_ERROR error code when closing the connection"): an
 * application close with H3_NO_ERROR, or with a code this client does not know (read as H3_NO_ERROR, section 9), or a
 * transport close with NO_ERROR. A close with an error code, a stream error and a local failure are not.
 */
internal fun isPeerShutdownClose(e: Throwable): Boolean =
    when (e) {
        is Http3Exception.Protocol -> {
            e.initiator == Initiator.Peer && e.streamId == null && e.h3Code == Http3ErrorCode.NO_ERROR
        }

        is QuicException.ConnectionLost.ApplicationClosed -> {
            e.initiator == Initiator.Peer && Http3ErrorCode.normalize(e.code) == Http3ErrorCode.NO_ERROR
        }

        is QuicException.ConnectionLost.TransportClosed -> {
            e.initiator == Initiator.Peer && e.code == TransportError.NO_ERROR
        }

        else -> {
            false
        }
    }

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

    private val drainedFlag = kotlin.concurrent.atomics.AtomicInt(0)

    /** Drained by `closeHttp3Connections()`: no request is handed this connection any more, not even one that found it retired. */
    val drained: Boolean get() = drainedFlag.load() != 0

    /** Takes no new requests and closes at its last [release]; [closeIfIdle] closes it when it has none (after its GOAWAY). */
    fun drain() {
        drainedFlag.store(1)
        retiredFlag.store(1)
    }

    fun closeIfIdle() {
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
    /** Where the migrators of `http3.connectionMigration` run ([followNetwork]); null: connections never migrate. */
    private val migrationScope: CoroutineScope? = null,
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

    @kotlin.concurrent.Volatile
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

    /** Set by [close]: nothing binds a new endpoint after it (a request or session after the client closed). */
    @kotlin.concurrent.Volatile
    private var closed = false

    private suspend fun endpoint(): Http3Endpoint =
        lock.withLock {
            check(!closed) { "the client is closed" }
            endpoint ?: Http3Endpoint.bind(InetSocketAddress("0.0.0.0", 0), endpointConfig, config.http3.settings).also {
                endpoint = it
                // a close that ran during the bind did not see this endpoint: it goes now
                if (closed) {
                    it.close()
                    endpoint = null
                    throw IllegalStateException("the client is closed")
                }
            }
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

    /** Test hook: whether the endpoint is bound. */
    internal val endpointBoundForTest: Boolean get() = endpoint != null

    /** Dedicated connections of WebTransport sessions, open or being set up (a test hook and the resource probe). */
    internal val dedicatedCount = kotlinx.coroutines.flow.MutableStateFlow(0)

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private val maxDedicated = config.http3.maxWebTransportSessions

    init {
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        require(config.http3.maxWebTransportSessions >= 1) {
            "http3.maxWebTransportSessions must be at least 1, not ${config.http3.maxWebTransportSessions}"
        }
    }

    /**
     * A QUIC connection to [originHost]:[port] for one WebTransport session, outside the pool: never shared with requests
     * and closed with its session. The engine's endpoint, trust and QUIC settings, with WebTransport, Extended CONNECT and
     * `reset_stream_at` turned on (draft-ietf-webtrans-http3-16 sections 3.1, 4.4). [connectTimeoutMillis] bounds the lookup
     * and the handshakes: the resolved addresses are tried in order, each with an equal share of what is left, so an
     * address whose handshake fails or stalls gives way to the next. At most `maxWebTransportSessions` such connections
     * exist at once; one more fails at once (IllegalStateException), nothing queues.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    suspend fun dedicated(
        originHost: String,
        port: Int,
        connectTimeoutMillis: Long,
    ): Http3Connection {
        check(!refusingDedicated && !closed) { "the client is closed" }
        while (true) {
            val n = dedicatedCount.value
            check(n < maxDedicated) { "maxWebTransportSessions ($maxDedicated) WebTransport sessions are open on this client" }
            if (dedicatedCount.compareAndSet(n, n + 1)) break
        }
        var handedOut = false
        try {
            val c = connectDedicated(originHost, port, connectTimeoutMillis)
            // tracked from now on, before its CONNECT: closeHttp3Connections() sends it GOAWAY too, and a CONNECT not sent
            // yet then fails with RequestNotProcessed instead of starting a session that escapes the drain
            val entry = c to drainEpoch.load()
            afterDedicatedEpochForTest?.invoke()
            dedicatedConnections.update { it + entry }
            c.closed.invokeOnCompletion {
                dedicatedCount.update { it - 1 }
                dedicatedConnections.update { s -> s - entry }
            }
            handedOut = true
            return c
        } finally {
            if (!handedOut) dedicatedCount.update { it - 1 }
        }
    }

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private suspend fun connectDedicated(
        originHost: String,
        port: Int,
        connectTimeoutMillis: Long,
    ): Http3Connection {
        val ep = endpoint()
        val settings =
            config.http3.settings
                .toBuilder()
                .apply {
                    enableConnectProtocol = true
                    webTransport = true
                }.build()
        val start =
            kotlin.time.TimeSource.Monotonic
                .markNow()
        val tls = config.tlsConfigFor(originHost, listOf(Http3Endpoint.H3))
        var last: Throwable? = null
        // set inside the timeouts: a handshake that completes as a timeout fires still lands here, never orphaned
        var made: Http3Connection? = null
        try {
            withTimeout(connectTimeoutMillis) {
                val addresses = config.newRequestDns().lookup(originHost, port)
                for ((i, a) in addresses.withIndex()) {
                    val left = connectTimeoutMillis - start.elapsedNow().inWholeMilliseconds
                    if (left <= 0) break
                    val share = maxOf(1L, left / (addresses.size - i))
                    val q = quicWithin(share).let { if (it.resetStreamAt) it else it.toBuilder().apply { resetStreamAt = true }.build() }
                    try {
                        withTimeoutOrNull(share) { made = ep.connect(InetSocketAddress(a.hostText, a.port), tls, q, settings) }
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Throwable) {
                        last = e // this address failed: the next one gets the rest of the time
                    }
                    if (made != null) return@withTimeout
                }
            }
        } catch (e: TimeoutCancellationException) {
            if (made == null) throw ConnectTimeoutException("https://$originHost:$port", connectTimeoutMillis, last ?: e)
        } catch (e: Throwable) {
            made?.let { withContext(NonCancellable) { runCatching { it.close(io.kuicksilver.http3.Http3ErrorCode.NO_ERROR, "") } } }
            throw e
        }
        // every address failed or ran out of its share: the last failure, or the connect timeout
        return made ?: throw (last ?: ConnectTimeoutException("https://$originHost:$port", connectTimeoutMillis, null))
    }

    /**
     * Set by the engine's `close()` itself, before its asynchronous cleanup: no new WebTransport session starts then.
     * Requests already running keep the endpoint until the cleanup ([close]) ends it.
     */
    @kotlin.concurrent.Volatile
    private var refusingDedicated = false

    /** The client is closing: [dedicated] refuses from now on. */
    fun refuseDedicated() {
        refusingDedicated = true
    }

    fun close() {
        refusingDedicated = true
        closed = true
        endpoint?.close()
        endpoint = null
        fresh.clear()
    }

    private fun Http3Connection.usable(): Boolean = !closed.isCompleted && goAwayReceived.value == null

    /** WebTransport sessions of this client and their dedicated connections ([trackSession]), for [goAwayAll]. */
    private val sessions =
        kotlin.concurrent.atomics.AtomicReference(emptySet<Pair<io.kuicksilver.http3.WebTransportSession, Http3Connection>>())

    /** Dedicated connections from [dedicated] on, with the [drainEpoch] they were made in, for [goAwayAll]. */
    private val dedicatedConnections = kotlin.concurrent.atomics.AtomicReference(emptySet<Pair<Http3Connection, Int>>())

    /** Moved by every [goAwayAll], before it looks at the sessions: a session tracked after that sees it moved. */
    private val drainEpoch = kotlin.concurrent.atomics.AtomicInt(0)

    /**
     * Tracks a WebTransport [session] on its dedicated [connection] until the session is over. When a [goAwayAll] ran since
     * the connection was made (it got a GOAWAY, but the session was not tracked yet), the session is drained at once.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    suspend fun trackSession(
        session: io.kuicksilver.http3.WebTransportSession,
        connection: Http3Connection,
    ) {
        val entry = session to connection
        sessions.update { it + entry }
        session.closed.invokeOnCompletion { sessions.update { s -> s - entry } }
        val madeIn = dedicatedConnections.load().firstOrNull { it.first === connection }?.second
        if (madeIn != null && madeIn != drainEpoch.load()) {
            // a goAwayAll ran since the connection was made and may not have seen it: GOAWAY and drain here
            withTimeoutOrNull(GOAWAY_TIMEOUT) { runCatching { if (!connection.closed.isCompleted) connection.goAway() } }
            runCatching { session.drain() } // bounded by drain's own limit
        }
    }

    /** Whether a [goAwayAll] ran since [connection] was handed out by [dedicated]. */
    fun drainedSince(connection: Http3Connection): Boolean {
        val madeIn = dedicatedConnections.load().firstOrNull { it.first === connection }?.second ?: return false
        return madeIn != drainEpoch.load()
    }

    /** Test hook: runs in [dedicated] between reading the drain epoch and registering the connection. */
    internal var afterDedicatedEpochForTest: (suspend () -> Unit)? = null

    /** Test hook: runs in [goAwayAll] between reading the dedicated connections and moving the drain epoch. */
    internal var goAwayAllBeforeEpochForTest: (suspend () -> Unit)? = null

    /** Test hook: runs in `webTransport` between [dedicated] and the CONNECT, and between the CONNECT and [trackSession]. */
    internal var webTransportStepForTest: (suspend (step: String) -> Unit)? = null

    /** WebTransport sessions tracked (tests). */
    internal val sessionCountForTest: Int get() = sessions.load().size

    /**
     * `HttpClient.closeHttp3Connections()`. First, under the lock, every pooled connection leaves the pool: an established one
     * is drained ([H3Entry.drain]: no request is handed it any more), one still being set up is retired (the requests
     * waiting for it use it, and it closes after the last one, or when [evictExpired] finds it unused). Then, concurrently in
     * [scope], every drained connection gets our GOAWAY (RFC 9114 section 5.2; a client announces 0, it accepts no pushes)
     * within [GOAWAY_TIMEOUT] and closes at once when idle, else at its last request; every dedicated WebTransport
     * connection gets our GOAWAY too (a CONNECT not sent yet then fails), and every tracked session WT_DRAIN_SESSION
     * (draft-ietf-webtrans-http3 section 4.7) after it, within drain()'s own limit. Returns once those are written or timed out.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    suspend fun goAwayAll(scope: CoroutineScope) {
        val drained = ArrayList<Pair<H3Entry, Http3Connection>>()
        lock.withLock {
            for (e in connections.values) {
                val c = e.deferred.getCompletedOrNull()
                if (c != null) {
                    e.drain()
                    drained += e to c
                } else if (!e.deferred.isCompleted) {
                    e.retire()
                }
                retired += e
            }
            connections.clear()
        }
        // dedicated connections are read BEFORE the epoch moves, sessions AFTER: a connection missing from this read was
        // added after it, so it read the old epoch (and its session is drained when tracked) or started after this call
        // began moving the epoch; a session missing from the later read sees the moved epoch in trackSession
        val dedicatedNow = dedicatedConnections.load()
        goAwayAllBeforeEpochForTest?.invoke()
        drainEpoch.addAndFetch(1)
        val jobs = ArrayList<Job>()
        for ((e, c) in drained) {
            jobs +=
                scope.launch {
                    withTimeoutOrNull(GOAWAY_TIMEOUT) { runCatching { if (!c.closed.isCompleted) c.goAway() } }
                    e.closeIfIdle()
                }
        }
        val withSession = sessions.load()
        for ((session, c) in withSession) {
            jobs +=
                scope.launch {
                    // GOAWAY first, under its own limit; drain() has a 5 s limit of its own, after which it ends the session
                    // as failed, so it runs without an outer one that could cut it short
                    withTimeoutOrNull(GOAWAY_TIMEOUT) { runCatching { if (!c.closed.isCompleted) c.goAway() } }
                    runCatching { session.drain() }
                }
        }
        // dedicated connections whose session is not tracked yet: a CONNECT not sent yet fails (RequestNotProcessed)
        for ((c, _) in dedicatedNow) {
            if (withSession.any { it.second === c }) continue
            jobs += scope.launch { withTimeoutOrNull(GOAWAY_TIMEOUT) { runCatching { if (!c.closed.isCompleted) c.goAway() } } }
        }
        jobs.joinAll()
    }

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

    /** Test hook: runs in a request that holds a connection, before it waits for the handshake or opens its stream. */
    internal var afterAcquireForTest: (suspend () -> Unit)? = null

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
            // set inside the timeout: a handshake that completes as the timeout fires is closed, never orphaned
            var made: Http3Connection? = null
            try {
                beforeSetupForTest?.invoke()
                withTimeout(data.connectTimeoutMillis(config)) {
                    // the first address of the request's resolution (the h3/h1 race covers a broken family; no
                    // race between addresses over QUIC), as a literal the endpoint does not look up again
                    val remote = dns.lookup(t.host, t.port).first().let { InetSocketAddress(it.hostText, it.port) }
                    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                    made =
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
                val c = made!!
                e.idleSince.store(clock())
                if (events.enabled) {
                    lock.withLock {
                        fresh.removeAll { it.closed.isCompleted } // closed before any exchange used them
                        fresh += c
                    }
                }
                d.complete(c)
                followNetwork(c, data)
            } catch (
                x: TimeoutCancellationException,
            ) {
                made?.close()
                d.completeExceptionally(ConnectTimeoutException(data, x))
                forget(t, e)
            } catch (
                x: CancellationException,
            ) {
                made?.close()
                // only this caller is cancelled: the others waiting on d start a new setup (cancelling d would cancel them too)
                d.completeExceptionally(SetupAbandoned(x))
                withContext(NonCancellable) { forget(t, e) }
                throw x
            } catch (x: Throwable) {
                if (!d.isCompleted) made?.close()
                d.completeExceptionally(x)
                forget(t, e)
            }
        } else {
            setupWaitersForTest.addAndFetch(1)
        }
        return e to d.await()
    }

    /**
     * Lets [c] follow the network with `http3.connectionMigration`, if set (docs/guide/ktor.md, "Connection migration"): once
     * its handshake has completed (RFC 9000 section 9: no migration before; a 0-RTT connection is handed out earlier), the
     * hook's migrator is started with its events going to the listener, and it is closed when [c] ends or the client
     * closes. The transport enforces the rest of section 9 (confirmation, `disable_active_migration`, zero-length IDs,
     * path validation): a refusal is a [MigrationEvent.Failed] that leaves [c] where it is.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private fun followNetwork(
        c: Http3Connection,
        data: HttpRequestData,
    ) {
        val migration = config.http3.connectionMigration ?: return
        val scope = migrationScope ?: return
        val origin = originKeyOf(data.url)
        val job =
            scope.launch {
                try {
                    c.quic.awaitHandshake()
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    return@launch // the handshake failed: the connection is gone, nothing to follow
                }
                val m =
                    try {
                        migration.start(c.quic, this)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        logMigration("connection migration for $origin not started: the hook failed", e)
                        return@launch
                    }
                try {
                    launch(start = CoroutineStart.UNDISPATCHED) { m.events.collect { reportMigration(origin, it) } }
                    try {
                        m.start()
                    } catch (_: IllegalStateException) {
                        // the hook started it already
                    }
                    awaitCancellation() // until the connection ends or the client closes
                } finally {
                    m.close()
                }
            }
        // a connection that ended already cancels at once
        c.closed.invokeOnCompletion { job.cancel() }
    }

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private fun reportMigration(
        origin: String,
        e: MigrationEvent<*>,
    ) {
        when (e) {
            is MigrationEvent.Failed -> {
                // the transport's refusal (disable_active_migration, zero-length connection IDs, not confirmed yet) comes
                // back on every network change and is no fault: Debug; anything else (a path that failed validation, a
                // socket that could not be opened, a hook's own IllegalStateException) is worth Info
                val refused = e.cause is MigrationRefusedException
                logMigration(
                    "connection to $origin did not migrate to ${e.network}",
                    e.cause,
                    if (refused) LogLevel.Debug else LogLevel.Info,
                )
            }

            is MigrationEvent.SourceFailed -> {
                logMigration("connection to $origin stopped following the network: its source failed", e.cause)
            }

            else -> {}
        }
        events.emit("connectionMigrated") { connectionMigrated(origin, e) }
    }

    private fun logMigration(
        message: String,
        cause: Throwable,
        level: LogLevel = LogLevel.Info,
    ) {
        runCatching { if (events.logger.isEnabled(level)) events.logger.log(level, message, cause) }
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
        prefer: Http3Connection? = null,
    ): Pair<H3Entry, Http3Connection> {
        // the connection the h3/h1 race set up for this request: used even when closeHttp3Connections() retired it while
        // it was being set up (it serves the requests that waited for it), instead of a second handshake
        if (prefer != null) {
            val e =
                lock.withLock {
                    (listOfNotNull(connections[t.key]) + retired)
                        .firstOrNull {
                            it.deferred.getCompletedOrNull() === prefer && !it.drained && prefer.usable()
                        }?.also { it.active.addAndFetch(1) }
                }
            if (e != null) return e to prefer
        }
        while (true) {
            val (e, c) = connectionEntry(t, data, dns)
            val counted =
                lock.withLock {
                    if ((connections[t.key] === e || (e in retired && !e.drained)) && !c.closed.isCompleted) {
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
                    // still being set up (retired by closeHttp3Connections): kept, so it is closed once set up and unused
                    !e.deferred.isCompleted -> {
                        false
                    }

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
        prefer: Http3Connection? = null,
    ): HttpResponseData {
        var attempts = 0
        data.attributes.remove(H3ClosedAfterGoAwayKey) // a mark of an earlier execution of the same request data
        while (true) {
            val (entry, conn) =
                try {
                    acquire(t, data, dns, if (attempts == 0) prefer else null)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    throw H3NotSent(e)
                }
            var reported = false // connectionAcquired went out: a failure below reports the release too
            try {
                afterAcquireForTest?.invoke()
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
                // the server sent GOAWAY, then closed the connection under this request with H3_NO_ERROR (a stopping server at
                // the end of its grace period): an orderly close (RFC 9114 section 5.2), not a failure of the alternative
                if (conn.goAwayReceived.value != null && isPeerShutdownClose(e)) data.attributes.put(H3ClosedAfterGoAwayKey, Unit)
                if (e !is Http3Exception.RequestNotProcessed) throw e
                lock.withLock {
                    connections[t.key]?.let {
                        if (it === entry) connections.remove(t.key)
                    }
                } // a new connection for the retry (RFC 9114 section 5.2)
                // a request refused before anything of it went out (this client's own GOAWAY, closeHttp3Connections) left
                // its body unread: it goes again whatever the body
                @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                if (!data.body.isReplayable() && !e.neverSent) {
                    throw H3BodyConsumed(
                        "the server did not process the request and its streamed body was already consumed",
                        e,
                    )
                }
                if (++attempts > 2) throw H3NotSent(e)
                @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                data.attributes.getOrNull(io.kuicksilver.ktor.client.KuicksilverDiagnosticsKey)?.let { it.attempts++ }
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
                        priority = data.priority
                    },
                )
            }
        data.attributes.put(PriorityUpdaterKey, response.priorityUpdater()) // for HttpResponse.updatePriority
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
                http3Request("CONNECT", data.url.authority(), data.url.h3Path()) {
                    this.headers = headers
                    priority = data.priority
                },
                "websocket",
            )
        // each direction on its own when the call is over. A send side the session closed cleanly ends with its FIN (the Close
        // reply may still be on its way to the stream): a RESET_STREAM could overtake it and discard that reply. The closing
        // handshake can end before the peer's FIN arrives (it may trail the peer's Close frame): only the read side is abandoned
        callContext[Job]?.invokeOnCompletion { cause ->
            // a send side the session finished (its Close and FIN queued) keeps them even when the call itself failed after
            // (the application threw once the Close was out): a reset would discard what is still in flight
            val sentCleanly = stream.output.isClosedForWrite && stream.output.closedCause == null
            val readToEnd = stream.input.isClosedForRead && stream.input.closedCause == null
            if (!sentCleanly) stream.reset(io.kuicksilver.http3.Http3ErrorCode.REQUEST_CANCELLED)
            if (!readToEnd) stream.stopSending(io.kuicksilver.http3.Http3ErrorCode.REQUEST_CANCELLED)
            events.emit("connectionReleased") { connectionReleased(data, HttpProtocolVersion.HTTP_3_0, kept = !conn.closed.isCompleted) }
        }
        // an extension the client did not offer fails the handshake (RFC 6455 section 4.1, RFC 9220 section 3); the
        // call's failure resets the stream (above)
        val extensions =
            stream.headers.fields
                .filter { it.first == "sec-websocket-extensions" }
                .map { it.second }
        val handshake = webSocketAfterHandshake(data, extensions, callContext)
        val session =
            RawWebSocket(
                guardWebSocketInput(
                    stream.input,
                    handshake.allowedRsv,
                    untilClose = true,
                    peerMasks = false,
                    context = callContext,
                    inflate = handshake.inflate,
                ),
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

        /** How long `closeHttp3Connections()` waits for each GOAWAY to be written (WT_DRAIN_SESSION has drain()'s own 5 s). */
        val GOAWAY_TIMEOUT = 5.seconds

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
            val ownPriority = data.priority != null // HttpRequestBuilder.priority replaces a raw field: one signal
            mergeHeaders(data.headers, data.body) { k, v ->
                val n = k.lowercase()
                // Ktor allows OWS around a value (its WebSocket plugin writes `Sec-WebSocket-Extensions: x-test `); an
                // HTTP/3 field value carries none (RFC 9110 section 5.5), as on the server side
                if (n !in HOP_BY_HOP && !(ownPriority && n == "priority")) out += n to v.trim { it == ' ' || it == '\t' }
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
