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
import io.ktor.http.takeFrom
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.util.AttributeKey
import io.ktor.util.date.GMTDate
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.discard
import io.ktor.utils.io.writer
import io.ktor.websocket.RawWebSocket
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3Response
import io.kuicksilver.http3.Http3Stream
import io.kuicksilver.http3.awaitWebTransportExchangeEnd
import io.kuicksilver.http3.contentHandedToTransport
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.webTransport
import io.kuicksilver.ktor.client.isIdempotent
import io.kuicksilver.ktor.client.Activity
import io.kuicksilver.ktor.client.ConsumedBody
import io.kuicksilver.ktor.client.EngineEvents
import io.kuicksilver.ktor.client.H3BodyConsumed
import io.kuicksilver.ktor.client.HeldTransportEnd
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.ktor.client.KuicksilverEngineConfig
import io.kuicksilver.ktor.client.PriorityUpdaterKey
import io.kuicksilver.ktor.client.RequestDns
import io.kuicksilver.ktor.client.WebSocketLifetime
import io.kuicksilver.ktor.client.WebSocketLifetimeKey
import io.kuicksilver.ktor.client.connectTimeoutMillis
import io.kuicksilver.ktor.client.h1.WebSocketConnecting
import io.kuicksilver.ktor.client.h1.toMillisOrMax
import io.kuicksilver.ktor.client.isTransientRefusal
import io.kuicksilver.ktor.client.newRequestDns
import io.kuicksilver.ktor.client.originKeyOf
import io.kuicksilver.ktor.client.priority
import io.kuicksilver.ktor.client.priorityUpdater
import io.kuicksilver.ktor.client.socketTimeoutMillis
import io.kuicksilver.ktor.client.tlsConfigFor
import io.kuicksilver.ktor.client.webSocketAfterHandshake
import io.kuicksilver.ktor.client.withSocketInactivityTimeout
import io.kuicksilver.ktor.client.withSocketTimeout
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.ktor.network.guardWebSocketInput
import io.kuicksilver.ktor.network.guardWebSocketOutput
import io.kuicksilver.ktor.network.isAtWebSocketFrameBoundary
import io.kuicksilver.ktor.network.raceAddresses
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.MigrationEvent
import io.kuicksilver.quic.MigrationRefusedException
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.activePath
import io.kuicksilver.quic.ipLiteral
import io.kuicksilver.quic.loopbackLocalFor
import io.kuicksilver.quic.unmappedLiteral
import io.kuicksilver.tls.completedWithin
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
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

/** The origin host of an [H3Target.key]. */
private fun originOfKey(key: String): String = key.substringBefore('|')

/**
 * Where a pooled connection goes, as an address literal: [bytes] (an IPv4-mapped IPv6 address as its IPv4 one), [port]
 * and the IPv6 zone [scopeId] (0: none). Two destinations are the same only with the same zone, so link-local addresses
 * of different interfaces never match; a preferred address (RFC 9000 section 9.6) carries no zone and gets 0.
 */
internal class Destination(
    val bytes: ByteArray,
    val port: Int,
    val scopeId: Int,
) {
    fun sameAs(o: Destination): Boolean = port == o.port && scopeId == o.scopeId && bytes.contentEquals(o.bytes)

    companion object {
        fun of(a: TcpAddress): Destination = Destination(unmapped(a.bytes), a.port, a.scopeId)
    }
}

private fun unmapped(b: ByteArray): ByteArray =
    if (b.size == 16 && (0 until 10).all { b[it] == 0.toByte() } && b[10] == 0xff.toByte() && b[11] == 0xff.toByte()) {
        b.copyOfRange(12, 16)
    } else {
        b
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
    /** Set up WebTransport-capable (its SETTINGS, Extended CONNECT, `reset_stream_at`): sessions may join it, requests use it. */
    val webTransport: Boolean = false,
    /** Called after every [release] (the pool's [H3Pool.releasesForTest]). */
    private val released: () -> Unit = {},
) {
    /** Requests and WebTransport sessions using the connection. */
    val active = kotlin.concurrent.atomics.AtomicInt(0)

    /** WebTransport sessions open on it. */
    val wtSessions = kotlin.concurrent.atomics.AtomicInt(0)

    /**
     * The sessions it carried when the server refused one more (H3_REQUEST_REJECTED, draft-16 section 5.2), or -1: no new
     * session is tried on it while it carries that many or more.
     */
    @kotlin.concurrent.Volatile
    var wtFullAt: Int = -1

    /**
     * Where this connection goes: the literal the pool's Happy Eyeballs race connected it to, then the server's preferred
     * address once the connection moved there (RFC 9000 section 9.6, [H3Pool]'s path-change collector). A literal, so
     * comparing it needs no lookup (the pool compares under its lock, and reading a socket address's host name can be a
     * reverse lookup on the JVM). Null until the setup finished.
     */
    @kotlin.concurrent.Volatile
    var connectedTo: Destination? = null

    val idleSince = kotlin.concurrent.atomics.AtomicLong(createdAt)
    private val retiredFlag = kotlin.concurrent.atomics.AtomicInt(0)

    fun release(now: Long) {
        if (active.addAndFetch(-1) == 0) {
            idleSince.store(now)
            if (retiredFlag.load() != 0) closeConnection()
        }
        released()
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
 * HTTP/3 connections of one engine: one client endpoint, one connection per (origin, alternative) reused while it is open,
 * and alternatives of one origin at the same address and port share one ([shareSameAddress], RFC 9114 section 3.3).
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
    /** The engine's one-WebSocket-CONNECTING-per-host lock (RFC 6455 section 4.1 step 2), shared with HTTP/1.1. */
    private val webSocketConnecting: WebSocketConnecting = WebSocketConnecting(),
) {
    private val lock = Mutex()

    /** A WebSocket's wait for its own Close to be written once its call ended after that Close was queued (tests change it). */
    internal var webSocketCloseWaitMillis: Long = io.kuicksilver.ktor.client.WEBSOCKET_CLOSE_WAIT_MILLIS

    /**
     * Tests: a WebSocket waits for the server's FIN ("waiting"); its own goes after it ("server ended") or at T2 ("T2"); a
     * server's reset meanwhile is answered with a reset ("server reset").
     */
    internal var webSocketClosingForTest: ((String) -> Unit)? = null

    /** Test hook: runs once a WebSocket read the server's end of the stream (its FIN or reset), still inside T2. */
    internal var webSocketServerEndForTest: (suspend () -> Unit)? = null

    /**
     * Test hook: how a WebSocket's stream ends once its session did ([h3WebSocketStreamEnd]), with what it was decided
     * from: whether the session's writer ended its channel and whether the frame guard was between frames.
     */
    internal var webSocketEndForTest: (
        (end: io.kuicksilver.ktor.client.h1.WebSocketTransportEnd, writerDone: Boolean, atFrameBoundary: Boolean) -> Unit
    )? =
        null

    /** Test hook: runs once a WebSocket's CONNECT was answered, still inside the connect timeout. */
    internal var webSocketConnectedForTest: (suspend () -> Unit)? = null

    /**
     * The connection ID length of the engine's endpoint and connections, which must agree (the endpoint parses short headers
     * with it): whichever of `quic` and `http3.endpoint` left the default follows the other; two different explicit values
     * are refused here, when the engine is created.
     */
    private val connectionIdLength: Int =
        resolveConnectionIdLength(config.quic.connectionIdLength, config.http3.endpoint.connectionIdLength)

    /**
     * The session tickets of every endpoint of this pool (the wildcard one and the loopback ones): a name that resolves to
     * both ::1 and 127.0.0.1 (`localhost`) resumes, with 0-RTT, whichever family its next connection takes. Closed by
     * [closeSessions] after the endpoints.
     */
    private val tickets = io.kuicksilver.tls.SessionCache()

    /** The engine's endpoint with its logger, connection listener, [connectionIdLength] and the pool's [tickets]. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private val endpointConfig: io.kuicksilver.quic.QuicEndpointConfig =
        config.http3.endpoint
            .toBuilder()
            .apply {
                config.logger?.let { logger = it }
                config.http3.connectionListener?.let { listener = it }
                connectionIdLength = this@H3Pool.connectionIdLength
                sessionCache = tickets
            }.build()

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

    /** The endpoint of every destination that is not a loopback address: the wildcard address, dual-stack. */
    @kotlin.concurrent.Volatile
    private var endpoint: Http3Endpoint? = null

    /**
     * The endpoints of loopback destinations, on 127.0.0.1 and ::1, each bound at its first use: a socket on the wildcard
     * address shares its port with a socket another local process holds on the loopback address (BSD sockets: macOS, iOS),
     * and the kernel even hands a wildcard bind such a port, so the replies of a server on localhost would reach that process
     * ([loopbackLocalFor]).
     */
    @kotlin.concurrent.Volatile
    private var loopback4: Http3Endpoint? = null

    @kotlin.concurrent.Volatile
    private var loopback6: Http3Endpoint? = null

    /** Test hook (this pool's): runs with each destination of a connection attempt and the endpoint chosen for it. */
    internal var endpointChosenForTest: ((InetSocketAddress, Http3Endpoint) -> Unit)? = null

    /**
     * Test hook (this pool's): runs twice with a newly bound endpoint, before the pool stores it (`stored` false) and after
     * it stores it and before it reads `closed` (`stored` true).
     */
    internal var endpointBindStepForTest: ((Http3Endpoint, stored: Boolean) -> Unit)? = null
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

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private val stallSettings =
        StallSettings(config.http3.stallProbeTimeouts, config.http3.stallMinSilence, config.http3.stallAbandonAfter)

    /** The stall monitors of connections requests watch ([monitorFor]), under [monitorsLock]; each leaves as its connection ends. */
    private val monitors = HashMap<Http3Connection, H3StallMonitor>()

    /** Guards [monitors] alone, so watching a connection never waits for the pool's [lock]. */
    private val monitorsLock = Mutex()

    /** Connections that stalled and are not over yet: [usable] is false for them and [acquire] refuses them. */
    private val stalledConnections = kotlin.concurrent.atomics.AtomicReference(emptyMap<Http3Connection, Stall>())

    /**
     * Marks the alternatives of a stalled connection broken: the stall and the `origin|alternative` keys of the requests on
     * it (the engine's; a stall during a response body happens after the request left the engine's fallback).
     */
    internal var stallMarker: (suspend (Stall, Set<String>) -> Unit)? = null

    /** A connection ended without ever stalling after it carried a whole exchange for `origin|alternative` (the engine's). */
    internal var exchangeCompleted: ((String) -> Unit)? = null

    /** Called once per stalled connection, after the pool dropped it and before the requests that may go again are released (tests). */
    internal var stalledForTest: ((Http3Connection) -> Unit)? = null

    /** A watched exchange's whole response arrived (tests). */
    internal var receivedForTest: (() -> Unit)? = null

    /** Stall monitors whose watching loop runs now: a request watches their connection (tests). */
    internal val stallWatchLoopsForTest = kotlinx.coroutines.flow.MutableStateFlow(0)

    /** Stall monitors not over yet: their connection has not ended (tests). */
    internal val stallMonitorsForTest = kotlinx.coroutines.flow.MutableStateFlow(0)

    /** Liveness PINGs the stall monitors sent (tests). */
    internal val stallPingsForTest = kotlin.concurrent.atomics.AtomicLong(0)

    /** A stall monitor ended with its connection, with whether that lowered a stall's backoff (tests). */
    internal var stallMonitorEndedForTest: ((Boolean) -> Unit)? = null

    /** Wake-ups of the stall monitors' loops (tests). */
    internal val stallPollsForTest = kotlin.concurrent.atomics.AtomicLong(0)

    private val monitorScope: CoroutineScope get() = migrationScope ?: CoroutineScope(kotlinx.coroutines.Dispatchers.Default)

    private fun warn(
        message: String,
        cause: Throwable?,
    ) {
        if (events.logger.isEnabled(io.kuicksilver.quic.LogLevel.Warn)) events.logger.log(io.kuicksilver.quic.LogLevel.Warn, message, cause)
    }

    /**
     * [conn]'s stall monitor, started at its first use. On a stall the connection is dropped from the pool at once, under
     * the pool's lock (a request that looked it up before is refused in [acquire]), before the waits of the repeatable
     * requests on it end; the engine marks the alternative broken.
     */
    private suspend fun monitorFor(conn: Http3Connection): H3StallMonitor =
        monitorsLock.withLock {
            monitors[conn] ?: H3StallMonitor(
                conn,
                stallSettings,
                clock,
                onStall = { stall, keys ->
                    stalledConnections.update { it + (conn to stall) }
                    // drained: no new request or session goes on it, and it closes at its last release (requests, WebSockets
                    // and WebTransport sessions alike), so a path that comes back lets what runs on it finish
                    lock.withLock {
                        connections.values.filter { it.deferred.getCompletedOrNull() === conn }.forEach {
                            retireUnderEveryKey(it)
                            it.drain()
                        }
                        retired.filter { it.deferred.getCompletedOrNull() === conn }.forEach { it.drain() }
                        fresh.remove(conn)
                    }
                    stallMarker?.let { mark -> monitorScope.launch { mark(stall, keys) } }
                    warn(stall.exception(null).message ?: "HTTP/3 connection stalled", null)
                    stalledForTest?.invoke(conn)
                },
                onCompleted = { keys -> keys.forEach { k -> exchangeCompleted?.invoke(k) } },
                warn = ::warn,
                polled = { stallPollsForTest.addAndFetch(1) },
                looping = { d -> stallWatchLoopsForTest.update { it + d } },
                pinged = { stallPingsForTest.addAndFetch(1) },
            ).also { m ->
                monitors[conn] = m
                stallMonitorsForTest.update { it + 1 }
                H3StallMonitor.launch(monitorScope, m) { lowered ->
                    stallMonitorEndedForTest?.invoke(lowered)
                    stallMonitorsForTest.update { it - 1 }
                    stalledConnections.update { it - conn }
                    monitorScope.launch { monitorsLock.withLock { monitors.remove(conn) } }
                }
            }
        }

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

    /** Fails once the client is closed: no new endpoint, no new connection. */
    private fun ensureOpen() = check(!closed) { "the client is closed" }

    /**
     * The endpoint a connection to [remote] (an address literal) leaves from, and the address it connects to: the one bound
     * to the loopback address of its family for a loopback destination (127.0.0.0/8 and its IPv4-mapped form, sent to as
     * IPv4; ::1), else the shared one on the wildcard address and [remote] as it is. Each is bound once,
     * at its first use, and closed with the pool. The endpoints share the pool's [tickets], so a session ticket resumes
     * whichever endpoint the next connection to that server leaves from; Alt-Svc entries, the address race and the pooled
     * connections do not depend on the endpoint.
     */
    private suspend fun endpointFor(remote: InetSocketAddress): Pair<Http3Endpoint, InetSocketAddress> {
        val local = loopbackLocalFor(remote)
        val v6 = local?.ipLiteral() == "::1"
        val chosen =
            lock.withLock {
                ensureOpen()
                val bound =
                    when {
                        local == null -> endpoint
                        v6 -> loopback6
                        else -> loopback4
                    }
                bound ?: Http3Endpoint.bind(local ?: InetSocketAddress("0.0.0.0", 0), endpointConfig, config.http3.settings).also {
                    endpointBindStepForTest?.invoke(it, false)
                    // stored first, then [closed] read: [close] (which takes no lock) sets [closed] and then reads the fields,
                    // so either it sees this endpoint and closes it, or this sees [closed] and closes it here
                    when {
                        local == null -> endpoint = it
                        v6 -> loopback6 = it
                        else -> loopback4 = it
                    }
                    endpointBindStepForTest?.invoke(it, true)
                    if (closed) {
                        it.close()
                        when {
                            local == null -> endpoint = null
                            v6 -> loopback6 = null
                            else -> loopback4 = null
                        }
                        throw IllegalStateException("the client is closed")
                    }
                }
            }
        endpointChosenForTest?.invoke(remote, chosen)
        // an IPv4-mapped loopback address (`::ffff:127.0.0.1`) is sent to as IPv4 from the IPv4 loopback endpoint
        return chosen to if (local != null && !v6) remote.unmappedLiteral() else remote
    }

    /** Test hook: the open connections, then forgets them so the next request connects again (a 0-RTT resumption). */
    internal suspend fun dropConnectionsForTest(): List<Http3Connection> =
        lock.withLock {
            val l = connections.values.distinct().mapNotNull { it.deferred.getCompletedOrNull() }
            connections.clear()
            l
        }

    /** Test hook: the open connections. */
    internal suspend fun connectionsForTest(): List<Http3Connection> =
        lock.withLock {
            connections.values.distinct().mapNotNull { it.deferred.getCompletedOrNull() }
        }

    /**
     * Test hook: the use of each pooled connection (retired ones and extra WebTransport connections aside), as (set up
     * WebTransport-capable, requests and sessions using it). Uses rise before the request or session is handed out, so they
     * read at once; they fall at a release, which [releasesForTest] counts, so a test waits for a fall without polling.
     */
    internal suspend fun activeForTest(): List<Pair<Boolean, Int>> =
        lock.withLock { connections.values.distinct().map { it.webTransport to it.active.load() } }

    /** Test hook: the releases of every connection's use so far (see [activeForTest]). */
    internal val releasesForTest = kotlinx.coroutines.flow.MutableStateFlow(0L)

    private fun noteReleased() {
        releasesForTest.update { it + 1 }
    }

    /** Entries of the connection map, retired ones included, open or not (the resource probe). */
    internal suspend fun connectionsForProbe(): Int =
        lock.withLock { (connections.values + retired + wtExtras.values.flatten()).distinct().size }

    /** Test hook: the (origin, alternative) entries tracked, retired ones included. */
    internal suspend fun entryCountForTest(): Int =
        lock.withLock { (connections.values + retired + wtExtras.values.flatten()).distinct().size }

    /** Test hook: whether an endpoint (the shared one or a loopback one) is bound. */
    internal val endpointBoundForTest: Boolean get() = endpoint != null || loopback4 != null || loopback6 != null

    /** WebTransport sessions of this client, open or being set up (the `maxWebTransportSessions` cap, a test hook and the resource probe). */
    internal val webTransportSessions = kotlinx.coroutines.flow.MutableStateFlow(0)

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private val maxSessions = config.http3.maxWebTransportSessions

    init {
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        require(config.http3.maxWebTransportSessions >= 1) {
            "http3.maxWebTransportSessions must be at least 1, not ${config.http3.maxWebTransportSessions}"
        }
    }

    /** The engine's HTTP/3 settings with WebTransport and Extended CONNECT on: a WebTransport-capable connection's. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private val wtSettings: io.kuicksilver.http3.Http3Settings =
        config.http3.settings
            .toBuilder()
            .apply {
                enableConnectProtocol = true
                webTransport = true
            }.build()

    /**
     * WebTransport-capable connections beyond the pooled one of their (origin, address) key, by key: made when the server
     * refused another session on the pooled one (its limit, draft-16 section 5.2) or a session could not join it (no flow
     * control, section 5.1). Sessions share them too; each closes with its last session (it is retired from the start).
     * Under [lock].
     */
    private val wtExtras = HashMap<String, MutableList<H3Entry>>()

    /**
     * Test hook: runs in [webTransport] once a connection was picked, before the CONNECT ("connection"), and once the
     * session is open, before it is tracked ("connected").
     */
    internal var webTransportStepForTest: (suspend (step: String) -> Unit)? = null

    /**
     * A WebTransport session to [url] (`HttpClient.webTransport`): on the pooled WebTransport-capable connection of the URL's
     * host and port (RFC 9114 section 3.3), made or swapped in for a request-only one as needed ([connectionEntryOnce]),
     * else on an extra one with room, else on a new extra one. A connection the session cannot join is passed over: the
     * HTTP/3 layer refuses a second session without flow control or beyond `webTransportMaxSessions`
     * ([io.kuicksilver.http3.WebTransportException.ConnectionFull]), and a server's H3_REQUEST_REJECTED (its limit, section 5.2; nothing of the
     * request was processed, RFC 9114 section 4.1.1) marks the connection full at its current count. At most two refusals,
     * then the server's answer is the caller's. At most `maxWebTransportSessions` sessions are open at once; one more fails
     * at once (IllegalStateException), nothing queues.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    suspend fun webTransport(
        url: io.ktor.http.Url,
        request: io.kuicksilver.http3.Http3Request,
        protocols: List<String>,
        connectTimeoutMillis: Long,
    ): io.kuicksilver.http3.WebTransportSession {
        check(!refusingWebTransport && !closed) { "the client is closed" }
        while (true) {
            val n = webTransportSessions.value
            check(n < maxSessions) { "maxWebTransportSessions ($maxSessions) WebTransport sessions are open on this client" }
            if (webTransportSessions.compareAndSet(n, n + 1)) break
        }
        var handedOut = false
        try {
            val t = H3Target(url.host, url.host, url.port)
            val data =
                io.ktor.client.request
                    .HttpRequestBuilder()
                    .apply {
                        this.url.takeFrom(url)
                        method = HttpMethod("CONNECT")
                    }.build()
            val dns = config.newRequestDns(events.dnsObserver(data))
            val passed = HashSet<H3Entry>()
            var refusals = 0
            var lost = 0
            // one deadline for every connection this call sets up or waits for, however many it tries
            val deadline =
                kotlin.time.TimeSource.Monotonic
                    .markNow() + connectTimeoutMillis.milliseconds
            while (true) {
                val (e, c) = sessionConnection(t, data, dns, passed, connectTimeoutMillis, deadline)
                val session =
                    try {
                        webTransportStepForTest?.invoke("connection")
                        c.webTransport(request, protocols)
                    } catch (x: Throwable) {
                        e.release(clock())
                        when {
                            x is io.kuicksilver.http3.WebTransportException.ConnectionFull -> {
                                passed += e
                                continue
                            }

                            x is Http3Exception.RequestNotProcessed && x.neverSent && e.drained -> {
                                throw IllegalStateException(
                                    "WebTransport CONNECT not sent: HttpClient.closeHttp3Connections() took HTTP/3 out of use while " +
                                        "the session was being set up; call webTransport again (or fall back) once HTTP/3 should be used",
                                    x,
                                )
                            }

                            x is Http3Exception.RequestNotProcessed -> {
                                // the server refused it unprocessed (its session limit) or sent GOAWAY: another connection.
                                // A refusal while none of our sessions is on the connection is no session limit (its rate,
                                // section 5.2, or its own reasons): another connection would only start a fresh budget there
                                if (!x.neverSent && e.wtSessions.load() == 0) throw x
                                if (!x.neverSent) e.wtFullAt = e.wtSessions.load()
                                passed += e
                                if (++refusals > 2) throw x
                                continue
                            }

                            // the connection ended as the session joined it (its last user had just left it): another one
                            (c.ended() || x is io.kuicksilver.quic.QuicException.ConnectionLost) && ++lost <= 2 -> {
                                passed += e
                                continue
                            }

                            else -> {
                                throw x
                            }
                        }
                    }
                e.wtSessions.addAndFetch(1)
                handedOut = true
                webTransportStepForTest?.invoke("connected")
                track(session, c, e)
                return session
            }
        } finally {
            if (!handedOut) webTransportSessions.update { it - 1 }
        }
    }

    /** Whether a new session may be tried on this entry's connection [c]: usable, not drained, below the count a server refused. */
    private fun H3Entry.takesSessions(c: Http3Connection): Boolean =
        c.usable() && !drained && (wtFullAt < 0 || wtSessions.load() < wtFullAt)

    /**
     * The connection to try a session to [t] on, counted as in use ([H3Entry.active]): the pooled one, else an extra one,
     * else a new extra one, none of [passed].
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private suspend fun sessionConnection(
        t: H3Target,
        data: HttpRequestData,
        dns: RequestDns,
        passed: Set<H3Entry>,
        connectTimeoutMillis: Long,
        deadline: kotlin.time.TimeMark,
    ): Pair<H3Entry, Http3Connection> {
        val (main, mc) = acquire(t, data, dns, wt = true)
        if (main !in passed && main.takesSessions(mc)) return main to mc
        main.release(clock())
        // an extra connection with room, one still being set up included (sessions racing past a full connection share
        // one new connection instead of opening one each, RFC 9114 section 3.3), else a new one; counted under the lock
        val perConnection = wtSettings.webTransportMaxSessions
        val (e, made) =
            lock.withLock {
                val found =
                    wtExtras[t.key]?.firstOrNull { e ->
                        e !in passed &&
                            if (e.deferred.isCompleted) {
                                e.deferred.getCompletedOrNull()?.let { e.takesSessions(it) } == true
                            } else {
                                e.active.load() < perConnection
                            }
                    }
                if (found != null) {
                    found.active.addAndFetch(1)
                    found to false
                } else {
                    val e = H3Entry(CompletableDeferred(), clock(), webTransport = true, released = ::noteReleased)
                    e.active.addAndFetch(1)
                    e.retire() // kept for the sessions of [t] and closed with its last one
                    wtExtras.getOrPut(t.key) { ArrayList() } += e
                    e to true
                }
            }
        if (made) {
            try {
                val c = connectWebTransport(t.originHost, t.port, dns, connectTimeoutMillis, deadline)
                c.closed.invokeOnCompletion { launchUnderLock { wtExtras[t.key]?.remove(e) } }
                e.deferred.complete(c)
            } catch (x: Throwable) {
                // the sessions waiting for it try another connection; our own cancellation is not theirs
                e.deferred.completeExceptionally(if (x is CancellationException) SetupGivenUp(x) else x)
                withContext(NonCancellable) { lock.withLock { wtExtras[t.key]?.remove(e) } }
                e.release(clock())
                throw x
            }
        }
        if (!made) {
            try {
                e.deferred.await()
            } catch (x: Throwable) {
                e.release(clock())
                currentCoroutineContext().ensureActive()
                // the setup another session started failed: its failure is this one's too (trying again would make each
                // waiter spend a timeout of its own); only a setup its caller gave up is tried again, within the deadline
                if (x !is SetupGivenUp) throw x
                return sessionConnection(t, data, dns, passed + e, connectTimeoutMillis, deadline)
            }
        }
        return e to e.deferred.getCompletedOrNull()!!
    }

    /** A setup of an extra connection its caller gave up: the sessions waiting for it try again. */
    private class SetupGivenUp(
        cause: Throwable,
    ) : IllegalStateException("the connection's setup was given up", cause)

    /** Test hook: runs inside the setup of an extra WebTransport connection, within its timeout. */
    internal var extraConnectForTest: (suspend () -> Unit)? = null

    /** Runs [block] under [lock] from a completion handler (which cannot suspend). */
    private fun launchUnderLock(block: () -> Unit) {
        (migrationScope ?: CoroutineScope(kotlinx.coroutines.Dispatchers.Default)).launch { lock.withLock { block() } }
    }

    /**
     * Tracks [session] on [entry]'s connection [connection] until it ends: the connection stays in use ([H3Entry.active])
     * while it is open and until its CONNECT stream ended both ways (its close capsule and FIN answered, within
     * [EXCHANGE_END_TIMEOUT]), so a connection that closes with its last user never cuts the session's close short; then
     * it idles as any pooled connection (an extra one closes). A session that opened on a connection [goAwayAll] drained
     * meanwhile is drained at once.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private suspend fun track(
        session: io.kuicksilver.http3.WebTransportSession,
        connection: Http3Connection,
        entry: H3Entry,
    ) {
        val pair = session to connection
        sessions.update { it + pair }
        session.closed.invokeOnCompletion {
            sessions.update { s -> s - pair }
            entry.wtSessions.addAndFetch(-1)
            webTransportSessions.update { n -> n - 1 }
            (migrationScope ?: CoroutineScope(kotlinx.coroutines.Dispatchers.Default)).launch {
                try {
                    withTimeoutOrNull(EXCHANGE_END_TIMEOUT) {
                        // the exchange's end, or the connection's (which ends the exchange without telling it)
                        @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
                        val exchange = launch { awaitWebTransportExchangeEnd(session) }
                        kotlinx.coroutines.selects.select {
                            exchange.onJoin {}
                            connection.closed.onAwait {}
                        }
                        exchange.cancel()
                    }
                } finally {
                    entry.release(clock())
                }
            }
        }
        if (entry.drained) {
            withTimeoutOrNull(GOAWAY_TIMEOUT) { runCatching { if (!connection.closed.isCompleted) connection.goAway() } }
            runCatching { session.drain() } // bounded by drain's own limit
        }
    }

    /**
     * A WebTransport-capable QUIC connection to [originHost]:[port] outside the pool map (an extra one): the engine's
     * endpoint, trust and QUIC settings with WebTransport, Extended CONNECT and `reset_stream_at` on (draft-16 sections 3.1,
     * 4.4). [connectTimeoutMillis] bounds the lookup and the handshakes, raced over the resolved addresses.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private suspend fun connectWebTransport(
        originHost: String,
        port: Int,
        dns: RequestDns,
        connectTimeoutMillis: Long,
        deadline: kotlin.time.TimeMark,
    ): Http3Connection {
        val left = -deadline.elapsedNow().inWholeMilliseconds
        if (left <= 0) throw ConnectTimeoutException("https://$originHost:$port", connectTimeoutMillis, null)
        ensureOpen()
        val tls = config.tlsConfigFor(originHost, listOf(Http3Endpoint.H3))
        val q = quicWithin(connectTimeoutMillis)
        // set inside the timeout: a handshake that completes as the timeout fires still lands here, never orphaned
        var made: Http3Connection? = null
        val failures = ArrayList<Throwable>()
        try {
            withTimeout(left) {
                extraConnectForTest?.invoke()
                made =
                    raceQuic(originHost, port, dns, failures) { remote ->
                        val (ep, to) = endpointFor(remote)
                        ep.connect(to, tls, q, wtSettings)
                    }
            }
        } catch (e: TimeoutCancellationException) {
            if (made == null) {
                throw ConnectTimeoutException("https://$originHost:$port", connectTimeoutMillis, e).withAttempts(failures)
            }
        } catch (e: Throwable) {
            made?.let { withContext(NonCancellable) { runCatching { it.close(io.kuicksilver.http3.Http3ErrorCode.NO_ERROR, "") } } }
            throw e
        }
        return made ?: throw ConnectTimeoutException("https://$originHost:$port", connectTimeoutMillis, null)
    }

    /**
     * Happy Eyeballs over QUIC (RFC 8305, [raceAddresses]): the handshakes to [host]'s addresses, as [dns] resolves them
     * one family at a time, sorted by RFC 6724 with the families alternating, one `connectionAttemptDelay` apart or as soon
     * as one failed; the first handshake to complete wins, the others are cancelled (a cancelled QUIC connect closes the
     * connection it started) or, when they completed too, closed. With `earlyData` an attempt returns as soon as it can
     * send 0-RTT (a resumed session): the first address of the order then wins at once and the other addresses are not
     * tried for that setup; its handshake failing later fails the requests sent on it, which then fall back as before.
     * When every attempt failed, the failure reported is a refusal (CONNECTION_REFUSED, no broken mark) only when every
     * attempt was refused, else the last attempt's other failure ([quicRaceFailure]).
     */
    private suspend fun raceQuic(
        host: String,
        port: Int,
        dns: RequestDns,
        failures: MutableList<Throwable>,
        connected: (Http3Connection, TcpAddress) -> Unit = { _, _ -> },
        connect: suspend (InetSocketAddress) -> Http3Connection,
    ): Http3Connection {
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        val delay = config.connectionAttemptDelay
        return raceAddresses(
            host,
            dns.resolution(host, port),
            delay,
            dns.order(),
            connect = { a -> connect(InetSocketAddress(a.hostText, a.port)).also { connected(it, a) } },
            close = { it.close() },
            failures = failures,
            chooseFailure = ::quicRaceFailure,
        )
    }

    /**
     * Set by the engine's `close()` itself, before its asynchronous cleanup: no new WebTransport session starts then.
     * Requests already running keep the endpoint until the cleanup ([close]) ends it.
     */
    @kotlin.concurrent.Volatile
    private var refusingWebTransport = false

    /** The client is closing: [webTransport] refuses from now on. */
    fun refuseWebTransport() {
        refusingWebTransport = true
    }

    /** Drops the pool's session tickets: the engine's cleanup calls it after [close]. */
    suspend fun closeSessions() = tickets.close()

    fun close() {
        refusingWebTransport = true
        closed = true
        endpoint?.close()
        endpoint = null
        loopback4?.close()
        loopback4 = null
        loopback6?.close()
        loopback6 = null
        fresh.clear()
    }

    /**
     * Whether [this] ended: its HTTP/3 session took note, or its QUIC transport ended before that (the session learns of
     * the end in a coroutine of its own, so for a moment its `closed` is not complete while every stream already failed).
     * A request is never handed such a connection: it would fail there and fall back to TCP instead of opening a new one.
     */
    private fun Http3Connection.ended(): Boolean = closed.isCompleted || quic.closed.isCompleted

    private fun Http3Connection.usable(): Boolean = !ended() && goAwayReceived.value == null && stalledConnections.load()[this] == null

    /** WebTransport sessions of this client and their connections ([track]), for [goAwayAll]. */
    private val sessions =
        kotlin.concurrent.atomics.AtomicReference(emptySet<Pair<io.kuicksilver.http3.WebTransportSession, Http3Connection>>())

    /** WebTransport sessions tracked (tests). */
    internal val sessionCountForTest: Int get() = sessions.load().size

    /**
     * `HttpClient.closeHttp3Connections()`. First, under the lock, every pooled connection, and every extra WebTransport
     * one, leaves the pool: an established one is drained ([H3Entry.drain]: no request or session is handed it any more,
     * and a session that opens on it after this is drained at once, [track]), one still being set up is retired (the
     * requests waiting for it use it, and it closes after the last one, or when [evictExpired] finds it unused). Then,
     * concurrently in [scope], every drained connection gets our GOAWAY (RFC 9114 section 5.2; a client announces 0, it
     * accepts no pushes; a CONNECT not sent yet then fails) within [GOAWAY_TIMEOUT] and closes at once when idle, else at its
     * last user; every tracked session gets WT_DRAIN_SESSION (draft-ietf-webtrans-http3 section 4.7) after its connection's
     * GOAWAY, within drain()'s own limit. Returns once those are written or timed out.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    suspend fun goAwayAll(scope: CoroutineScope) {
        val drained = ArrayList<Pair<H3Entry, Http3Connection>>()
        lock.withLock {
            for (e in (connections.values + wtExtras.values.flatten()).distinct()) {
                val c = e.deferred.getCompletedOrNull()
                if (c != null) {
                    e.drain()
                    drained += e to c
                } else if (!e.deferred.isCompleted) {
                    e.retire()
                }
                addRetired(e)
            }
            connections.clear()
            wtExtras.clear()
        }
        val withSession = sessions.load()
        val jobs = ArrayList<Job>()
        for ((e, c) in drained) {
            jobs +=
                scope.launch {
                    withTimeoutOrNull(GOAWAY_TIMEOUT) { runCatching { if (!c.closed.isCompleted) c.goAway() } }
                    if (withSession.none { it.second === c }) e.closeIfIdle()
                }
        }
        for ((session, c) in withSession) {
            jobs +=
                scope.launch {
                    // GOAWAY first, under its own limit; drain() has a 5 s limit of its own, after which it ends the session
                    // as failed, so it runs without an outer one that could cut it short
                    withTimeoutOrNull(GOAWAY_TIMEOUT) { runCatching { if (!c.closed.isCompleted) c.goAway() } }
                    runCatching { session.drain() }
                }
        }
        jobs.joinAll()
    }

    /**
     * Under the lock: [e] joins [retired], and leaves it as soon as its connection ended (or its setup failed), not only
     * at the next [evictExpired]: the probe and [goAwayAll] see live connections only.
     */
    private fun addRetired(e: H3Entry) {
        if (e in retired) return
        retired += e
        e.deferred.invokeOnCompletion { failed ->
            val c = e.deferred.getCompletedOrNull()
            if (failed != null || c == null) {
                launchUnderLock { retired.remove(e) }
            } else {
                c.closed.invokeOnCompletion { launchUnderLock { retired.remove(e) } }
            }
        }
    }

    private fun H3Entry.pastLifetime(now: Long): Boolean = now - createdAt >= maxLifetimeMillis

    /**
     * Under the lock: [e] takes no new requests and finishes the ones it has ([H3Entry.retire]); it leaves the map under
     * every key it was filed under (a connection [shareSameAddress] shares is filed under several), so a retired entry is
     * never in the map and [goAwayAll] and [evictExpired] see it only in [retired].
     */
    private fun retireUnderEveryKey(e: H3Entry) {
        connections.entries.removeAll { it.value === e }
        addRetired(e)
        e.retire()
    }

    /**
     * Under the lock, once [c] was set up for [t] as [e]: the connection of another live entry of the same origin (the same
     * configuration) connected to [c]'s address and port ([H3Entry.connectedTo], literals: no lookup under the lock), if any; [t] is then filed under that entry instead
     * of [e], whose waiters are handed it too ([e] leaves the pool unused). The older connection is kept: it may carry
     * requests already, [c] carries none yet.
     */
    private fun sameAddressAs(
        t: H3Target,
        e: H3Entry,
        c: Http3Connection,
    ): Http3Connection? {
        if (connections[t.key] !== e) return null
        val here = e.connectedTo ?: return null
        val now = clock()
        for ((k, other) in connections) {
            if (other === e || originOfKey(k) != t.originHost || other.drained || other.pastLifetime(now)) continue
            // a WebTransport-capable connection serves requests too, not the other way round
            if (e.webTransport && !other.webTransport) continue
            val o = other.deferred.getCompletedOrNull()?.takeIf { it.usable() } ?: continue
            val there = other.connectedTo ?: continue
            if (there.sameAs(here)) {
                connections[t.key] = other
                return o
            }
        }
        return null
    }

    /** Test hook: the connections [shareSameAddress] let a destination share (one per sharing). */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal val sharedForTest = kotlin.concurrent.atomics.AtomicInt(0)

    /**
     * RFC 9114 section 3.3: "Clients SHOULD NOT open more than one HTTP/3 connection to a given IP address and UDP port,
     * where the IP address and port might be derived from a URI, a selected alternative service (\[ALTSVC\]), a configured
     * proxy, or name resolution of any of these" and "SHOULD avoid creating multiple connections with the same
     * configuration". Before [t] gets a connection of its own, a live connection of the same origin to another destination
     * name (the origin's host, an `Alt-Svc` or HTTPS-record target, an address literal) is looked for whose current remote
     * address and port are among the addresses [t]'s name resolves to now; when one is found, [t] is filed under it and
     * shares it. The same origin means the same configuration: the TLS configuration (server_name, the name the
     * certificate is checked against, trust, client identity) is the origin's, ALPN, QUIC and HTTP/3 settings are the
     * pool's. The address compared is the literal the connection's race connected to ([H3Entry.connectedTo]: no lookup
     * ever runs for it, the comparison is under the lock; a client migration changes only the local side); the destination's
     * addresses are those of its current answers, the NAT64 synthesis of an IPv6-only network included. A setup of the
     * same origin still in its handshake is waited for first, for one Connection Attempt Delay at most. Nothing is resolved
     * when the origin has no other connection.
     */
    private suspend fun shareSameAddress(
        t: H3Target,
        dns: RequestDns,
        wt: Boolean = false,
    ) {
        val now = clock()

        fun H3Entry.shareable(): Http3Connection? = deferred.getCompletedOrNull()?.takeIf { it.usable() && !drained && !pastLifetime(now) }
        val candidates =
            lock.withLock {
                val existing = connections[t.key]
                if (existing != null && (!wt || existing.webTransport) &&
                    (!existing.deferred.isCompleted || existing.shareable() != null)
                ) {
                    return
                }
                connections.entries
                    .filter { (k, e) ->
                        k != t.key && originOfKey(k) == t.originHost && (!wt || e.webTransport) &&
                            (!e.deferred.isCompleted || e.shareable() != null)
                    }.map { it.value }
                    .distinct()
            }
        if (candidates.isEmpty()) return
        val addresses =
            try {
                dns.answeredDestinations(t.host, t.port).map(Destination::of)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Throwable) {
                return // the setup resolves again and reports the failure
            }

        // a sibling still in its handshake has no address yet: its outcome is waited for, for one Connection Attempt Delay
        // at most (RFC 8305 section 5, 250 ms by default), so two names of one address set up at once end as one
        // connection, while a sibling whose handshake stalls (a black-holed alternative) does not hold this one up longer
        // than Happy Eyeballs holds up its next address
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        val waitAtMost = config.connectionAttemptDelay
        withTimeoutOrNull(waitAtMost) {
            for (e in candidates) {
                e.deferred.join() // completes failed or not: a failed setup is only no candidate
            }
        }
        val match =
            candidates.firstOrNull { e ->
                val remote = e.shareable()?.let { e.connectedTo }
                remote != null && addresses.any { it.sameAs(remote) }
            } ?: return
        lock.withLock {
            val existing = connections[t.key]
            if (existing != null && (!wt || existing.webTransport) && (!existing.deferred.isCompleted || existing.shareable() != null)) {
                return
            }
            if (match.shareable() == null || connections.values.none { it === match }) return
            // a replaced connection of [t] past its lifetime finishes its requests first, as when a new one replaces it
            val old = existing?.deferred?.getCompletedOrNull()
            if (existing != null && old != null && old.usable()) {
                retireUnderEveryKey(existing)
            }
            connections[t.key] = match
            sharedForTest.addAndFetch(1)
        }
    }

    /** An open connection to [t], connecting (once, shared by concurrent callers) when needed. */
    suspend fun connection(
        t: H3Target,
        data: HttpRequestData,
        dns: RequestDns = config.newRequestDns(events.dnsObserver(data)),
    ): Http3Connection = connectionEntry(t, data, dns).second

    private suspend fun connectionEntry(
        t: H3Target,
        data: HttpRequestData,
        dns: RequestDns,
        wt: Boolean = false,
    ): Pair<H3Entry, Http3Connection> {
        while (true) {
            try {
                return connectionEntryOnce(t, data, dns, wt)
            } catch (_: SetupAbandoned) {
                // the caller that was setting the connection up was cancelled: not a failure of the origin, so this caller
                // starts (or joins) a new setup instead of failing or falling back
            }
        }
    }

    /** Test hook: runs in a request that holds a connection, before it waits for the handshake or opens its stream. */
    internal var afterAcquireForTest: (suspend () -> Unit)? = null

    /** Test hook: in [acquire], after a connection was looked up and before it is counted as in use. */
    internal var beforeCountForTest: (suspend (Http3Connection) -> Unit)? = null

    /** Test hook: runs in the caller that sets up a connection, before it connects. */
    internal var beforeSetupForTest: (suspend () -> Unit)? = null

    /** Test hook: runs once a setup's race made its connection, still inside the connect timeout. */
    internal var setupMadeForTest: (suspend () -> Unit)? = null

    /** A setup whose race made no connection within the connect timeout. */
    private class SetupTimedOut : Exception("no QUIC connection within the connect timeout")

    /** Test hook: callers that waited for a setup another caller started. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal val setupWaitersForTest = kotlin.concurrent.atomics.AtomicInt(0)

    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private suspend fun connectionEntryOnce(
        t: H3Target,
        data: HttpRequestData,
        dns: RequestDns,
        wt: Boolean = false,
    ): Pair<H3Entry, Http3Connection> {
        ensureOpen()
        shareSameAddress(t, dns, wt)
        val (e, connect) =
            lock.withLock {
                val existing = connections[t.key]
                val done = existing?.deferred?.takeIf { it.isCompleted }?.getCompletedOrNull()
                // a WebTransport session needs a WebTransport-capable connection; a request takes either kind
                val fits = existing == null || !wt || existing.webTransport
                if (existing != null && fits &&
                    (!existing.deferred.isCompleted || (done != null && done.usable() && !existing.pastLifetime(clock())))
                ) {
                    existing to false
                } else {
                    // past its lifetime, or not WebTransport-capable when a session needs it (RFC 9114 section 3.3: one
                    // connection per origin, the capable one serving the requests from now on): it finishes what it carries
                    // first ([evictExpired] closes it); one still being set up is closed once set up and unused
                    if (existing != null && ((done != null && done.usable()) || !existing.deferred.isCompleted)) {
                        retireUnderEveryKey(existing)
                    }
                    H3Entry(CompletableDeferred(), clock(), webTransport = wt, released = ::noteReleased)
                        .also { connections[t.key] = it } to true
                }
            }
        val d = e.deferred
        if (connect) {
            // set inside the timeout: a handshake that completes as the timeout fires is closed, never orphaned
            var made: Http3Connection? = null
            val failures = ArrayList<Throwable>()
            // the connections the race's attempts made, with the literal each went to: the winner's is kept on the entry
            val attempts = kotlin.concurrent.atomics.AtomicReference(emptyList<Pair<Http3Connection, Destination>>())
            try {
                beforeSetupForTest?.invoke()
                // a connection the race made as the connect timeout fires is the connection: made is set as the race
                // returns, though withTimeoutOrNull drops the block's end when its timeout lands after it
                withTimeoutOrNull(data.connectTimeoutMillis(config)) {
                    // every address of the request's resolution, raced (RFC 8305), each as a literal the endpoint does not
                    // look up again
                    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                    made =
                        raceQuic(t.host, t.port, dns, failures, { won, a ->
                            attempts.update { it + (won to Destination.of(a)) }
                        }) { destination ->
                            val (ep, remote) = endpointFor(destination)
                            if (wt) {
                                // never 0-RTT: a WebTransport CONNECT does not go early (draft-16 section 3.2)
                                ep.connect(remote, config.tlsConfigFor(t.originHost, listOf(Http3Endpoint.H3)), quic, wtSettings)
                            } else if (config.http3.earlyData) {
                                // returns as soon as 0-RTT keys exist: the connect timeout still bounds the setup, through
                                // the handshake timer (a request sent early then fails, and falls back, at that time)
                                ep
                                    .connectEarly(
                                        remote,
                                        config.tlsConfigFor(t.originHost, listOf(Http3Endpoint.H3)),
                                        quicWithin(data.connectTimeoutMillis(config)),
                                        config.http3.settings,
                                    )
                            } else {
                                ep
                                    .connect(
                                        remote,
                                        config.tlsConfigFor(t.originHost, listOf(Http3Endpoint.H3)),
                                        quic,
                                        config.http3.settings,
                                    )
                            }
                        }
                    setupMadeForTest?.invoke()
                }
                val c = made ?: throw SetupTimedOut()
                e.connectedTo = attempts.load().firstOrNull { it.first === c }?.second
                e.idleSince.store(clock())
                // RFC 9114 section 3.3: a setup of the same origin to the same address that finished meanwhile (both ran
                // past each other's wait) keeps that one; this connection is closed before any request used it. The check
                // and the completion are one step under the lock: a setup finishing right after this one sees it complete
                val kept =
                    lock.withLock {
                        sameAddressAs(t, e, c).also { k ->
                            if (k != null) {
                                d.complete(k)
                            } else {
                                if (events.enabled) {
                                    fresh.removeAll { it.ended() } // closed before any exchange used them
                                    fresh += c
                                }
                                d.complete(c)
                            }
                        }
                    }
                if (kept != null) {
                    sharedForTest.addAndFetch(1)
                    withContext(NonCancellable) { runCatching { c.close() } }
                    return e to kept
                }
                followNetwork(c, data)
                followPreferredAddress(e, c)
            } catch (
                x: SetupTimedOut,
            ) {
                d.completeExceptionally(ConnectTimeoutException(data, x).withAttempts(failures))
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

    /** Test hook: preferred-address moves [followPreferredAddress] recorded. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal val preferredMovesForTest = kotlin.concurrent.atomics.AtomicInt(0)

    /**
     * Keeps [e]'s [H3Entry.connectedTo] where [c] goes: when the server moves it to its preferred address (RFC 9000
     * section 9.6, `followPreferredAddress`; the only way a client connection's remote address changes, a client migration
     * changes the local side), the new path's address replaces the race's, so the comparisons of RFC 9114 section 3.3 see
     * the address the connection uses. Collected outside the pool's lock in [migrationScope] until [c] ends: the active
     * path as the collection starts (a move right after the handshake may come before it), then every path change. The
     * path's address is the literal of the transport parameter; its bytes are read without a name lookup.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private fun followPreferredAddress(
        e: H3Entry,
        c: Http3Connection,
    ) {
        val scope = migrationScope ?: return

        fun follow(path: io.kuicksilver.quic.QuicPath?) {
            val r = path?.remoteAddress ?: return
            val bytes = runCatching { r.resolveAddress() }.getOrNull()?.takeIf { it.size == 4 || it.size == 16 } ?: return
            val now = e.connectedTo
            val there =
                Destination(
                    unmapped(bytes),
                    r.port,
                    if (now != null &&
                        now.bytes.contentEquals(unmapped(bytes))
                    ) {
                        now.scopeId
                    } else {
                        0
                    },
                )
            if (now == null || !now.sameAs(there)) {
                e.connectedTo = there
                preferredMovesForTest.addAndFetch(1)
            }
        }
        val job =
            scope.launch(start = CoroutineStart.UNDISPATCHED) {
                launch(start = CoroutineStart.UNDISPATCHED) {
                    c.quic.pathEvents.collect { ev -> if (ev is io.kuicksilver.quic.PathEvent.Changed) follow(ev.new) }
                }
                follow(c.quic.activePath ?: c.quic.paths.firstOrNull())
            }
        c.closed.invokeOnCompletion { job.cancel() }
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
        wt: Boolean = false,
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
            val (e, c) = connectionEntry(t, data, dns, wt)
            beforeCountForTest?.invoke(c)
            val counted =
                lock.withLock {
                    when {
                        // stalled since it was looked up: dropped from the pool, and no request goes on it any more
                        stalledConnections.load()[c] != null -> null

                        (connections[t.key] === e || (e in retired && !e.drained)) && !c.ended() -> {
                            e.active.addAndFetch(1)
                            true
                        }

                        else -> false
                    }
                }
            // the alternative just stalled: this request was not sent, so it goes over TCP whatever its method
            if (counted == null) throw stalledConnections.load().getValue(c).exception(null)
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
                if (c == null || c.ended()) {
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

                    c == null || c.ended() -> {
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
        toClose.distinct().forEach { it.close() }
        return next
    }

    /** The open, usable connection to [t], if one exists (no connection attempt). */
    suspend fun existing(t: H3Target): Http3Connection? =
        lock
            .withLock { connections[t.key] }
            ?.deferred
            ?.getCompletedOrNull()
            ?.takeIf { it.usable() }

    /**
     * Whether an open connection to [t] exists that may still carry a new request (no GOAWAY from its peer, after which
     * this client opens no new request on it, RFC 9114 section 5.2, as [usable] says) and whose peer accepts Extended
     * CONNECT (WebSockets over HTTP/3, RFC 9220).
     */
    suspend fun canConnectProtocol(t: H3Target): Boolean =
        lock.withLock { connections[t.key] }?.deferred?.getCompletedOrNull()?.let {
            it.usable() &&
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
        dns: RequestDns = config.newRequestDns(events.dnsObserver(data)),
        prefer: Http3Connection? = null,
        // stall detection (`http3 { stallDetection }`): where TCP is the way out, never for a WebSocket
        watchStall: Boolean = false,
    ): HttpResponseData {
        var attempts = 0
        data.attributes.remove(H3ClosedAfterGoAwayKey) // a mark of an earlier execution of the same request data
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        val watched = watchStall && config.http3.stallDetection && !data.attributes.contains(WEBSOCKETS_KEY)
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
            var watch: H3StallMonitor.Watch? = null
            try {
                // from before the wait for the handshake: a request on a 0-RTT connection into a path that drops UDP
                // a connection that stalled since it was handed out: the request was not sent (H3NotSent below)
                if (watched) {
                    watch =
                        try {
                            monitorFor(conn).watch("${io.kuicksilver.ktor.client.originKeyOf(data.url)}|${t.host}:${t.port}")
                        } catch (e: io.kuicksilver.ktor.client.QuicStalledException) {
                            throw H3NotSent(e)
                        }
                }
                afterAcquireForTest?.invoke()
                // a request that cannot go in 0-RTT waits for the handshake here, before any stream is opened or its body
                // touched: a handshake that fails leaves it provably unsent (RFC 8470 section 4 — the client starts over)
                @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                if (!conn.quic.isHandshakeComplete && !goesEarly(data)) {
                    try {
                        // a stall during the wait ends it: the request was not sent, it goes over TCP whatever its method
                        val w = watch
                        if (w != null) w.abortable { conn.quic.awaitHandshake() } else conn.quic.awaitHandshake()
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
                        exchange(conn, data, callContext, extraHeaders, watch)
                    }
                // in use until the call ends (its body read or abandoned), not just until the response head; a WebSocket
                // until its session ended, which may be after the call (WebSocketLifetime): a connection whose count fell to
                // 0 is closed when retired or idle, and the session may still be writing its Close on it
                val session =
                    if (r.statusCode ==
                        HttpStatusCode.SwitchingProtocols
                    ) {
                        data.attributes.getOrNull(WebSocketLifetimeKey)
                    } else {
                        null
                    }
                val job = callContext[Job]
                when {
                    session != null -> {
                        watch?.end()
                        session.invokeOnEnd { entry.release(clock()) }
                    }

                    job == null -> {
                        watch?.end()
                        entry.release(clock())
                    }

                    else -> {
                        val w = watch
                        job.invokeOnCompletion {
                            w?.end()
                            entry.release(clock())
                        }
                    }
                }
                return r
            } catch (e: Throwable) {
                watch?.end()
                entry.release(clock())
                // every connectionAcquired gets its connectionReleased, also when the exchange failed before a response
                if (reported) {
                    events.emit(
                        "connectionReleased",
                    ) { connectionReleased(data, HttpProtocolVersion.HTTP_3_0, kept = !conn.ended()) }
                }
                // the server sent GOAWAY, then closed the connection under this request with H3_NO_ERROR (a stopping server at
                // the end of its grace period): an orderly close (RFC 9114 section 5.2), not a failure of the alternative
                if (conn.goAwayReceived.value != null && isPeerShutdownClose(e)) data.attributes.put(H3ClosedAfterGoAwayKey, Unit)
                // the connection stalled under the request: the stall is the failure, with what the request saw as its cause
                val stall = watch?.stall
                val named = e is io.kuicksilver.ktor.client.QuicStalledException || e.cause is io.kuicksilver.ktor.client.QuicStalledException
                if (stall != null && e !is CancellationException && !named) {
                    throw if (e is H3NotSent) H3NotSent(stall.exception(e.cause)) else stall.exception(e)
                }
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
        watch: H3StallMonitor.Watch? = null,
    ): HttpResponseData {
        val requestTime = GMTDate()
        val body = data.body.unwrap()
        // the socket timeout measures inactivity (Ktor: "maximum time of inactivity between two data packets"): the body
        // goes out while the response is awaited, and every piece of it the stream takes restarts the timer
        val activity = data.socketTimeoutMillis()?.let { Activity() }
        // a request that may be repeated (RFC 9110 section 9.2.2) waits for its response only until a stall: then it goes
        // over TCP; any other request waits on, for the path to come back or the stall to be abandoned
        val repeatable = data.method.isIdempotent() && data.body.isReplayable()
        val response: Http3Response =
            withSocketInactivityTimeout(data, activity) {
                val w = watch
                if (w != null && repeatable) {
                    w.abortable(discard = { it.cancel() }) { send(conn, data, callContext, extraHeaders, body, activity) }
                } else {
                    send(conn, data, callContext, extraHeaders, body, activity)
                }
            }
        data.attributes.put(PriorityUpdaterKey, response.priorityUpdater()) // for HttpResponse.updatePriority
        // a stall abandoned while the body is read fails the read with QuicStalledException, before the connection's close does;
        // once the whole response arrived the exchange needs the network no more, and a stall must not touch it
        watch?.onAbandon { response.body.cancel(it) }
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        response.bodyReceived?.invokeOnCompletion { cause ->
            watch?.end(completed = cause == null)
            if (watch != null) receivedForTest?.invoke()
        }
        return finish(conn, data, callContext, response, requestTime)
    }

    @OptIn(InternalAPI::class)
    private suspend fun send(
        conn: Http3Connection,
        data: HttpRequestData,
        callContext: CoroutineContext,
        extraHeaders: List<Pair<String, String>>,
        body: OutgoingContent,
        activity: Activity?,
    ): Http3Response =
        conn.request(
            http3Request(data.method.value, data.url.authority(), data.url.h3Path()) {
                headers =
                    (headersOf(data, body) + Http3Headers(extraHeaders)).let { h ->
                        val marked = data.attributes.getOrNull(io.kuicksilver.ktor.client.NeverIndexKey).orEmpty()
                        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                        if (marked.isEmpty()) h else h.withNeverIndexed(*marked.toTypedArray())
                    }
                this.body = bodyChannel(body, callContext)?.let { b -> activity?.let { ConsumedBody(b, it) } ?: b }
                @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                allowEarlyData = config.http3.earlyData
                priority = data.priority
            },
        )

    @OptIn(InternalAPI::class)
    private fun finish(
        conn: Http3Connection,
        data: HttpRequestData,
        callContext: CoroutineContext,
        response: Http3Response,
        requestTime: GMTDate,
    ): HttpResponseData {
        callContext[Job]?.invokeOnCompletion { cause ->
            // the call is over: an unread rest of the body is abandoned (STOP_SENDING); a reader still waiting sees why
            // (the request timeout, the caller's exception), not the stream's cancellation (found by the vendored contract)
            if (cause != null) response.body.cancel(cause) // as the HTTP/1.1 body: closed with the call's own cancellation
            response.cancel()
            events.emit("connectionReleased") { connectionReleased(data, HttpProtocolVersion.HTTP_3_0, kept = !conn.ended()) }
        }
        val status = HttpStatusCode.fromValue(response.status)
        val headers = HeadersBuilder().apply { for ((n, v) in response.headers.fields) append(n, v) }.build()
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        response.headers.neverIndexed.takeIf { it.isNotEmpty() }?.let {
            data.attributes.put(io.kuicksilver.ktor.client.NeverIndexedReceivedKey, it)
        }
        val noBody = data.method == HttpMethod.Head || status == HttpStatusCode.NoContent || status == HttpStatusCode.NotModified
        val bodyChannel: ByteReadChannel = if (noBody) ByteReadChannel.Empty else response.body.withSocketTimeout(data)
        val responseBody: Any =
            data.attributes.getOrNull(ResponseAdapterAttributeKey)?.adapt(data, status, headers, bodyChannel, data.body, callContext)
                ?: bodyChannel
        return HttpResponseData(status, requestTime, headers, HttpProtocolVersion.HTTP_3_0, responseBody, callContext)
    }

    /**
     * RFC 9220: Extended CONNECT with `:protocol = websocket`; the 2xx is reported as 101 so Ktor's plugin accepts it.
     * The handshake is a WebSocket CONNECTING (RFC 6455 section 4.1 step 2: "There MUST be no more than one connection in
     * a CONNECTING state"): it holds the URL's name and the address of the connection it uses, shared with HTTP/1.1, from before
     * the CONNECT goes out until the server answered it, the attempt failed, or the connect timeout passed (then
     * `ConnectTimeoutException`), so a second WebSocket to the host, over either protocol, waits for it at most that long.
     */
    @OptIn(InternalAPI::class)
    private suspend fun webSocket(
        conn: Http3Connection,
        data: HttpRequestData,
        callContext: CoroutineContext,
        extraHeaders: List<Pair<String, String>>,
    ): HttpResponseData {
        val requestTime = GMTDate()
        val headers =
            Http3Headers(headersOf(data, data.body.unwrap()).fields.filter { it.first !in WS_HOP_BY_HOP } + extraHeaders).let { h ->
                val marked = data.attributes.getOrNull(io.kuicksilver.ktor.client.NeverIndexKey).orEmpty()
                @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                if (marked.isEmpty()) h else h.withNeverIndexed(*marked.toTypedArray())
            }
        val millis = data.connectTimeoutMillis(config)
        // the keys of the remote host: the URL's name and the address the QUIC connection actually goes to (no lookup)
        val quic = conn.quic
        val path = quic.paths.firstOrNull { it.id == quic.stats.currentPath } ?: quic.paths.firstOrNull()
        val keys =
            listOfNotNull(
                WebSocketConnecting.nameKey(data.url.host),
                WebSocketConnecting.peerIp(path?.remoteAddress)?.let { WebSocketConnecting.ipKey(it) },
            )
        val held = webSocketConnecting.acquire(keys)
        // the answer must come within the connect timeout, as over HTTP/1.1: a server that never answers holds the host's
        // other WebSockets back for at most that long (cancelling the CONNECT resets its stream)
        // kept as soon as it exists (on the connection's dispatcher, before connect returns): a CONNECT answered as the
        // deadline fires is a stream that exists on both sides, kept and used. Before, it was dropped, also when the
        // deadline landed as connect's withContext returned (it then reset the stream), and stayed open with nobody to end it
        var kept: Http3Stream? = null
        val stream =
            try {
                withTimeoutOrNull(millis) {
                    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
                    conn.connect(
                        http3Request("CONNECT", data.url.authority(), data.url.h3Path()) {
                            this.headers = headers
                            priority = data.priority
                        },
                        "websocket",
                    ) {
                        kept = it
                        webSocketConnectedForTest?.invoke()
                    }
                }
                kept ?: throw io.ktor.client.network.sockets.ConnectTimeoutException(
                    "The WebSocket was not connected within the connect timeout [url=${data.url}, connect_timeout=$millis ms]",
                    null,
                )
            } catch (e: CancellationException) {
                // the call itself was cancelled: a stream kept meanwhile is ended here, as connect would have
                kept?.let {
                    it.reset(io.kuicksilver.http3.Http3ErrorCode.REQUEST_CANCELLED)
                    it.stopSending(io.kuicksilver.http3.Http3ErrorCode.REQUEST_CANCELLED)
                }
                throw e
            } finally {
                held.release()
            }
        // the session runs under a job of its own, so that a Close it queued is written even when the call is cancelled
        // right after (Ktor's webSocketSession() always ends so; WebSocketLifetime); the extensions' state lives as long
        val lifetime = WebSocketLifetime(data, callContext, webSocketCloseWaitMillis)
        // the session's channel to the stream: its FIN is sent here, after the session; the frame guard stops reading at
        // the server's Close, and what follows it is read and dropped here
        val heldEnd = HeldTransportEnd(stream.output)
        val inputDone = CompletableDeferred<Unit>()
        // the stream ends as RFC 9220 section 3 maps RFC 6455's TCP close onto it ("Orderly TCP-level closures are
        // represented as a FIN bit on the stream ... RST exceptions are represented with a stream error ... of type
        // H3_REQUEST_CANCELLED"), the server's first (RFC 6455 section 7.1.1: a client "SHOULD wait for a TCP Close from
        // the server"; RFC 9114 section 4.4: "clients SHOULD NOT close a stream for sending while they still expect to
        // receive data from the target of the CONNECT"). A session that ended in order keeps its FIN back until the
        // server's FIN, at most T2 (WebSocketLifetime), then sends it; a server still silent then is stopped with
        // H3_REQUEST_CANCELLED once one more close wait has passed. A peer's STOP_SENDING meanwhile is answered with
        // RESET_STREAM by the transport (RFC 9000 section 3.5). A session that did not end in order gets a FIN when its
        // stream is whole (the frame guard between frames: a writer that ended says nothing, Ktor's ends its channel in order
        // also when cancelled inside a frame) and the close wait did not cut it (a session cancelled by its call: its Close,
        // if any, may still be in flight, and a RESET_STREAM could discard it) or, cut, everything it wrote was handed to
        // QUIC's send buffer; it is reset otherwise, so nothing it queued leaves after T1, and stopped. As over HTTP/1.1
        // (h3WebSocketStreamEnd, webSocketTransportEnd)
        var guard: io.ktor.utils.io.ByteWriteChannel? = null
        lifetime.invokeOnEnd { cause ->
            val failed = stream.output.closedCause != null
            val writerDone = heldEnd.endRequested && !failed
            val atFrameBoundary = guard?.isAtWebSocketFrameBoundary() == true
            // nothing waits in front of QUIC's send buffer: what the session wrote was all handed to the stream
            val drained = stream.contentHandedToTransport == heldEnd.handed
            val end = h3WebSocketStreamEnd(cause == null, failed, writerDone, atFrameBoundary, drained, lifetime.cutByCloseWait)
            webSocketEndForTest?.invoke(end, writerDone, atFrameBoundary)
            try {
                if (end == io.kuicksilver.ktor.client.h1.WebSocketTransportEnd.AfterServer) {
                    webSocketClosingForTest?.invoke("waiting")
                    // true: the server's FIN; false: the server reset its direction, an abort (RFC 9220 section 3: "RST
                    // exceptions are represented with a stream error"), which gets no clean FIN after it but a reset, as
                    // over HTTP/2; null: T2 passed. An end read as T2 fires is the end: dropped, a reset was answered with a FIN
                    val serverEnded =
                        completedWithin(lifetime.remainingTransportWaitMillis().milliseconds) {
                            inputDone.join()
                            discardToEnd(stream.input).also { webSocketServerEndForTest?.invoke() }
                        }
                    webSocketClosingForTest?.invoke(
                        when (serverEnded) {
                            true -> "server ended"
                            false -> "server reset"
                            null -> "T2"
                        },
                    )
                    if (serverEnded == false) {
                        stream.reset(io.kuicksilver.http3.Http3ErrorCode.REQUEST_CANCELLED)
                    } else {
                        withTimeoutOrNull(lifetime.closeWait) { runCatching { stream.output.flushAndClose() } }
                        if (serverEnded == null && withTimeoutOrNull(lifetime.closeWait) { discardToEnd(stream.input) } == null) {
                            stream.stopSending(io.kuicksilver.http3.Http3ErrorCode.REQUEST_CANCELLED)
                        }
                    }
                } else {
                    if (end == io.kuicksilver.ktor.client.h1.WebSocketTransportEnd.Orderly) {
                        withTimeoutOrNull(lifetime.closeWait) { runCatching { stream.output.flushAndClose() } }
                    } else {
                        stream.reset(io.kuicksilver.http3.Http3ErrorCode.REQUEST_CANCELLED)
                    }
                    if (!(stream.input.isClosedForRead && stream.input.closedCause == null)) {
                        stream.stopSending(io.kuicksilver.http3.Http3ErrorCode.REQUEST_CANCELLED)
                    }
                }
            } catch (e: CancellationException) {
                // cut by the end handlers' bound: both directions are let go now
                if (!stream.output.isClosedForWrite) stream.reset(io.kuicksilver.http3.Http3ErrorCode.REQUEST_CANCELLED)
                if (!stream.input.isClosedForRead) stream.stopSending(io.kuicksilver.http3.Http3ErrorCode.REQUEST_CANCELLED)
                throw e
            } finally {
                events.emit("connectionReleased") { connectionReleased(data, HttpProtocolVersion.HTTP_3_0, kept = !conn.ended()) }
            }
        }

        // a refused answer (or anything else before the session exists) gives the lifetime up: its end resets the stream
        val session =
            try {
                @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                stream.headers.neverIndexed.takeIf { it.isNotEmpty() }?.let {
                    data.attributes.put(io.kuicksilver.ktor.client.NeverIndexedReceivedKey, it)
                }

                // an extension or a subprotocol the client did not offer fails the handshake (RFC 6455 section 4.1, kept by RFC 8441
                // section 5 and RFC 9220 section 3); the call's failure resets the stream (above)
                fun values(name: String) =
                    stream.headers.fields
                        .filter { it.first == name }
                        .map { it.second }
                val handshake =
                    webSocketAfterHandshake(data, values("sec-websocket-extensions"), values("sec-websocket-protocol"), lifetime.context)
                // Ktor writes unmasked frames; the guard masks each with a key from the CSPRNG (RFC 6455 section 5.3)
                val raw =
                    RawWebSocket(
                        guardWebSocketInput(
                            stream.input,
                            handshake.allowedRsv,
                            untilClose = true,
                            peerMasks = false,
                            context = lifetime.context,
                            inflate = handshake.inflate,
                            perMessageDeflate = handshake.perMessageDeflate,
                            maxMessageSize = config.webSocketMaxMessageSize,
                            checkText = handshake.checkText,
                            onEnd = { inputDone.complete(Unit) },
                        ),
                        guardWebSocketOutput(heldEnd, masking = true, handshake.checkText, handshake.sentCompression).also { guard = it },
                        masking = false,
                        coroutineContext = lifetime.context,
                        channelsConfig = data.attributes[WEBSOCKETS_KEY].channelsConfig,
                    )
                lifetime.watch(raw)
            } catch (e: Throwable) {
                lifetime.abandon(e)
                throw e
            }
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

        /** How long a connection stays in use after a WebTransport session on it closed, for its CONNECT exchange to end. */
        val EXCHANGE_END_TIMEOUT = 5.seconds

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

/**
 * The failure a QUIC address race reports when every attempt failed, deterministic in the attempts' order: a refusal (the
 * server's CONNECTION_REFUSED, which marks no alternative broken) only when every attempt was refused, else the last
 * failure of another kind, which does (RFC 7838 section 2.4).
 */
internal fun quicRaceFailure(attempts: List<Throwable>): Throwable =
    if (attempts.all(::isTransientRefusal)) attempts.last() else attempts.last { !isTransientRefusal(it) }

/** This timeout with every failed attempt of the race it ended attached, so the report says what each address did. */
internal fun <T : Throwable> T.withAttempts(attempts: List<Throwable>): T =
    also { t -> attempts.distinct().forEach { t.addSuppressed(it) } }

/** Reads and drops [input] to its end: true at the peer's FIN, false when it failed (a reset). */
private suspend fun discardToEnd(input: ByteReadChannel): Boolean =
    try {
        input.discard()
        input.closedCause == null
    } catch (e: CancellationException) {
        throw e
    } catch (_: Throwable) {
        false
    }

/**
 * How an HTTP/3 WebSocket's stream ends once its session did, as an HTTP/1.1 connection does
 * ([webSocketTransportEnd][io.kuicksilver.ktor.client.h1.webSocketTransportEnd]): a FIN needs the frame guard between
 * frames, and for a session the close wait cut also [drained], everything it wrote handed to QUIC's send buffer (the
 * transport's part, like a kernel's: its Close still in flight is delivered, never discarded by a reset). A session cut
 * with frames still queued in front of it (the stream's writer channel, its pump, the QUIC stream's own buffer) is reset
 * with RESET_STREAM H3_REQUEST_CANCELLED (RFC 9220 section 3), so nothing it queued leaves after T1.
 */
internal fun h3WebSocketStreamEnd(
    endedInOrder: Boolean,
    failed: Boolean,
    writerDone: Boolean,
    atFrameBoundary: Boolean,
    drained: Boolean,
    cutByCloseWait: Boolean,
): io.kuicksilver.ktor.client.h1.WebSocketTransportEnd =
    io.kuicksilver.ktor.client.h1.webSocketTransportEnd(
        endedInOrder = endedInOrder,
        failed = failed,
        writerDone = writerDone,
        atFrameBoundary = atFrameBoundary,
        drained = drained,
        cutByCloseWait = cutByCloseWait,
    )
