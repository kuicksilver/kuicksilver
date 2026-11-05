// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client.h1

import io.ktor.client.network.sockets.SocketTimeoutException
import io.ktor.client.plugins.ConnectTimeoutException
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.content.OutgoingContent
import io.ktor.http.isSecure
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.util.date.GMTDate
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.ClosedReadChannelException
import io.kuicksilver.http2.runtime.H2ClientConnection
import io.kuicksilver.ktor.client.Activity
import io.kuicksilver.ktor.client.ActivityInput
import io.kuicksilver.ktor.client.ActivityOutput
import io.kuicksilver.ktor.client.EngineEvents
import io.kuicksilver.ktor.client.H3ExchangeKey
import io.kuicksilver.ktor.client.KuicksilverEngineConfig
import io.kuicksilver.ktor.client.RequestDns
import io.kuicksilver.ktor.client.ResolvedProxy
import io.kuicksilver.ktor.client.connectTimeoutMillis
import io.kuicksilver.ktor.client.h2.H2Conn
import io.kuicksilver.ktor.client.h2.H2Http11Required
import io.kuicksilver.ktor.client.h2.H2NotProcessed
import io.kuicksilver.ktor.client.h2.H2Pool
import io.kuicksilver.ktor.client.h2.H2RefusedRoutes
import io.kuicksilver.ktor.client.h2.h2Exchange
import io.kuicksilver.ktor.client.isIdempotent
import io.kuicksilver.ktor.client.newRequestDns
import io.kuicksilver.ktor.client.platformCleartextPermitted
import io.kuicksilver.ktor.client.socketHost
import io.kuicksilver.ktor.client.socketTimeoutMillis
import io.kuicksilver.ktor.client.tlsConfigFor
import io.kuicksilver.ktor.client.withSocketInactivityTimeout
import io.kuicksilver.ktor.network.connectTcpRacing
import io.kuicksilver.tls.SessionCache
import io.kuicksilver.tls.TlsConnection
import io.kuicksilver.tls.TlsException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.CoroutineContext
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** One HTTP/1.1 connection: TCP, optionally a CONNECT tunnel, optionally TLS; its pool slot comes back when it closes. */
internal class H1Connection(
    private val socket: Socket,
    private val tls: TlsConnection?,
    rawInput: ByteReadChannel,
    val output: ByteWriteChannel,
    val key: String,
    createdAt: Long = 0,
) : PooledConnection(key, createdAt) {
    /** What the server sends, with the size limit on each response head ([MAX_RESPONSE_HEAD_BYTES]). */
    val input: HeadLimitedInput = HeadLimitedInput(rawInput, MAX_RESPONSE_HEAD_BYTES)

    /**
     * Not closed, not closed by the server, and nothing unread: bytes on a connection between exchanges answer no request
     * (an unsolicited `408 Request Timeout` before the server closes, RFC 9110 section 15.5.9) and would be read as the next
     * response, so such a connection is not reused (as Go's net/http). RFC 9112 section 9.2: "If a client receives data on a
     * connection that doesn't have outstanding requests, the client MUST NOT consider that data to be a valid response;
     * the client SHOULD close the connection".
     */
    override val isOpen: Boolean get() = !closed && !input.isClosedForRead && !input.hasUnread

    override fun closeTransport() {
        tls?.close()
        socket.close()
    }
}

/**
 * The TCP path: HTTP/1.1, and HTTP/2 when the server picks `h2` in ALPN (RFC 9113 section 3.2; ADR-0017), over TLS 1.3.
 * An HTTP/2 connection takes one slot of the limits below and serves its route's requests as streams ([H2Pool]): one
 * connection per route while it has a free stream, a second only when it is full. HTTP/1.1 keeps keep-alive and the
 * connection limits ([ConnectionPool]): at most
 * `maxConnectionsCount` connections and `maxConnectionsPerRoute` per route, requests beyond that wait in FIFO order
 * within the connect timeout; a connection whose response body ended by its framing goes back to an idle list of at most
 * `maxIdleConnectionsPerRoute` per route, kept for `idleTimeout`. A stale idle connection is replaced once, transparently,
 * for idempotent requests only (RFC 9110 section 9.2.2, RFC 9112 section 9.3.1): a request the server may have processed
 * is never sent twice.
 */
internal class H1Pool(
    private val config: KuicksilverEngineConfig,
    private val selector: SelectorManager,
    private val events: EngineEvents = EngineEvents(null, io.kuicksilver.quic.KuicksilverLogger.None),
    private val clock: () -> Long = monotonicMillis(),
) {
    /** The HTTP/2 connections' coroutines: not the engine's request job, which waits for its children before the cleanup. */
    private val h2Scope = CoroutineScope(selector.coroutineContext.minusKey(Job) + SupervisorJob() + CoroutineName("kuicksilver-h2"))

    /** HTTP/2 connections by route; internal for tests. */
    internal val h2 = H2Pool(config.poolLimits(), clock)

    /**
     * An HTTP/2 connection from which nothing arrived for this long is checked with a PING before it takes a request
     * (Chromium checks a session idle for 10 s, "at risk of loss"); internal so tests can check every reuse.
     */
    internal var h2HealthAfterIdleMillis: Long = 10_000

    /** Runs after a request got a pool permit and before it may become its route's dialer (tests: widens that gap). */
    internal var beforeDialForTest: (suspend () -> Unit)? = null

    /** Routes that answered HTTP_1_1_REQUIRED; internal for tests. */
    internal val h2Refused = H2RefusedRoutes(clock)

    init {
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        val ping = config.http2.pingInterval
        require(
            ping.isInfinite() || ping >= MIN_PING_INTERVAL,
        ) { "http2.pingInterval must be at least 100 ms or Duration.INFINITE, was $ping" }
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        val delay = config.connectionAttemptDelay
        // RFC 8305 section 8: at least 10 ms (100 ms recommended as the floor), at most 2 s
        require(delay.isInfinite() || delay in MIN_ATTEMPT_DELAY..MAX_ATTEMPT_DELAY) {
            "connectionAttemptDelay must be 10 ms..2 s or Duration.INFINITE (RFC 8305 section 8), was $delay"
        }
    }

    /** The platform's cleartext policy (Android Network Security Configuration); replaced by tests. */
    internal var cleartextPermitted: (String) -> Boolean = { host -> platformCleartextPermitted(host) }

    /** Limits, keep-alive and idle expiry; internal for tests. */
    internal val pool = ConnectionPool<H1Connection>(config.poolLimits(), clock)

    /** This engine's TLS session tickets (resumption secrets stay native); closed by [closeAll], so closing the engine drops them. */
    internal val sessions = SessionCache()

    /** Returns a connection that finished its exchange, or one that lost the protocol race unused. */
    fun recycle(c: H1Connection) = pool.release(c)

    /** Gives back what the race's TCP side opened and did not use: an HTTP/1.1 connection, or a reserved HTTP/2 stream. */
    fun recycle(o: Opened) {
        o.connection?.let { pool.release(it) }
        o.h2?.client?.unreserve()
    }

    /**
     * Closes idle connections past their idle timeout or lifetime, and retires HTTP/2 connections the same way; the
     * milliseconds until the next expiry, null when nothing waits for one.
     */
    fun evictExpired(): Long? = listOfNotNull(pool.evictExpired(), h2.evictExpired()).minOrNull()

    suspend fun closeAll() {
        h2.closeAll()
        h2Scope.cancel()
        pool.shutdown()
        sessions.close() // a connection still finishing stores its ticket into a closed cache, which releases it
    }

    private fun keyOf(
        data: HttpRequestData,
        proxy: ResolvedProxy?,
    ): String =
        data.url.let {
            "${it.protocol.name}://${it.host}:${it.port}|${proxy?.routeKey}"
        }

    /**
     * A connection for [data]: an idle pooled one, else a new one (the HTTP/1.1 side of the h3/h1 race). [Opened.reused]
     * travels with it to [execute], so a pooled connection the server closed still earns the stale-connection retry.
     */
    suspend fun open(
        data: HttpRequestData,
        dns: RequestDns = config.newRequestDns(),
    ): Opened = obtain(data, keyOf(data, null), dns, null, webSocketKeys = null).let { Opened(it.connection, it.reused, it.h2) }

    /**
     * A connection [open] handed out and whether it came from the idle pool (or, for HTTP/2, was open already): an HTTP/1.1
     * [connection], or a stream reserved on the HTTP/2 connection [h2].
     */
    class Opened(
        val connection: H1Connection?,
        val reused: Boolean,
        val h2: H2Conn? = null,
    )

    /** A connection from [obtain] (as [Opened]) and the WebSocket keys it holds. */
    private class Obtained(
        val connection: H1Connection?,
        val reused: Boolean,
        val held: WebSocketConnecting.Held?,
        val h2: H2Conn? = null,
    )

    /**
     * Whether [data] may go over HTTP/2 on [key]: enabled, `https` (no h2c, ADR-0017), not a WebSocket (RFC 8441 is not
     * supported: OkHttp also opens WebSockets over HTTP/1.1) and the route did not answer HTTP_1_1_REQUIRED lately.
     */
    @OptIn(io.ktor.utils.io.InternalAPI::class, io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private fun h2Allowed(
        data: HttpRequestData,
        key: String,
    ): Boolean =
        config.http2.enabled && data.url.protocol.isSecure() && tls13Only &&
            !data.attributes.contains(io.ktor.client.plugins.websocket.WEBSOCKETS_KEY) && !upgrades(data.body) && !h2Refused.isRefused(key)

    /** A body that takes over the connection (`Upgrade`): HTTP/2 has no such thing (RFC 9113 section 8.6), so HTTP/1.1. */
    private fun upgrades(body: OutgoingContent): Boolean =
        when (body) {
            is OutgoingContent.ProtocolUpgrade -> true
            is OutgoingContent.ContentWrapper -> upgrades(body.delegate())
            else -> false
        }

    /**
     * Whether the engine's TLS is TLS 1.3 only (the default). RFC 9113 section 9.2.1 makes a TLS 1.2 renegotiation a
     * connection error of type PROTOCOL_ERROR, and the TLS layer cannot report one: OpenSSL answers a server's
     * HelloRequest itself (no_renegotiation, SSL_OP_NO_RENEGOTIATION in ksl_ctx.c) and the connection goes on. So a client
     * configured to allow TLS 1.2 offers only http/1.1 rather than run HTTP/2 against that MUST; TLS 1.2 is opt-in, for
     * peers without TLS 1.3 (TlsVersions.Tls12And13).
     */
    private val tls13Only: Boolean by lazy {
        config.tlsConfigFor("localhost", listOf("http/1.1")).versions == io.kuicksilver.tls.TlsVersions.Tls13
    }

    /**
     * An idle connection for [key] ([Obtained.reused]), else a new one once the limits allow; waiting for room and
     * connecting share the connect timeout, as in the CIO engine ([ConnectTimeoutException]). A WebSocket ([webSocketKeys]
     * not null) first takes the remote host's keys (RFC 6455 section 4.1: at most one connection CONNECTING per host, the
     * others wait), and only then asks the pool. The wait for the keys is not part of the connect timeout: RFC 6455 has the
     * client wait for the other connection, not give up, so only the call (its request timeout or its cancellation) bounds
     * it, and every holder lets go within its own connect timeout (review 2026-10-28 R1: forty WebSockets started at once to
     * one address failed from about the 33rd on). A WebSocket waiting for keys holds no pool permit and no idle connection
     * (review S2: one held them, so queued WebSockets starved the pool and kept idle connections until they were stale).
     */
    private suspend fun obtain(
        data: HttpRequestData,
        key: String,
        dns: RequestDns,
        proxy: ResolvedProxy?,
        webSocketKeys: List<String>?,
    ): Obtained {
        val held = webSocketKeys?.let { webSocketConnecting.acquire(it) }
        val h2Ok = webSocketKeys == null && h2Allowed(data, key)
        var conn: H1Connection? = null
        var stream: H2Conn? = null
        var reused = false
        try {
            withTimeout(data.connectTimeoutMillis(config)) {
                // a request that may use HTTP/2 also watches its route: a stream that frees up, or a connection that
                // another request just set up, serves it instead of a new TCP connection (OkHttp RealRoutePlanner)
                val signal = if (h2Ok) h2.watch(key) else null
                try {
                    while (true) {
                        // the change count, read before looking: a dial decision refuses when it moved since, and the
                        // waits below end when the published signal passes it
                        val seen = if (signal != null) h2.version(key) else null
                        if (signal != null) {
                            val found = h2.reserve(key)
                            if (found != null) {
                                // a connection quiet for a while may be dead (a NAT that forgot it, a peer gone without a
                                // FIN): one PING, bounded, before the request goes on it; a failed one retires it, and the
                                // request, not sent there, looks again
                                if (found.client.receivedIdleMillis >= h2HealthAfterIdleMillis &&
                                    !found.client.checkHealth(healthTimeoutMillis(data))
                                ) {
                                    found.client.unreserve()
                                    // calls still running on it (a long poll, an upload) are not cut: GOAWAY, no new streams,
                                    // closed when they are done; a connection without any is closed at once
                                    if (found.client.reservedStreams > 0) {
                                        found.client.shutdown()
                                    } else {
                                        found.client.abort(kotlinx.io.IOException("the HTTP/2 connection did not answer a health PING"))
                                    }
                                    continue
                                }
                                stream = found
                                reused = true
                                return@withTimeout
                            }
                        }
                        val got = acquireOrChange(key, signal, seen)
                        if (got === CHANGED) continue
                        if (got is H1Connection) {
                            conn = got
                            reused = true
                            return@withTimeout
                        }
                        // a route marked meanwhile (HTTP_1_1_REQUIRED on a connection of this loop) offers http/1.1 only
                        val offerH2 = h2Ok && !h2Refused.isRefused(key)
                        // one HTTP/2 connect at a time per route (RFC 9113 section 9.1): the others wait for its outcome
                        // without a permit, within the connect timeout
                        beforeDialForTest?.invoke()
                        if (offerH2 && signal != null && !h2.tryStartDial(key, seen!!)) {
                            pool.releasePermit(key)
                            signal.first { it > seen }
                            continue
                        }
                        val dialer = offerH2 && signal != null
                        val opened =
                            try {
                                connect(data, data.url, data.url.protocol.isSecure(), proxy, key, dns, offerH2).also { pool.adopt(it) }
                            } catch (e: Throwable) {
                                pool.releasePermit(key)
                                if (dialer) h2.endDial(key, null)
                                throw e
                            }
                        if (opened is H1Connection) {
                            if (dialer) h2.endDial(key, false) // the waiting requests connect on their own now
                            conn = opened
                            return@withTimeout
                        }
                        val c = opened as H2Conn
                        h2Scope.launch {
                            // its slot comes back once it ended (GOAWAY drained, an error, closed by the pool)
                            c.client.awaitClosed()
                            h2.remove(c)
                            c.close()
                        }
                        // the waiting requests are told only once the connection is in the pool (or refused): told earlier,
                        // they would find nothing and connect again
                        try {
                            // another HTTP/2 connection with room (opened while this one connected): use it, close this one
                            val other = h2.reserve(key)
                            if (other != null) {
                                c.client.shutdown()
                                stream = other
                                reused = true
                                return@withTimeout
                            }
                            // our stream first, then the pool: another request cannot take the one stream this request opened for
                            if (c.client.tryReserve()) {
                                h2.register(c)
                                stream = c
                                return@withTimeout
                            }
                            // a server that sends GOAWAY with HTTP_1_1_REQUIRED at once wants HTTP/1.1 (RFC 9113 section 7): the
                            // route is marked and the next round connects with http/1.1 only
                            @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
                            if (c.client.goAwayCode == io.kuicksilver.http2.Http2ErrorCode.HTTP_1_1_REQUIRED) {
                                h2Refused.mark(key)
                                @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                                data.attributes.getOrNull(io.kuicksilver.ktor.client.KuicksilverDiagnosticsKey)?.h2Refused = true
                            } else {
                                // a new connection that takes no request (a GOAWAY at once, SETTINGS_MAX_CONCURRENT_STREAMS 0):
                                // the call fails rather than open connection after connection to a server that refuses them
                                c.client.shutdown()
                                throw kotlinx.io.IOException(
                                    "the server took no request on a new HTTP/2 connection (GOAWAY or SETTINGS_MAX_CONCURRENT_STREAMS 0)",
                                )
                            }
                        } finally {
                            if (dialer) h2.endDial(key, true)
                        }
                    }
                } finally {
                    if (signal != null) h2.unwatch(key)
                }
            }
        } catch (e: Throwable) {
            held?.release()
            if (e is CancellationException) {
                // a timeout that fired as the block returned: the connection is not handed out, so its slot comes back here
                conn?.let { if (reused) pool.release(it) else it.close() }
                stream?.client?.unreserve()
                if (e is TimeoutCancellationException) throw ConnectTimeoutException(data, e)
            }
            throw e
        }
        return Obtained(conn, reused, held, stream)
    }

    /** The bound of a health PING: half the connect timeout (the rest is for a new connection), at most 5 s. */
    private fun healthTimeoutMillis(data: HttpRequestData): Long = (data.connectTimeoutMillis(config) / 2).coerceIn(1, 5_000)

    /**
     * [ConnectionPool.acquire] for [key] (an idle [H1Connection], or [PERMIT] to open one); with [signal], it gives up
     * with [CHANGED] as soon as the route's HTTP/2 state changes after [seen]. What the pool granted meanwhile is never
     * lost: a grant that arrives with the change or a cancellation is handed back.
     */
    private suspend fun acquireOrChange(
        key: String,
        signal: StateFlow<Long>?,
        seen: Long?,
    ): Any {
        if (signal == null) return pool.acquire(key) ?: PERMIT
        return coroutineScope {
            var got: Any? = null
            val a = launch(start = CoroutineStart.UNDISPATCHED) { got = pool.acquire(key) ?: PERMIT }
            if (got != null) return@coroutineScope got!!
            val watcher =
                launch {
                    signal.first { it > seen!! }
                    a.cancel()
                }
            try {
                a.join()
            } catch (e: Throwable) {
                a.cancel()
                watcher.cancel()
                withContext(NonCancellable) { a.join() }
                got?.let { giveBack(key, it) }
                throw e
            }
            watcher.cancel()
            got ?: CHANGED
        }
    }

    private fun giveBack(
        key: String,
        got: Any,
    ) {
        if (got is H1Connection) pool.release(got) else pool.releasePermit(key)
    }

    /**
     * One exchange; [preopened] is a connection the race already obtained ([open]), [dns] the request's name resolution,
     * [proxy] the proxy that applies to the request (the engine resolved it), null for a direct connection.
     */
    suspend fun execute(
        data: HttpRequestData,
        callContext: CoroutineContext,
        preopened: Opened? = null,
        dns: RequestDns = config.newRequestDns(),
        proxy: ResolvedProxy? = null,
        onSelected: ((HttpProtocolVersion) -> Unit)? = null,
    ): HttpResponseData {
        @OptIn(io.ktor.utils.io.InternalAPI::class)
        val webSocket = data.attributes.contains(io.ktor.client.plugins.websocket.WEBSOCKETS_KEY)
        // a WebSocket is CONNECTING from its connection until the server answers its handshake (RFC 6455 section 4.1)
        return exchange(data, callContext, preopened, dns, proxy, if (webSocket) remoteHosts(data, dns, proxy) else null, onSelected)
    }

    /** Race-opened connections a WebSocket gave back because its keys were taken (tests). */
    @kotlin.concurrent.Volatile
    internal var raceConnectionsReturnedForTest = 0

    /** One WebSocket at a time in the CONNECTING state per remote host (RFC 6455 section 4.1, step 2). */
    internal val webSocketConnecting = WebSocketConnecting()

    /**
     * The remote hosts [data] may connect to, as [WebSocketConnecting] keys: the IP addresses of the origin, without the
     * port, when the engine resolves its name (the request's own resolution, which the connection then uses, under the
     * connect timeout), else (an HTTP proxy, a SOCKS5 proxy that resolves names) the origin's name; each in one form per
     * host ([WebSocketConnecting.addressKey], [WebSocketConnecting.nameKey]).
     */
    private suspend fun remoteHosts(
        data: HttpRequestData,
        dns: RequestDns,
        proxy: ResolvedProxy?,
    ): List<String> {
        val url = data.url
        if (proxy != null && (proxy.kind != ResolvedProxy.Kind.Socks5 || proxy.remoteDns)) {
            return listOf(WebSocketConnecting.nameKey(url.host))
        }
        val addresses =
            try {
                withTimeout(data.connectTimeoutMillis(config)) { dns.lookup(url.host, url.port) }
            } catch (e: TimeoutCancellationException) {
                throw ConnectTimeoutException(data, e)
            }
        return addresses.map { WebSocketConnecting.addressKey(it) }
    }

    /**
     * [execute]; [webSocketKeys] are the remote hosts of a WebSocket ([remoteHosts]), null for any other request. A
     * WebSocket holds them from [obtain] until the server answered its handshake (the response head, the 101 or a
     * refusal), or the exchange failed or was cancelled; that answer must arrive within the connect timeout, counted
     * from the moment the connection is in hand, or the WebSocket fails with [ConnectTimeoutException]: its opening
     * handshake is part of connecting, and a server that never answers would otherwise keep every later WebSocket to
     * the address waiting.
     */
    private suspend fun exchange(
        data: HttpRequestData,
        callContext: CoroutineContext,
        preopened: Opened?,
        dns: RequestDns,
        proxy: ResolvedProxy?,
        webSocketKeys: List<String>?,
        onSelected: ((HttpProtocolVersion) -> Unit)?,
    ): HttpResponseData {
        // a request sent again over HTTP/1.1 (after a 421 or a failure over HTTP/3) leaves its HTTP/3 exchange behind:
        // HttpResponse.updatePriority must not reach that stream
        data.attributes.remove(H3ExchangeKey)
        val url = data.url
        val secure = url.protocol.isSecure()
        if (!secure) {
            val host = url.host.removePrefix("[").removeSuffix("]") // an IPv6 literal as the policy knows it
            if (!cleartextPermitted(host)) {
                throw io.kuicksilver.ktor.client
                    .cleartextNotPermitted(host)
            }
        }
        // through an HTTP proxy, plain http goes in the absolute form (RFC 9112 section 3.2.2); TLS and WebSockets, ws://
        // included (RFC 6455 section 4.1, as browsers), through a CONNECT tunnel; through SOCKS5 everything is tunneled
        val tunneled = proxy != null && proxy.tunnels(data)
        val key = keyOf(data, proxy)
        var first = true
        var given = preopened
        var announced: HttpProtocolVersion? = null
        var h2Repeats = 0
        var attempt = 1 // this call's attempts on the TCP path, for the retry event

        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        val diagnostics = data.attributes.getOrNull(io.kuicksilver.ktor.client.KuicksilverDiagnosticsKey)
        while (true) {
            // a connection the race just opened is fresh and never earns the stale retry; an idle one it took from the pool does.
            // A WebSocket takes its keys before it holds a connection (RFC 6455 section 4.1): a connection the race opened is
            // used only when the keys are free now; otherwise it goes back to the pool and the WebSocket waits for the keys in
            // obtain, holding nothing (review S2 of 7de616bf)
            val pre = given
            given = null
            val preHeld = if (pre != null && webSocketKeys != null) webSocketConnecting.tryAcquire(webSocketKeys) else null
            if (pre != null && webSocketKeys != null && preHeld == null) {
                recycle(pre)
                raceConnectionsReturnedForTest++
            }
            val obtained =
                if (pre != null && (webSocketKeys == null || preHeld != null)) {
                    Obtained(pre.connection, pre.reused, preHeld, pre.h2)
                } else {
                    obtain(data, key, dns, proxy, webSocketKeys)
                }
            val h2c = obtained.h2
            val protocol = if (h2c != null) HttpProtocolVersion.HTTP_2_0 else HttpProtocolVersion.HTTP_1_1
            // HTTP/1.1 where HTTP/2 would have been offered, but the route answered HTTP_1_1_REQUIRED lately
            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
            if (h2c == null && diagnostics != null && webSocketKeys == null && !h2Allowed(data, key) &&
                config.http2.enabled && secure && h2Refused.isRefused(key)
            ) {
                diagnostics.h2Refused = true
            }
            // protocolSelected goes out once the connection is in hand, with the protocol it speaks; again only when a
            // repeat changes it (HTTP_1_1_REQUIRED)
            if (announced != protocol) {
                announced = protocol
                onSelected?.invoke(protocol)
            }
            if (h2c != null) {
                events.emit("connectionAcquired") { connectionAcquired(data, HttpProtocolVersion.HTTP_2_0, obtained.reused) }
                try {
                    return h2Exchange(h2c, data, callContext, events) { kept ->
                        events.emit("connectionReleased") { connectionReleased(data, HttpProtocolVersion.HTTP_2_0, kept) }
                    }
                } catch (e: H2NotProcessed) {
                    // RFC 9113 section 8.7: not processed, so safe to repeat whatever the method, on another stream or
                    // connection; at most twice, as over HTTP/3
                    if (e.bodyConsumed) {
                        throw io.kuicksilver.ktor.client.H3BodyConsumed(
                            "the server did not process the HTTP/2 request and its streamed body was already consumed",
                            e.cause,
                        )
                    }
                    if (++h2Repeats > 2) throw e.cause
                    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                    diagnostics?.let { it.attempts++ }
                    attempt++
                    events.emit("retry") { retry(data, attempt, e.cause) }
                    continue
                } catch (e: H2Http11Required) {
                    // RFC 9113 section 7: the server wants this request over HTTP/1.1; the route offers only http/1.1 for a while
                    h2Refused.mark(key)
                    // a request the server may have processed is not sent again (RFC 9110 section 9.2.2, RFC 9113 section 8.7)
                    if (!e.mayRepeat) {
                        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                        throw io.kuicksilver.ktor.client.Http11RequiredException(
                            "the server requires HTTP/1.1 (HTTP_1_1_REQUIRED) for ${data.method.value} ${data.url.protocol.name}://" +
                                "${data.url.host}:${data.url.port}; the request may have been processed, so it was not sent again; " +
                                "this route now uses HTTP/1.1, and the request can be repeated",
                            e.cause,
                        )
                    }
                    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                    diagnostics?.let {
                        it.h2Refused = true
                        it.attempts++
                    }
                    if (e.bodyConsumed) {
                        throw io.kuicksilver.ktor.client.H3BodyConsumed(
                            "the server asked for HTTP/1.1 (HTTP_1_1_REQUIRED) and the request's streamed body was already consumed",
                            e.cause,
                        )
                    }
                    attempt++
                    events.emit("retry") { retry(data, attempt, e.cause) }
                    continue
                }
            }
            val conn = obtained.connection!!
            val reused = obtained.reused
            var held = obtained.held
            events.emit("connectionAcquired") { connectionAcquired(data, HttpProtocolVersion.HTTP_1_1, reused) }
            var bodyJob: BodySender? = null
            try {
                val requestTime = GMTDate()
                // the socket timeout measures inactivity in both directions (Ktor: "maximum time of inactivity between two
                // data packets"): sending the request and waiting for the response head share one timer, which every
                // flushed piece of the request and every arriving byte of the response restarts
                val activity = data.socketTimeoutMillis()?.let { Activity() }
                val output = activity?.let { ActivityOutput(conn.output, it) } ?: conn.output
                val input = activity?.let { ActivityInput(conn.input, it) } ?: conn.input
                var bodySent = false

                suspend fun exchangeOnce(): HttpResponseData =
                    withSocketInactivityTimeout(data, activity, onExpiry = { conn.close() }) {
                        writeHeaders(
                            data,
                            output,
                            overProxy = proxy != null && !tunneled,
                            tunneled = tunneled,
                            proxyAuthorization = proxy?.takeIf { !tunneled }?.basicAuthorization,
                        )

                        suspend fun sendBody() {
                            bodySent = true
                            // a streamed body is sent while the response is read (as the CIO engine): the server may answer first
                            if (data.body.isStreamed()) {
                                bodyJob = sendBodyConcurrently(data, conn, output, callContext)
                            } else {
                                writeBody(data, output, callContext)
                            }
                        }
                        // `Expect: 100-continue` (RFC 9110 section 10.1.1): the body waits for the server's 100 Continue, or a
                        // final response that refuses it (417, 401), up to CONTINUE_TIMEOUT; a server that says nothing in that
                        // time gets the body anyway
                        val answered = expectsContinue(data) && withTimeoutOrNull(CONTINUE_TIMEOUT) { input.awaitContent() } != null
                        if (!answered) sendBody()
                        val continueBody: (suspend () -> Unit)? = if (answered) ({ sendBody() }) else null
                        readResponse(
                            requestTime,
                            data,
                            input,
                            conn.output,
                            callContext,
                            conn.input,
                            continueBody,
                            requestBodySent = { bodyJob?.sent },
                        ) { after ->
                            fun released(kept: Boolean) =
                                events.emit("connectionReleased") { connectionReleased(data, HttpProtocolVersion.HTTP_1_1, kept) }

                            fun settle(a: AfterResponse) {
                                when (a) {
                                    AfterResponse.Reuse -> {
                                        released(pool.release(conn))
                                    }

                                    // at once, and a request body still being sent with it (RFC 9112 section 9.5): its
                                    // sender is cancelled too, so one waiting for the application's body (not for the
                                    // connection, which the close fails) ends now rather than at its next write
                                    AfterResponse.Close -> {
                                        conn.close()
                                        bodyJob?.job?.cancel()
                                        released(false)
                                    }

                                    // a request body still being sent is not cut off: the connection closes when its
                                    // sender ends (sent, failed, or cancelled with the call)
                                    AfterResponse.CloseAfterUpload -> {
                                        val job = bodyJob?.job
                                        if (job == null) {
                                            conn.close()
                                            released(false)
                                        } else {
                                            job.invokeOnCompletion {
                                                conn.close()
                                                released(false)
                                            }
                                        }
                                    }

                                    AfterResponse.HandOver -> {
                                        callContext[Job]?.invokeOnCompletion {
                                            conn.close()
                                            released(false)
                                        }
                                    }
                                }
                            }
                            // Reuse only with a streamed request body already out (readResponse)
                            settle(after)
                        }
                    }
                val response =
                    try {
                        when (webSocketKeys) {
                            null -> exchangeOnce()
                            else -> connectingWithin(data, onExpiry = { conn.close() }) { exchangeOnce() }
                        }
                    } finally {
                        held?.release()
                    }
                // a 417 to a request that waited for 100 Continue only says that something on the way does not support
                // expectations: the request is repeated once without one (RFC 9110 section 10.1.1, as CIO); its body was
                // never sent, so it can be. The 417's connection was closed: it promised a body it never got
                if (response.statusCode == HttpStatusCode.ExpectationFailed && !bodySent && expectsContinue(data)) {
                    data.attributes.put(ExpectationFailedKey, Unit)
                    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                    data.attributes.getOrNull(io.kuicksilver.ktor.client.KuicksilverDiagnosticsKey)?.let { it.attempts++ }
                    attempt++
                    events.emit("retry") { retry(data, attempt, IllegalStateException("417 Expectation Failed to Expect: 100-continue")) }
                    continue
                }
                return response
            } catch (e: CancellationException) {
                held?.release()
                conn.close()
                events.emit("connectionReleased") { connectionReleased(data, HttpProtocolVersion.HTTP_1_1, kept = false) }
                throw e
            } catch (e: Throwable) {
                held?.release()
                conn.close()
                // every connectionAcquired gets its connectionReleased, also when the exchange failed before a response
                events.emit("connectionReleased") { connectionReleased(data, HttpProtocolVersion.HTTP_1_1, kept = false) }
                bodyJob?.failure?.let { throw it }
                // a pooled connection the server already closed: one transparent retry on a fresh connection, for an
                // idempotent request with a replayable body only (a non-idempotent one may have been processed, RFC 9112 section 9.3.1);
                // a socket timeout is an IOException too, but a slow server, not a closed connection: it is not repeated,
                // nor is a WebSocket handshake the server did not answer within the connect timeout.
                // `e !is TlsException` is intentionally not reached for a TLS failure read through the connection's channel
                // (it arrives wrapped): a TLS failure on a reused connection is the stale-connection case this retry is for
                if (reused && first && bodyJob == null && data.method.isIdempotent() &&
                    (e is ClosedReadChannelException || e is kotlinx.io.IOException) && e !is TlsException &&
                    e !is SocketTimeoutException && e !is io.ktor.client.network.sockets.ConnectTimeoutException
                ) {
                    first = false
                    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                    data.attributes.getOrNull(io.kuicksilver.ktor.client.KuicksilverDiagnosticsKey)?.let { it.attempts++ }
                    attempt++
                    events.emit("retry") { retry(data, attempt, e) }
                    continue
                }
                throw e
            }
        }
    }

    /**
     * [block] within the request's connect timeout, else [ConnectTimeoutException]: a WebSocket's wait for its keys
     * (a connection handed over by the protocol race) and for the answer to its handshake. [onExpiry] ends a wait that
     * cancellation does not reach (the response reader runs in the call's context): it closes the connection.
     */
    private suspend fun <T> connectingWithin(
        data: HttpRequestData,
        onExpiry: () -> Unit = {},
        block: suspend () -> T,
    ): T {
        val millis = data.connectTimeoutMillis(config)
        // an Activity nobody ticks: a plain deadline
        return Activity().within(
            millis,
            timeout = {
                io.ktor.client.network.sockets.ConnectTimeoutException(
                    "The WebSocket was not connected within the connect timeout [url=${data.url}, connect_timeout=$millis ms]",
                    it,
                )
            },
            onExpiry = onExpiry,
            block = block,
        )
    }

    /**
     * Writes the body in its own coroutine; a failure closes the connection (so the response read fails too) and is
     * reported through the call ([BodySender.failure]). It is not rethrown: this coroutine has no parent, so a failure
     * thrown out of it went to the uncaught-exception handler as well (printed on the JVM, fatal to an Android app). It is
     * logged at [io.kuicksilver.quic.LogLevel.Debug]: when the response was already complete (a server that answered before the whole body),
     * the call does not fail and nothing else reports it.
     */
    @OptIn(DelicateCoroutinesApi::class)
    private fun sendBodyConcurrently(
        data: HttpRequestData,
        conn: H1Connection,
        output: ByteWriteChannel,
        callContext: CoroutineContext,
    ): BodySender {
        val sender = BodySender()
        sender.job =
            GlobalScope.launch(callContext.minusKey(Job) + CoroutineName("kuicksilver-h1-request-body")) {
                try {
                    writeBody(data, output, callContext)
                    sender.sent.complete(true)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    sender.failure = e
                    sender.sent.complete(false)
                    conn.close()
                    val logger = events.logger
                    runCatching {
                        if (logger.isEnabled(io.kuicksilver.quic.LogLevel.Debug)) {
                            logger.log(
                                io.kuicksilver.quic.LogLevel.Debug,
                                "HTTP/1.1 request body of ${data.method.value} " +
                                    "${data.url.protocol.name}://${data.url.host}:${data.url.port} failed; its connection is closed",
                                e,
                            )
                        }
                    }
                }
            }
        sender.job.invokeOnCompletion { c -> sender.ended(c, conn) }
        callContext[Job]?.invokeOnCompletion { sender.job.cancel() } // not a child: the call does not wait for it, it ends with the call
        return sender
    }

    internal class BodySender {
        lateinit var job: Job

        @kotlin.concurrent.Volatile var failure: Throwable? = null

        /** Completed when the sending ends: true once the whole body was written and flushed, false when it failed or was cancelled. */
        val sent = CompletableDeferred<Boolean>()

        /**
         * The sender's job completed with [cause]. Cancelled before the whole body was out: [conn] is closed. Cancelled
         * after (the call ended between the last flush and the job's completion), [conn] is left alone: it may already be
         * idle in the pool or serve the next request.
         */
        fun ended(
            cause: Throwable?,
            conn: PooledConnection,
        ) {
            if (cause != null && sent.complete(false)) conn.close()
        }
    }

    /**
     * TCP, the proxy's tunnel (HTTP CONNECT or SOCKS5) and TLS; runs under [obtain]'s connect timeout, which bounds every
     * step of a proxy's handshake too.
     */
    private suspend fun connect(
        data: HttpRequestData,
        url: Url,
        secure: Boolean,
        proxy: ResolvedProxy?,
        key: String,
        dns: RequestDns,
        h2Ok: Boolean = false,
    ): PooledConnection {
        val (host, port) = if (proxy != null) proxy.host to proxy.port else url.host to url.port
        // through socks5:// (names resolved here) each address of the origin in turn while the proxy answers "network
        // unreachable" or "host unreachable" (RFC 1928 section 6, REP 3 and 4), each on a new connection to the proxy
        val socksTargets =
            if (proxy?.kind == ResolvedProxy.Kind.Socks5) socks5Targets(url.host, proxy.remoteDns, dns) else listOf(null)
        for ((attempt, socksTarget) in socksTargets.withIndex()) {
            // every address of the host, IPv6 and IPv4 alternating (RFC 8305); this module's connects on Kotlin/Native, not
            // ktor-network's (Ktor issue KTOR-10017, security, under coordinated disclosure)
            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
            val tcp = connectTcpRacing(selector, host, port, config.connectionAttemptDelay, dns::lookup)
            try {
                val rawIn = tcp.openReadChannel()
                val rawOut = tcp.openWriteChannel(autoFlush = true)
                when {
                    proxy == null -> {}

                    socksTarget != null -> {
                        try {
                            socks5Connect(rawIn, rawOut, socksTarget, url.port, proxy.credentials, "$proxy")
                        } catch (e: io.kuicksilver.ktor.client.ProxyException) {
                            if ((e.replyCode != 3 && e.replyCode != 4) || attempt == socksTargets.lastIndex) throw e
                            tcp.close()
                            continue
                        }
                    }

                    proxy.tunnels(data) -> {
                        startTunnel(
                            url,
                            data.headers[HttpHeaders.UserAgent],
                            // the request's own field wins; else the configured credentials, sent at once (no 407 round trip)
                            data.headers[HttpHeaders.ProxyAuthorization] ?: proxy.basicAuthorization,
                            rawOut,
                            rawIn,
                        )
                    }
                }
                return if (secure) {
                    // through a proxy too: ALPN is inside the TLS session with the origin (OkHttp does the same)
                    val alpn = if (h2Ok) listOf("h2", "http/1.1") else listOf("http/1.1")
                    val tls =
                        TlsConnection.client(
                            rawIn,
                            rawOut,
                            config.tlsConfigFor(url.host, alpn),
                            callContextOrEmpty(),
                            sessions,
                        )
                    if (h2Ok && tls.negotiatedAlpn == "h2") {
                        // RFC 9113 section 3.2: h2 over TLS; the server's preface (its SETTINGS) within the connect timeout
                        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                        val client =
                            try {
                                H2ClientConnection.start(
                                    tls.input,
                                    tls.output,
                                    config.http2.settings,
                                    h2Scope,
                                    config.http2.pingInterval,
                                    closeTransport = {
                                        tls.close()
                                        tcp.close()
                                    },
                                    onChange = { h2.bump(key) },
                                )
                            } catch (e: Throwable) {
                                tls.close()
                                throw e
                            }
                        return H2Conn(client, key, clock())
                    }
                    H1Connection(tcp, tls, tls.input, tls.output, key, clock())
                } else {
                    H1Connection(tcp, null, rawIn, rawOut, key, clock())
                }
            } catch (e: Throwable) {
                tcp.close()
                throw e
            }
        }
        throw kotlinx.io.IOException("no SOCKS5 destination for ${url.host}") // socks5Targets never returns an empty list
    }

    private fun callContextOrEmpty(): CoroutineContext = selector.coroutineContext

    /**
     * The SOCKS5 destinations for [host], in order: an address literal as ATYP 1 or 4; a name as itself for the proxy to
     * resolve ([remoteDns], `socks5h`), else every address the request's resolution gives (`socks5`).
     */
    private suspend fun socks5Targets(
        host: String,
        remoteDns: Boolean,
        dns: RequestDns,
    ): List<Socks5Target> {
        val name = socketHost(host)
        val literal = ':' in name || parseIpv4(name) != null
        if (!literal && remoteDns) return listOf(Socks5Target.Domain(name))
        return dns
            .lookup(name, 0)
            .map { it.bytes }
            .distinctBy { it.toList() }
            .map { Socks5Target.Address(it) }
    }
}

/** Whether a request through this proxy goes in a tunnel: always through SOCKS5; through HTTP for TLS and WebSockets. */
@OptIn(io.ktor.utils.io.InternalAPI::class)
internal fun ResolvedProxy.tunnels(data: HttpRequestData): Boolean =
    kind == ResolvedProxy.Kind.Socks5 || data.url.protocol.isSecure() ||
        data.attributes.contains(io.ktor.client.plugins.websocket.WEBSOCKETS_KEY)

/** Four dotted-decimal octets 0..255, or null. */
private fun parseIpv4(s: String): List<Int>? =
    s.split('.').takeIf { it.size == 4 }?.map { p ->
        p.toIntOrNull()?.takeIf { it in 0..255 && p.isNotEmpty() && p.length <= 3 }
            ?: return null
    }

/** Milliseconds on a monotonic clock, for idle and lifetime expiry. */
internal fun monotonicMillis(): () -> Long {
    val start =
        kotlin.time.TimeSource.Monotonic
            .markNow()
    return { start.elapsedNow().inWholeMilliseconds }
}

/** The pool limits of this configuration; validates them. */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
internal fun KuicksilverEngineConfig.poolLimits(): PoolLimits =
    PoolLimits(
        maxTotal = maxConnectionsCount,
        maxPerRoute = maxConnectionsPerRoute,
        maxIdlePerRoute = maxIdleConnectionsPerRoute,
        idleTimeoutMillis = idleTimeout.toMillisOrMax(),
        maxLifetimeMillis = maxConnectionLifetime.toMillisOrMax(),
    )

internal fun kotlin.time.Duration.toMillisOrMax(): Long = if (isInfinite()) Long.MAX_VALUE else inWholeMilliseconds

/** A body that streams (its end is not known up front): sent concurrently with reading the response. */
private fun OutgoingContent.isStreamed(): Boolean =
    when (this) {
        is OutgoingContent.ContentWrapper -> delegate().isStreamed()
        is OutgoingContent.ReadChannelContent, is OutgoingContent.WriteChannelContent -> true
        else -> false
    }

/** RFC 8305 section 8: the connection attempt delay is at least 10 ms and at most 2 s. */
private val MIN_ATTEMPT_DELAY = 10.milliseconds

/** OkHttp has no floor; below 100 ms a PING timer would end connections on any ordinary delay. */
private val MIN_PING_INTERVAL = 100.milliseconds

/** [H1Pool]'s answers from the pool: a permit to open a connection, or a change of the route's HTTP/2 connections. */
private val PERMIT = Any()
private val CHANGED = Any()
private val MAX_ATTEMPT_DELAY = 2.seconds
