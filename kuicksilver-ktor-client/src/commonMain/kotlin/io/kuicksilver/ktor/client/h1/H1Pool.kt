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
import io.ktor.http.takeFrom
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openWriteChannel
import io.ktor.util.date.GMTDate
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.ClosedReadChannelException
import io.ktor.utils.io.availableForRead
import io.ktor.utils.io.discard
import io.kuicksilver.http2.runtime.H2ClientConnection
import io.kuicksilver.io.ConnectionEndedException
import io.kuicksilver.ktor.client.Activity
import io.kuicksilver.ktor.client.ActivityInput
import io.kuicksilver.ktor.client.ActivityOutput
import io.kuicksilver.ktor.client.EchRoute
import io.kuicksilver.ktor.client.EngineEvents
import io.kuicksilver.ktor.client.KuicksilverEngineConfig
import io.kuicksilver.ktor.client.NoCoalescingKey
import io.kuicksilver.ktor.client.PriorityUpdaterKey
import io.kuicksilver.ktor.client.RequestDns
import io.kuicksilver.ktor.client.ResolvedProxy
import io.kuicksilver.ktor.client.WEBSOCKET_NOT_CONNECTED
import io.kuicksilver.ktor.client.checkCoalescing
import io.kuicksilver.ktor.client.cleartextNotPermitted
import io.kuicksilver.ktor.client.cleartextPolicyHost
import io.kuicksilver.ktor.client.coalescingRetired
import io.kuicksilver.ktor.client.connectTimeoutException
import io.kuicksilver.ktor.client.connectTimeoutMillis
import io.kuicksilver.ktor.client.evictEldest
import io.kuicksilver.ktor.client.h2.H2Conn
import io.kuicksilver.ktor.client.h2.H2Http11Required
import io.kuicksilver.ktor.client.h2.H2Misdirected
import io.kuicksilver.ktor.client.h2.H2NotProcessed
import io.kuicksilver.ktor.client.h2.H2Pool
import io.kuicksilver.ktor.client.h2.H2RefusedRoutes
import io.kuicksilver.ktor.client.h2.h2Exchange
import io.kuicksilver.ktor.client.h2.h2WebSocket
import io.kuicksilver.ktor.client.isIdempotent
import io.kuicksilver.ktor.client.mayCoalesce
import io.kuicksilver.ktor.client.newRequestDns
import io.kuicksilver.ktor.client.newWebSocketKey
import io.kuicksilver.ktor.client.platformCleartextPermitted
import io.kuicksilver.ktor.client.proxyTlsConfigFor
import io.kuicksilver.ktor.client.requestTimeoutMillis
import io.kuicksilver.ktor.client.socketHost
import io.kuicksilver.ktor.client.socketTimeoutMillis
import io.kuicksilver.ktor.client.tlsConfigFor
import io.kuicksilver.ktor.client.toInet
import io.kuicksilver.ktor.client.withEchRetry
import io.kuicksilver.ktor.client.withSocketInactivityTimeout
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.ktor.network.abort
import io.kuicksilver.ktor.network.awaitWebSocketOutputEnd
import io.kuicksilver.ktor.network.isAtWebSocketFrameBoundary
import io.kuicksilver.ktor.network.openDeliveringReadChannel
import io.kuicksilver.ktor.network.tls
import io.kuicksilver.tls.SessionCache
import io.kuicksilver.tls.TlsConnection
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.completedWithin
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
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.update
import kotlin.coroutines.CoroutineContext
import kotlin.time.Duration
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
    /** Ends the TLS session in order (close_notify) and then the socket, bounded; null: as [closeTransport]. */
    private val orderly: (() -> Unit)? = null,
    /** The socket's own channels under [tls] (the TCP connection's FIN in both directions); null without TLS. */
    private val tcpIn: ByteReadChannel? = null,
    private val tcpOut: ByteWriteChannel? = null,
    /** Whether a proxy carries the connection (for the call diagnostics). */
    val viaProxy: Boolean = false,
) : PooledConnection(key, createdAt) {
    override val remoteIp: ByteArray? get() = WebSocketConnecting.peerIp(socket.remoteAddress)

    /** The call diagnostics of a call on this connection ([io.kuicksilver.ktor.client.TcpConnectionSnapshot]). */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    fun snapshot(reused: Boolean): io.kuicksilver.ktor.client.TcpConnectionSnapshot =
        io.kuicksilver.ktor.client.TcpConnectionSnapshot(
            HttpProtocolVersion.HTTP_1_1,
            socket.localAddress as? io.ktor.network.sockets.InetSocketAddress,
            socket.remoteAddress as? io.ktor.network.sockets.InetSocketAddress,
            reused,
            tls?.negotiatedAlpn,
            viaProxy,
            tls != null,
            tls?.protocolVersion,
        )

    /**
     * What the server sends, with the size limit on each response head ([MAX_RESPONSE_HEAD_BYTES]). Cancelled (a body
     * abandoned, a timeout), it ends over TLS with [TlsConnection.cancelInput]: the session reads on and drops what still
     * comes, so an orderly close still gets the server's close_notify instead of closing under its unread data, up to
     * `TlsConnection.INPUT_DROP_LIMIT`, 256 KiB; a longer rest is cut, not downloaded.
     */
    val input: HeadLimitedInput =
        if (tls != null) {
            HeadLimitedInput(rawInput, MAX_RESPONSE_HEAD_BYTES) { tls.cancelInput(it) }
        } else {
            HeadLimitedInput(rawInput, MAX_RESPONSE_HEAD_BYTES)
        }

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

    override fun closeTransportOrderly() {
        orderly?.invoke() ?: closeTransport()
    }

    /**
     * Everything handed to the connection's output has been taken by the socket's writer (and, over TLS, by the TLS
     * session, then the socket's writer): nothing waits in the channels in front of the kernel. A TLS record the session
     * is encrypting at that moment is not seen.
     */
    fun outputDrained(): Boolean = output.queuedNothing() && (tcpOut?.queuedNothing() ?: true)

    private fun ByteWriteChannel.queuedNothing(): Boolean = (this as? ByteReadChannel)?.availableForRead == 0

    // the raw socket first, with a reset: the TLS session's close ends its output, and a raw writer still draining would
    // send a FIN (and the rest it holds) ahead of the reset
    override fun abortTransport() {
        socket.abort()
        tls?.close()
    }

    /**
     * Ends the reading side at once (a timeout fired): whoever waits on [input] fails now, not when the orderly close is
     * over (the peer's close_notify, or its bound); the output still says goodbye.
     */
    fun cancelInput(cause: Throwable) {
        input.cancel(cause)
    }

    /**
     * Ends the connection of a WebSocket session that ended in order (both Closes sent and received), as RFC 6455 section
     * 7.1.1 wants of a client: "when a client is instructed to [_Close the WebSocket Connection_], it SHOULD wait for a TCP
     * Close from the server", closing "cleanly ... discarding any trailing bytes", as in its example: "shutdown() with
     * SHUT_WR on the socket, call recv() until obtaining a return value of 0 indicating that the peer has also performed an
     * orderly shutdown, and finally call close()". Here the order is the server's first:
     *
     * - without TLS: what the server still sends is read and dropped until its FIN, then this side's FIN, then the close;
     * - over TLS: the server's plaintext is read and dropped until its close_notify (or the end of its transport), then this
     *   side's close_notify (RFC 9846 section 6.1: "Each party MUST send a "close_notify" alert before closing its write
     *   side of the connection"; with TLS 1.2 it answers the server's, which TLS before 1.3 required at once), then the
     *   server's TCP FIN is awaited, then this side's FIN and the close.
     *
     * The waits for the server end after [waitMillis] (T2, [io.kuicksilver.ktor.client.WebSocketLifetime.remainingTransportWaitMillis]):
     * "in abnormal cases (such as not having received a TCP Close from the server after a reasonable amount of time) a
     * client MAY initiate the TCP Close", so this side's close_notify (bounded by [ORDERLY_CLOSE_TIMEOUT] more) and FIN go
     * then, cleanly, never a reset. [inputDone] completes once the session stopped reading [input]. [onEvent] (tests) gets
     * "waiting" once everything this side sends before the server's close is out, then "server closed" or "T2". A
     * cancellation (the end handlers' bound) or a [close] meanwhile (the pool's, the engine's) closes the connection where it
     * stands. The slot comes back when it is over, or at that [close].
     */
    suspend fun closeAfterWebSocket(
        waitMillis: Long,
        inputDone: Job,
        serverClosedForTest: (suspend () -> Unit)? = null,
        onEvent: (String) -> Unit = {},
    ) {
        if (!claimClose()) return
        try {
            // in a coroutine of its own, which [close] cancels (abortClaimedClose): the end handler that runs this goes on
            coroutineScope {
                val work = launch { closeInOrder(waitMillis, inputDone, serverClosedForTest, onEvent) }
                lingering = work
                if (abortRequested) work.cancel()
                work.join()
            }
        } finally {
            lingering = null
            tls?.close()
            socket.close()
            slotBack()
        }
    }

    @kotlin.concurrent.Volatile private var lingering: Job? = null

    @kotlin.concurrent.Volatile private var abortRequested = false

    override fun abortClaimedClose() {
        abortRequested = true
        lingering?.cancel()
    }

    private suspend fun closeInOrder(
        waitMillis: Long,
        inputDone: Job,
        serverClosedForTest: (suspend () -> Unit)?,
        onEvent: (String) -> Unit,
    ) {
        val deadline =
            kotlin.time.TimeSource.Monotonic
                .markNow() + waitMillis.milliseconds

        fun left() = (-deadline.elapsedNow()).inWholeMilliseconds.coerceAtLeast(0)
        try {
            // the server's close of its side: its plaintext ends (close_notify, or its transport's end), or its FIN
            onEvent("waiting")
            // a close read as T2 fires is the server's close: dropped, the server's FIN was not read over TLS
            val serverClosed =
                completedWithin(left().milliseconds) {
                    inputDone.join()
                    drainToEnd(input)
                    serverClosedForTest?.invoke()
                    true
                } == true
            onEvent(if (serverClosed) "server closed" else "T2")
            if (tls != null) {
                // close_notify: after the server's, or once T2 is over; then the server's FIN
                withTimeoutOrNull(ORDERLY_CLOSE_TIMEOUT) { tls.shutdown(drainTimeout = null, stopAwaitingPeer = DONE) }
                // the session's pumps stop before the socket's input is read here: its reader may still be reading it
                // (the server's input ended without close_notify, or the shutdown above did not wait for the peer)
                val pumpsStopped = withTimeoutOrNull(ORDERLY_CLOSE_TIMEOUT) { tls.closeAndAwaitPumps() } != null
                if (serverClosed && pumpsStopped && tcpIn != null) withTimeoutOrNull(left()) { drainToEnd(tcpIn) }
            }
            // this side's FIN after everything written, then the close
            withTimeoutOrNull(ORDERLY_CLOSE_TIMEOUT) { (tcpOut ?: output).flushAndClose() }
        } finally {
            tls?.close()
            socket.close()
        }
    }
}

/** Reads and drops [input] to its end; a failed input (a reset, a TLS truncation) ends it too. */
private suspend fun drainToEnd(input: ByteReadChannel) {
    try {
        input.discard()
    } catch (e: CancellationException) {
        throw e
    } catch (_: Throwable) {
        // the input failed: it has ended all the same
    }
}

/** The ALPN of the TLS configuration another origin's certificate check uses for an HTTP/2 connection (as a new one offers). */
private val H2_ALPN = listOf("h2", "http/1.1")

/** A completed job: a TLS shutdown that does not wait for the peer's close_notify, already in hand. */
private val DONE: Job = Job().also { it.complete() }

/**
 * The TCP path: HTTP/1.1, and HTTP/2 when the server picks `h2` in ALPN (RFC 9113 section 3.2; ADR-0017), over TLS 1.3 or 1.2, or
 * over cleartext TCP with prior knowledge for the origins in `http2 { priorKnowledge }` (h2c, section 3.3; ADR-0018).
 * An HTTP/2 connection takes one slot of the limits below and serves its route's requests as streams ([H2Pool]): one
 * connection per route while it has a free stream, a second only when it is full. HTTP/1.1 keeps keep-alive and the
 * connection limits ([ConnectionPool]): at most
 * `pool { maxConnections }` connections and `maxConnectionsPerRoute` per route, requests beyond that wait in FIFO
 * order within the connect timeout; a connection whose response body ended by its framing goes back to an idle list of at
 * most `maxIdleConnectionsPerRoute` per route, kept for `idleTimeout`. A stale idle connection is replaced once, transparently,
 * for idempotent requests only (RFC 9110 section 9.2.2, RFC 9112 section 9.3.1): a request the server may have processed
 * is never sent twice.
 */
internal class H1Pool(
    private val config: KuicksilverEngineConfig,
    private val selector: SelectorManager,
    private val events: EngineEvents = EngineEvents(null, io.kuicksilver.quic.KuicksilverLogger.None),
    private val clock: () -> Long = monotonicMillis(),
    /**
     * An ALTSVC frame (RFC 7838 section 4) for the origin of the URL, from an HTTP/2 connection to it that goes through no
     * proxy (no `Alt-Svc` is learned through one); it must not block.
     */
    private val altSvcFrame: (Url, String) -> Unit = { _, _ -> },
) {
    /** The HTTP/2 settings of the engine's connections (`http2 { settings { } }`). */
    private val h2Settings: io.kuicksilver.http2.Http2Settings = config.resolveHttp2Settings()

    /**
     * Orderly closes in progress ([closeOrderly]): TLS close_notify after what was written, bounded by
     * [ORDERLY_CLOSE_TIMEOUT]. Not the engine's request job; [closeAll] waits for them before the selector goes.
     */
    private val closers = CoroutineScope(selector.coroutineContext.minusKey(Job) + SupervisorJob() + CoroutineName("kuicksilver-close"))

    /**
     * The bound of [closeOrderly], [ORDERLY_CLOSE_TIMEOUT] (a test hook: a test stretches it to tell a call that waited
     * for the orderly close from one that did not by a wide margin).
     */
    internal var orderlyCloseTimeoutForTest: Duration = ORDERLY_CLOSE_TIMEOUT

    /** Test hook: gets how long each [closeOrderly] took, once the connection is closed (in order or past its bound). */
    internal var orderlyCloseTookForTest: ((Duration) -> Unit)? = null

    /** Test hook: the cause a connection's input is cut with, by an orderly close or an expired timeout, as it is cut. */
    internal var inputCutForTest: ((Throwable) -> Unit)? = null

    /**
     * Ends [tls] (none for h2c) in order and then the socket under it: what the application wrote, then close_notify (RFC 9846 section 6.1:
     * "Each party MUST send a 'close_notify' alert before closing its write side of the connection, unless it has already
     * sent some error alert"), a short wait for the peer's, then [rawOut] flushed so that it all reaches the wire before the
     * FIN. Bounded by [ORDERLY_CLOSE_TIMEOUT]; past it, and when the engine is closed meanwhile, the connection is closed
     * hard. Runs in [closers], never in the caller. With [dropInput] (an HTTP/1.1 connection, which nobody reads once it
     * closes, and an HTTP/2 one, whose read loop has stopped with the connection) what the server still sends is read and dropped ([TlsConnection.cancelInput]): the wait for its close_notify
     * then lasts while it sends, not while nobody reads (a response refused after its head, its body still coming, held
     * each such close to the bound). The session still reads its records, so a ticket is still taken. Past the session's
     * drop bound (`TlsConnection.INPUT_DROP_LIMIT`) it stops reading and the close comes under the rest: a response
     * abandoned mid-body is cut, as it was before the drop, not downloaded for as long as the wait lasts.
     */
    private fun closeOrderly(
        tls: TlsConnection?,
        rawOut: ByteWriteChannel,
        tcp: Socket,
        dropInput: Boolean = false,
    ) {
        // ATOMIC: an engine closed meanwhile still runs the finally block, which closes the connection hard
        @OptIn(DelicateCoroutinesApi::class)
        closers.launch(start = CoroutineStart.ATOMIC) {
            val started =
                kotlin.time.TimeSource.Monotonic
                    .markNow()
            try {
                val bound = orderlyCloseTimeoutForTest
                if (dropInput) {
                    val cut = ConnectionEndedException.LocalClose("the connection is closing")
                    inputCutForTest?.invoke(cut)
                    tls?.cancelInput(cut)
                }
                withTimeoutOrNull(bound) {
                    tls?.shutdown(drainTimeout = bound)
                    rawOut.flushAndClose()
                }
            } finally {
                tls?.close()
                tcp.close()
                orderlyCloseTookForTest?.invoke(started.elapsedNow())
            }
        }
    }

    /** The HTTP/2 connections' coroutines: not the engine's request job, which waits for its children before the cleanup. */
    private val h2Scope = CoroutineScope(selector.coroutineContext.minusKey(Job) + SupervisorJob() + CoroutineName("kuicksilver-h2"))

    /** HTTP/2 connections by route; internal for tests. */
    internal val h2 = H2Pool(config.poolLimits(), clock)

    /**
     * An HTTP/2 connection from which nothing arrived for this long is checked with a PING before it takes a request
     * (Chromium checks a session idle for 10 s, "at risk of loss"); internal so tests can check every reuse.
     */
    internal var h2HealthAfterIdleMillis: Long = 10_000

    /** Test hook: runs as a reserved stream's connection starts its health check ([answersHealthCheck]), before the PING. */
    internal var healthCheckForTest: (suspend () -> Unit)? = null

    /**
     * Tests: the connection of a WebSocket that ended in order has sent everything it sends before the server closes its
     * side ("waiting"), then saw that close ("server closed") or gave up at T2 ("T2").
     */
    internal var webSocketClosingForTest: ((String) -> Unit)? = null

    /** Test hook: runs once a WebSocket's connection read the server's close (HTTP/1.1), still inside T2. */
    internal var webSocketServerEndForTest: (suspend () -> Unit)? = null

    /** Test hook: runs once a request obtained its connection or stream, still inside the connect timeout. */
    internal var obtainedForTest: (suspend () -> Unit)? = null

    /**
     * Test hook: gets what is left of the connect timeout, in milliseconds, as a request starts to obtain its connection
     * (for a WebSocket, after its name resolution took its part): a test reads the budget the step got instead of timing it.
     */
    internal var obtainBudgetForTest: ((Long) -> Unit)? = null

    /**
     * Test hook: gets the deadline of a new HTTP/2 connection's wait for the server's preface (what TCP, the proxy and TLS
     * left of the connect timeout): a test reads the budget the step got instead of timing it.
     */
    internal var prefaceTimeoutForTest: ((Duration) -> Unit)? = null

    /** Test hook: runs once a WebSocket's addresses (its connecting keys) were resolved, still inside the connect timeout. */
    internal var remoteHostsForTest: (suspend () -> Unit)? = null

    /** Tests: the connection a WebSocket session was handed over. */
    internal var webSocketConnectionForTest: ((H1Connection) -> Unit)? = null

    /** Runs after a request got a pool permit and before it may become its route's dialer (tests: widens that gap). */
    internal var beforeDialForTest: (suspend () -> Unit)? = null

    /**
     * Runs once an HTTP/2 connection has started, before it is handed out, with its TCP socket (tests: lets the server end
     * it, and the socket close, first, as a GOAWAY right after the preface can).
     */
    internal var afterH2StartForTest: (suspend (H2ClientConnection, Socket) -> Unit)? = null

    /** The coroutines of the HTTP/2 connections (tests: none outlives its connection). */
    internal val h2JobsForTest: Sequence<Job> get() = h2Scope.coroutineContext[Job]!!.children

    /** Routes that answered HTTP_1_1_REQUIRED; internal for tests. */
    internal val h2Refused = H2RefusedRoutes(clock)

    /** Routes known to handle HTTP/1.1 (RFC 9112 section 6.1); internal for tests. */
    internal val http11Routes = Http11Routes()

    /**
     * The user's configuration says the server [data] goes to handles HTTP/1.1 (RFC 9112 section 6.1): `http1 { knownServers }`
     * is `KnownServers.All`, or `Listed` with that server (the origin, or the proxy for plain `http` in the absolute form).
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private fun configuredHttp11(
        data: HttpRequestData,
        proxy: ResolvedProxy?,
        tunneled: Boolean,
    ): Boolean {
        val known = config.http1.knownServers
        if (known == io.kuicksilver.ktor.client.KnownServers.None) return false
        val server =
            if (proxy != null && !tunneled) {
                io.kuicksilver.ktor.client
                    .HostPort(proxy.host, proxy.port)
            } else {
                io.kuicksilver.ktor.client
                    .HostPort(data.url.host, data.url.port)
            }
        return known.knows(server)
    }

    /** Tests: [data]'s route is known to handle HTTP/1.1, as after an earlier HTTP/1.1 response on it. */
    internal fun knowsHttp11ForTest(
        data: HttpRequestData,
        proxy: ResolvedProxy? = null,
    ) = http11Routes.mark(keyOf(data, proxy))

    init {
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        val ping = config.http2.pingInterval
        require(ping == null || ping >= MIN_PING_INTERVAL) { "http2 { pingInterval } must be at least 100 ms, or null (none), was $ping" }
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        val delay = config.network.happyEyeballsDelay
        // RFC 8305 section 8: the Minimum Connection Attempt Delay (100 ms) to the Maximum (2 s)
        require(delay == null || delay in MIN_ATTEMPT_DELAY..MAX_ATTEMPT_DELAY) {
            "network { happyEyeballsDelay } must be 100 ms..2 s, or null (one address after another; RFC 8305 section 8), was $delay"
        }
    }

    /** The platform's cleartext policy (Android Network Security Configuration); replaced by tests. */
    internal var cleartextPermitted: (String) -> Boolean = { host -> platformCleartextPermitted(host) }

    /** Limits, keep-alive and idle expiry; internal for tests. */
    internal val pool = ConnectionPool<H1Connection>(config.poolLimits(), clock)

    /** This engine's TLS session tickets (resumption secrets stay native); closed by [closeAll], so closing the engine drops them. */
    internal val sessions = SessionCache()

    /**
     * The TLS session tickets of `https://` proxies, apart from [sessions]: a proxy's ticket never goes to an origin nor an
     * origin's to a proxy, whatever their names (one host can be both); closed with [sessions].
     */
    internal val proxySessions = SessionCache()

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

    /**
     * Closes every connection: GOAWAY (NO_ERROR) on every HTTP/2 connection, written and closed in order (RFC 9113 section
     * 6.8; at most [ORDERLY_CLOSE_TIMEOUT]), then the idle HTTP/1.1 connections with close_notify, and waits for the
     * orderly closes (at most twice [ORDERLY_CLOSE_TIMEOUT]): about 3 s at most in all. The hard part (pool shutdown, the
     * closes cut off, the scopes and the session cache) always runs, also when the caller is cancelled, and is over when
     * this returns, so the selector may go next.
     */
    suspend fun closeAll() {
        withContext(NonCancellable) {
            try {
                h2.closeAll(ORDERLY_CLOSE_TIMEOUT)
                pool.shutdown()
                withTimeoutOrNull(ORDERLY_CLOSE_TIMEOUT * 2) {
                    closers.coroutineContext[Job]!!
                        .children
                        .toList()
                        .forEach { it.join() }
                }
            } finally {
                pool.shutdown() // idempotent; a close cut off before it still frees the idle connections
                // closes still running end hard (their finally closes TLS and the socket) before the selector goes
                closers.coroutineContext[Job]!!.cancelAndJoin()
                h2Scope.cancel()
                sessions.close() // a connection still finishing stores its ticket into a closed cache, which releases it
                proxySessions.close()
            }
        }
    }

    private fun keyOf(
        data: HttpRequestData,
        proxy: ResolvedProxy?,
    ): String =
        data.url.let {
            "${it.protocol.name}://${it.host}:${it.port}|${proxy?.routeKey}"
        }

    /**
     * The HTTP/2 route of a [key]: a WebSocket's is its HTTP origin's (`wss` is `https`, RFC 8441 section 5: "The scheme of
     * the target URI ... MUST be "https" for "wss"-schemed WebSockets"), so it finds that origin's connections and its
     * HTTP_1_1_REQUIRED mark; any other request's is the key itself.
     */
    private fun h2RouteOf(key: String): String =
        when {
            key.startsWith("wss://") -> "https://" + key.removePrefix("wss://")
            key.startsWith("ws://") -> "http://" + key.removePrefix("ws://")
            else -> key
        }

    /**
     * A connection for [data]: an idle pooled one, else a new one (the HTTP/1.1 side of the h3/h1 race). [Opened.reused]
     * travels with it to [execute], so a pooled connection the server closed still earns the stale-connection retry.
     */
    suspend fun open(
        data: HttpRequestData,
        dns: RequestDns = config.newRequestDns(events.dnsObserver(data)),
    ): Opened =
        obtain(data, keyOf(data, null), dns, null, webSocketKeys = null).let {
            Opened(it.connection, it.reused, it.h2, it.coalesced)
        }

    /**
     * A connection [open] handed out and whether it came from the idle pool (or, for HTTP/2, was open already): an HTTP/1.1
     * [connection], or a stream reserved on the HTTP/2 connection [h2], another origin's when [coalesced] (ADR-0018).
     */
    class Opened(
        val connection: H1Connection?,
        val reused: Boolean,
        val h2: H2Conn? = null,
        val coalesced: Boolean = false,
    )

    /** A connection from [obtain] (as [Opened]) and the WebSocket keys it holds. */
    private class Obtained(
        val connection: H1Connection?,
        val reused: Boolean,
        val held: WebSocketConnecting.Held?,
        val h2: H2Conn? = null,
        val coalesced: Boolean = false,
    )

    /**
     * Whether [data] may open or use an HTTP/2 connection on [key]: enabled, `https` or an h2c origin ([h2cPriorKnowledge]), not a WebSocket
     * (one takes HTTP/2 only on a connection that is there already, [webSocketConnection]: a new connection for it
     * offers `http/1.1` only, as Chromium's) and the route did not answer HTTP_1_1_REQUIRED lately.
     */
    @OptIn(io.ktor.utils.io.InternalAPI::class)
    private fun h2Allowed(
        data: HttpRequestData,
        key: String,
    ): Boolean = h2Usable(data, key) && !data.attributes.contains(io.ktor.client.plugins.websocket.WEBSOCKETS_KEY) && !upgrades(data.body)

    /**
     * HTTP/2 is enabled, the request is `https` or for an h2c origin ([h2cPriorKnowledge]) and the route did not answer
     * HTTP_1_1_REQUIRED lately.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private fun h2Usable(
        data: HttpRequestData,
        key: String,
    ): Boolean = config.http2.enabled && (data.url.protocol.isSecure() || h2cPriorKnowledge(data.url)) && !h2Refused.isRefused(key)

    /**
     * RFC 9113 section 3.3: [url] is `http`/`ws` and its origin is in `http2 { priorKnowledge }`, so its connections are
     * h2c (HTTP/2 over cleartext TCP, the preface at once). Never for `https`/`wss`, which negotiate `h2` by ALPN.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private fun h2cPriorKnowledge(url: Url): Boolean =
        !url.protocol.isSecure() && config.http2.priorKnowledge.isNotEmpty() &&
            io.kuicksilver.ktor.client
                .HostPort(url.host, url.port) in config.http2.priorKnowledge

    /** How long a WebSocket waits for the SETTINGS of a new HTTP/2 connection before it goes over HTTP/1.1 (tests lower it). */
    internal var h2WebSocketSettingsWaitMillis: Long = 1_000

    /** Tests: each WebSocket-over-HTTP/2 session's output, as it is made. */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    internal var h2WebSocketOutputForTest: (io.kuicksilver.http2.runtime.H2StreamOutput) -> Unit = {}

    /** Tests: an HTTP/2 WebSocket waits for the server's END_STREAM ("waiting"); its own goes after it ("server ended") or at T2 ("T2"). */
    internal var h2WebSocketClosingForTest: ((String) -> Unit)? = null

    /** Test hook: runs once an HTTP/2 WebSocket read the server's end of its stream, still inside T2. */
    internal var h2WebSocketServerEndForTest: (suspend () -> Unit)? = null

    /**
     * A WebSocket's wait for its own Close to be written once its call ended after that Close was queued (any protocol),
     * and over HTTP/2 for its last frames and the server's END_STREAM after an orderly close (tests change it).
     */
    internal var webSocketCloseWaitMillis: Long = io.kuicksilver.ktor.client.WEBSOCKET_CLOSE_WAIT_MILLIS

    /**
     * A stream for a WebSocket over HTTP/2 (RFC 8441) on a usable connection of [key] whose server enabled Extended CONNECT,
     * reserved; null when there is none, and the WebSocket goes over HTTP/1.1 as before. RFC 8441 section 3: a client MAY
     * use Extended CONNECT "Upon receipt of SETTINGS_ENABLE_CONNECT_PROTOCOL with a value of 1", and the setting's initial
     * value is 0, so a connection whose server's SETTINGS have not arrived yet (it carries its first request) is waited
     * for before the WebSocket decides: at most [h2WebSocketSettingsWaitMillis] (1 s, within the connect timeout), then
     * the WebSocket goes over HTTP/1.1. A connection that allows it but has no free
     * stream is not waited for: the WebSocket takes a connection of its own (HTTP/1.1). A connection quiet for a while
     * gets the health PING other requests get first.
     */
    private suspend fun webSocketConnection(
        data: HttpRequestData,
        key: String,
    ): H2Conn? {
        val signal = h2.watch(key)
        val started =
            kotlin.time.TimeSource.Monotonic
                .markNow()
        try {
            while (true) {
                val seen = h2.version(key)
                val conns = h2.usable(key)
                var pending = false
                for (c in conns) {
                    if (!c.client.serverSettingsReceived) {
                        pending = true
                        continue
                    }
                    if (!c.client.serverAllowsExtendedConnect || !c.client.tryReserve()) continue
                    if (!answersHealthCheck(c, data)) {
                        c.client.unreserve()
                        if (c.client.reservedStreams > 0) {
                            c.client.shutdown()
                        } else {
                            // a peer that does not answer has not lost the transport: GOAWAY, close_notify, FIN, bounded
                            c.client.abortInOrder(
                                ConnectionEndedException.PeerUnresponsive("the HTTP/2 connection did not answer a health PING"),
                            )
                        }
                        continue
                    }
                    return c
                }
                if (!pending) return null
                // its SETTINGS (or its end) bump the route; a server that sends none within the budget does not hold the
                // WebSocket for its whole connect timeout: it goes over HTTP/1.1
                val left = h2WebSocketSettingsWaitMillis - started.elapsedNow().inWholeMilliseconds
                if (left <= 0 || withTimeoutOrNull(left) { signal.first { it > seen } } == null) return null
            }
        } finally {
            h2.unwatch(key)
        }
    }

    /**
     * For a `ws://` WebSocket ([data]) to an h2c origin whose route [route] has no usable HTTP/2 connection: opens one through
     * the path of any request to the origin (pooled, one dial per route, SETTINGS within the connect timeout) and leaves it
     * in the pool for [webSocketConnection] to take, which waits for its SETTINGS within [h2WebSocketSettingsWaitMillis]
     * and uses Extended CONNECT only when the server allows it (RFC 8441 section 3), else the WebSocket goes over HTTP/1.1
     * as on any connection without the setting. False when the route has a connection already (in use, full, or without
     * the setting: as for `wss://`, no second one is opened for the WebSocket), is marked HTTP_1_1_REQUIRED, or got
     * HTTP/1.1 (HTTP_1_1_REQUIRED on the new connection). A
     * connection that cannot be opened fails the WebSocket, as it fails any request to a listed origin (no fallback).
     */
    @OptIn(io.ktor.utils.io.InternalAPI::class)
    private suspend fun openH2cForWebSocket(
        data: HttpRequestData,
        route: String,
        dns: RequestDns,
        proxy: ResolvedProxy?,
    ): Boolean {
        // a route that answered HTTP_1_1_REQUIRED takes no HTTP/2 for a while: the dial below would open an HTTP/1.1
        // connection the WebSocket does not use (the caller checks it too, through h2Usable; kept here so the function holds
        // on its own)
        if (h2Refused.isRefused(route) || h2.usable(route).isNotEmpty()) return false
        val attributes = io.ktor.util.Attributes(concurrent = true)
        for (k in data.attributes.allKeys) {
            if (k == io.ktor.client.plugins.websocket.WEBSOCKETS_KEY) continue
            @Suppress("UNCHECKED_CAST")
            attributes.put(k as io.ktor.util.AttributeKey<Any>, data.attributes[k])
        }
        val plain =
            HttpRequestData(
                io.ktor.http
                    .URLBuilder(data.url)
                    .apply { protocol = io.ktor.http.URLProtocol.HTTP }
                    .build(),
                io.ktor.http.HttpMethod.Get,
                io.ktor.http.Headers.Empty,
                io.ktor.client.utils.EmptyContent,
                data.executionContext,
                attributes,
            )
        val got = obtain(plain, route, dns, proxy, webSocketKeys = null)
        got.connection?.let { pool.release(it) }
        val c = got.h2 ?: return false
        c.client.unreserve()
        return true
    }

    /** A body that takes over the connection (`Upgrade`): HTTP/2 has no such thing (RFC 9113 section 8.6), so HTTP/1.1. */
    private fun upgrades(body: OutgoingContent): Boolean =
        when (body) {
            is OutgoingContent.ProtocolUpgrade -> true
            is OutgoingContent.ContentWrapper -> upgrades(body.delegate())
            else -> false
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
     * [resolvedMillis] is what the WebSocket's name resolution before the keys ([remoteHosts]) took of the connect timeout:
     * resolving, waiting for room and connecting share one timeout, as for any other request, which resolves inside it.
     */
    private suspend fun obtain(
        data: HttpRequestData,
        key: String,
        dns: RequestDns,
        proxy: ResolvedProxy?,
        webSocketKeys: List<String>?,
        resolvedMillis: Long = 0,
    ): Obtained {
        val held = webSocketKeys?.let { webSocketConnecting.acquire(it) }
        val h2Ok = webSocketKeys == null && h2Allowed(data, key)
        val webSocketOverH2 = webSocketKeys != null && h2Usable(data, h2RouteOf(key))
        // a stream on another origin's connection when this route has none free (RFC 9113 section 9.1.1, ADR-0018)
        val coalesce = h2Ok && config.mayCoalesce(data, proxy != null)
        var conn: H1Connection? = null
        var stream: H2Conn? = null
        var reused = false
        var coalesced = false

        // what the request waits for (no allocation: a reused connection needs none of it), and, once a new connection is
        // set up, what its setup is doing: for the report of a connect timeout
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        var waitingFor: io.kuicksilver.ktor.client.ConnectStage? = null
        var progress: TcpProgress? = null
        // the connect timeout's start: a new HTTP/2 connection's wait for the server's SETTINGS gets what is left of it
        val connectStarted =
            kotlin.time.TimeSource.Monotonic
                .markNow()
        try {
            val budget = (data.connectTimeoutMillis(config) - resolvedMillis).coerceAtLeast(1)
            obtainBudgetForTest?.invoke(budget)
            withTimeout(budget) {
                run attempt@{
                    // RFC 8441: a WebSocket on an HTTP/2 connection there already, when its server allows Extended CONNECT
                    if (webSocketOverH2) {
                        webSocketConnection(data, h2RouteOf(key))?.let {
                            stream = it
                            reused = true
                            return@attempt
                        }
                        // an h2c origin (prior knowledge) has no HTTP/1.1 to offer a new connection first: a cold `ws://`
                        // opens the route's h2c connection as any request would, then decides on its SETTINGS
                        if (h2cPriorKnowledge(data.url) && openH2cForWebSocket(data, h2RouteOf(key), dns, proxy)) {
                            webSocketConnection(data, h2RouteOf(key))?.let {
                                stream = it
                                return@attempt
                            }
                        }
                    }
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
                                    if (!answersHealthCheck(found, data)) {
                                        found.client.unreserve()
                                        // calls still running on it (a long poll, an upload) are not cut: GOAWAY, no new streams,
                                        // closed when they are done; a connection without any is closed at once
                                        if (found.client.reservedStreams > 0) {
                                            found.client.shutdown()
                                        } else {
                                            // a peer that does not answer has not lost the transport: GOAWAY, close_notify,
                                            // FIN, bounded (RFC 9113 section 6.8, RFC 9846 section 6.1)
                                            found.client.abortInOrder(
                                                ConnectionEndedException.PeerUnresponsive(
                                                    "the HTTP/2 connection did not answer a health PING",
                                                ),
                                            )
                                        }
                                        continue
                                    }
                                    stream = found
                                    reused = true
                                    return@attempt
                                }
                                if (coalesce) {
                                    coalescedStream(data, key, dns)?.let {
                                        stream = it
                                        reused = true
                                        coalesced = true
                                        return@attempt
                                    }
                                }
                            }
                            waitingFor = io.kuicksilver.ktor.client.ConnectStage.PoolWait
                            // a connection the pool hands out is the request's at once, so obtain's catch below settles it
                            // like any other: kept when the connect timeout fired as it came, else given back
                            val got =
                                acquireOrChange(key, signal, seen) {
                                    conn = it
                                    reused = true
                                }
                            waitingFor = null
                            if (got === CHANGED) continue
                            if (got is H1Connection) {
                                conn = got
                                reused = true
                                return@attempt
                            }
                            // a route marked meanwhile (HTTP_1_1_REQUIRED on a connection of this loop) offers http/1.1 only
                            val offerH2 = h2Ok && !h2Refused.isRefused(key)
                            // one HTTP/2 connect at a time per route (RFC 9113 section 9.1): the others wait for its outcome
                            // without a permit, within the connect timeout
                            beforeDialForTest?.invoke()
                            if (offerH2 && signal != null && !h2.tryStartDial(key, seen!!)) {
                                pool.releasePermit(key)
                                waitingFor = io.kuicksilver.ktor.client.ConnectStage.H2DialWait
                                signal.first { it > seen }
                                waitingFor = null
                                continue
                            }
                            val dialer = offerH2 && signal != null
                            val opened =
                                try {
                                    connect(
                                        data,
                                        data.url,
                                        data.url.protocol.isSecure(),
                                        proxy,
                                        key,
                                        dns,
                                        offerH2,
                                        connectStarted,
                                        TcpProgress().also { progress = it },
                                    ).also {
                                        pool.adopt(it)
                                    }
                                } catch (e: Throwable) {
                                    pool.releasePermit(key)
                                    if (dialer) h2.endDial(key, null)
                                    throw e
                                }
                            if (opened is H1Connection) {
                                if (dialer) h2.endDial(key, false) // the waiting requests connect on their own now
                                conn = opened
                                return@attempt
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
                                    return@attempt
                                }
                                // our stream first, then the pool: another request cannot take the one stream this request opened for
                                if (c.client.tryReserve()) {
                                    h2.register(c)
                                    stream = c
                                    return@attempt
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
                                    // the call fails rather than open connection after connection to a server that refuses them.
                                    // A connection whose transport failed already fails the call with that loss: over TLS 1.3
                                    // the client's handshake completes before the server checks its certificate, and the
                                    // server's alert (certificate_required) is what the caller must see, not a refusal. Read
                                    // before the shutdown below, whose own end ("GOAWAY and no streams left") is no reason,
                                    // and only a loss with a cause: a refusal ended by the protocol stays a refusal
                                    val lost =
                                        (c.client.closeCause as? io.kuicksilver.http2.runtime.Http2Exception.ConnectionClosed)
                                            ?.takeIf { it.cause != null }
                                    c.client.shutdown()
                                    lost?.let {
                                        @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
                                        throw it.copyForCall()
                                    }
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
                obtainedForTest?.invoke()
            }
        } catch (e: Throwable) {
            // a connection or stream obtained as the connect timeout fires is the request's: the block set it as it
            // returned, and withTimeout threw for work that was done
            if (e is TimeoutCancellationException &&
                (conn != null || stream != null)
            ) {
                return Obtained(conn, reused, held, stream, coalesced)
            }
            held?.release()
            if (e is CancellationException) {
                // a cancellation as the block returned: the connection is not handed out, so its slot comes back here
                conn?.let { if (reused) pool.release(it) else it.close() }
                stream?.client?.unreserve()
                if (e is TimeoutCancellationException) {
                    val timeout = data.connectTimeoutException(data.connectTimeoutMillis(config), e)
                    val wait = waitingFor
                    val failures =
                        if (wait != null) {
                            listOf(
                                io.kuicksilver.ktor.client.ConnectFailure(
                                    io.kuicksilver.ktor.client.Transport.Tcp,
                                    wait,
                                    null,
                                    proxy != null,
                                    timeout,
                                ),
                            )
                        } else {
                            progress?.timedOut(timeout).orEmpty() // nothing pending (a health PING, an HTTP/2 preface): no report
                        }
                    for (f in failures) events.connectFailed(data, f)
                    throw timeout
                }
            }
            throw e
        }
        return Obtained(conn, reused, held, stream, coalesced)
    }

    /**
     * A stream reserved on a connection of another route that may carry [data] (RFC 9113 section 9.1.1, ADR-0018): its
     * certificate passes every check for [data]'s host and that host resolves to the address and port it is connected to
     * ([io.kuicksilver.ktor.client.checkCoalescing]), and it answers the health PING a quiet connection gets first. A
     * connection whose certificate fails for a reason that may apply to its own origins too (expired, revoked, no longer
     * trusted) is retired as it is found (RFC 9114 section 3.3). Null when none may: the request takes a connection of its
     * own route.
     */
    private suspend fun coalescedStream(
        data: HttpRequestData,
        key: String,
        dns: RequestDns,
    ): H2Conn? {
        for (c in h2.coalescingCandidates(key)) {
            val peer = c.peer ?: continue
            val verdict =
                config.checkCoalescing(peer, data.url.host, data.url.port, dns, H2_ALPN) { own, forHost ->
                    events.coalescingRetired(peer.ownHost, data.url.host, own, forHost)
                }
            if (verdict == io.kuicksilver.ktor.client.Coalesce.Retire) {
                // GOAWAY: its streams finish, no new ones; the next request of its own route connects anew and verifies
                h2.remove(c)
                c.client.shutdown()
                continue
            }
            if (verdict != io.kuicksilver.ktor.client.Coalesce.Yes || !c.client.tryReserve()) continue
            if (!answersHealthCheck(c, data)) {
                c.client.unreserve()
                if (c.client.reservedStreams > 0) {
                    c.client.shutdown()
                } else {
                    c.client.abortInOrder(ConnectionEndedException.PeerUnresponsive("the HTTP/2 connection did not answer a health PING"))
                }
                continue
            }
            return c
        }
        return null
    }

    /**
     * Whether [c], on which the caller reserved a stream, may take the request: true at once unless it was quiet for
     * [h2HealthAfterIdleMillis], else whether it answers a health PING, bounded ([healthTimeoutMillis]). The reservation
     * is the caller's on a result; when the check throws (the caller cancelled: the race lost to HTTP/3, the connect
     * timeout) it is given back here, as nobody else holds it yet: a stream left reserved would hold a concurrent-stream
     * slot and keep the connection from ever being idle, and so from eviction, until the engine closes.
     */
    private suspend fun answersHealthCheck(
        c: H2Conn,
        data: HttpRequestData,
    ): Boolean {
        if (c.client.receivedIdleMillis < h2HealthAfterIdleMillis) return true
        try {
            healthCheckForTest?.invoke()
            return c.client.checkHealth(healthTimeoutMillis(data))
        } catch (e: Throwable) {
            c.client.unreserve()
            throw e
        }
    }

    /** The bound of a health PING: half the connect timeout (the rest is for a new connection), at most 5 s. */
    private fun healthTimeoutMillis(data: HttpRequestData): Long = (data.connectTimeoutMillis(config) / 2).coerceIn(1, 5_000)

    /**
     * [ConnectionPool.acquire] for [key] (an idle [H1Connection], or [PERMIT] to open one); with [signal], it gives up
     * with [CHANGED] as soon as the route's HTTP/2 state changes after [seen]. What the pool granted meanwhile is never
     * lost: an idle connection goes to [taken] the moment the pool hands it out, so it is the caller's whatever ends the
     * wait ([obtain] keeps one that came as its connect timeout fired, and gives back one that came as it was cancelled);
     * a permit that came with a failure or a cancellation is given back here.
     */
    private suspend fun acquireOrChange(
        key: String,
        signal: StateFlow<Long>?,
        seen: Long?,
        taken: (H1Connection) -> Unit,
    ): Any {
        if (signal == null) return (pool.acquire(key)?.also(taken)) ?: PERMIT
        // the grant, kept outside the scope: a cancellation that reaches the scope before it ends (as its block returns
        // the grant, or while the watcher winds down) makes coroutineScope throw instead of returning it, which dropped an
        // idle connection taken from the pool, open and out of it for good. coroutineScope throws only once every child has
        // ended, so the grant is final when the catch looks at it
        var got: Any? = null
        try {
            return coroutineScope {
                val a =
                    launch(start = CoroutineStart.UNDISPATCHED) {
                        got = pool.acquire(key)?.also(taken) ?: PERMIT
                    }
                if (got == null) {
                    val watcher =
                        launch {
                            signal.first { it > seen!! }
                            a.cancel()
                        }
                    a.join()
                    watcher.cancel()
                }
                got ?: CHANGED
            }
        } catch (e: Throwable) {
            if (got === PERMIT) pool.releasePermit(key) // a connection went to taken: the caller's catch settles it
            throw e
        }
    }

    /**
     * One exchange; [preopened] is a connection the race already obtained ([open]), [dns] the request's name resolution,
     * [proxy] the proxy that applies to the request (the engine resolved it), null for a direct connection.
     */
    suspend fun execute(
        data: HttpRequestData,
        callContext: CoroutineContext,
        preopened: Opened? = null,
        dns: RequestDns = config.newRequestDns(events.dnsObserver(data)),
        proxy: ResolvedProxy? = null,
        onSelected: ((HttpProtocolVersion) -> Unit)? = null,
    ): HttpResponseData {
        @OptIn(io.ktor.utils.io.InternalAPI::class)
        val webSocket = data.attributes.contains(io.ktor.client.plugins.websocket.WEBSOCKETS_KEY)
        // a WebSocket is CONNECTING from its connection until the server answers its handshake (RFC 6455 section 4.1)
        if (!webSocket) return exchange(data, callContext, preopened, dns, proxy, null, onSelected)
        val resolving =
            kotlin.time.TimeSource.Monotonic
                .markNow()
        val keys = remoteHosts(data, dns, proxy)
        return exchange(data, callContext, preopened, dns, proxy, keys, onSelected, resolving.elapsedNow().inWholeMilliseconds)
    }

    /** Race-opened connections a WebSocket gave back because its keys were taken (tests). */
    @kotlin.concurrent.Volatile
    internal var raceConnectionsReturnedForTest = 0

    /** One WebSocket at a time in the CONNECTING state per remote host (RFC 6455 section 4.1, step 2). */
    internal val webSocketConnecting = WebSocketConnecting()

    /**
     * The remote hosts [data] may connect to, as [WebSocketConnecting] keys: the origin's name and its IP addresses, without
     * the port, when the engine resolves its name (the families of the request's own resolution that answered, the other
     * waited for only during the Resolution Delay, under the connect timeout: [RequestDns.answered]), else (an HTTP proxy, a SOCKS5 proxy that resolves names) the origin's name; each in one form per
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
        // the families that answered: one that stalls (dropped AAAA queries) holds back neither the keys nor the connection,
        // which the race makes with what came (RFC 8305 section 3); the connection's own address is added once it is up
        // (exchange). Kept as they are known, inside the lookups' scope: answers that came as the connect timeout fires
        // are the answers, also when it lands as that scope completes
        var addresses: List<TcpAddress>? = null
        withTimeoutOrNull(data.connectTimeoutMillis(config)) {
            dns.answered(url.host, url.port, onAnswered = { addresses = it }, afterForTest = remoteHostsForTest)
        }
        val answered = addresses ?: throw data.connectTimeoutException(data.connectTimeoutMillis(config), null)
        return listOf(WebSocketConnecting.nameKey(url.host)) + answered.map { WebSocketConnecting.addressKey(it) }
    }

    /**
     * [execute]; [webSocketKeysAsked] are the remote hosts of a WebSocket ([remoteHosts]), null for any other request. A
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
        webSocketKeysAsked: List<String>?,
        onSelected: ((HttpProtocolVersion) -> Unit)?,
        resolvedMillis: Long = 0,
    ): HttpResponseData {
        // a request sent again over HTTP/1.1 (after a 421 or a failure over HTTP/3 or HTTP/2) leaves its earlier stream
        // behind: HttpResponse.updatePriority must not reach that stream
        data.attributes.remove(PriorityUpdaterKey)
        val url = data.url
        val secure = url.protocol.isSecure()
        if (!secure) {
            val host = cleartextPolicyHost(url.host)
            if (!cleartextPermitted(host)) throw cleartextNotPermitted(host)
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
        var webSocketKeys = webSocketKeysAsked
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
                    Obtained(pre.connection, pre.reused, preHeld, pre.h2, pre.coalesced)
                } else {
                    // the resolution counts once, against the first connection (a repeat gets a connect timeout of its own)
                    obtain(data, key, dns, proxy, webSocketKeys, if (attempt == 1) resolvedMillis else 0)
                }
            // a WebSocket holds the address its connection actually goes to (RFC 6455 section 4.1): one its keys did not
            // name (a family that answered late, a pooled or race connection) is taken now, without waiting; when another
            // WebSocket holds it, the connection goes back and this one waits for every key, that one too
            val wsHeld = obtained.held
            if (webSocketKeys != null && proxy == null && wsHeld != null) {
                val peer = (obtained.connection ?: obtained.h2)?.remoteIp?.let { WebSocketConnecting.ipKey(it) }
                if (peer != null && !wsHeld.tryAdd(peer)) {
                    obtained.connection?.let { pool.release(it) }
                    obtained.h2?.client?.unreserve()
                    wsHeld.release()
                    webSocketKeys = webSocketKeys + peer
                    continue
                }
            }
            val h2c = obtained.h2
            val protocol = if (h2c != null) HttpProtocolVersion.HTTP_2_0 else HttpProtocolVersion.HTTP_1_1
            // the connection in hand, for the call's diagnostics: one object per connection a call is sent on
            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
            diagnostics?.connection =
                if (h2c != null) {
                    io.kuicksilver.ktor.client.TcpConnectionSnapshot(
                        HttpProtocolVersion.HTTP_2_0,
                        h2c.localAddress,
                        h2c.remoteAddress,
                        obtained.reused,
                        "h2",
                        h2c.viaProxy,
                        true,
                        h2c.tlsVersion,
                    )
                } else {
                    obtained.connection?.snapshot(obtained.reused)
                }
            // HTTP/1.1 where HTTP/2 would have been offered, but the route answered HTTP_1_1_REQUIRED lately
            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
            if (h2c == null && diagnostics != null && webSocketKeys == null && !h2Allowed(data, key) &&
                config.http2.enabled && (secure || h2cPriorKnowledge(url)) && h2Refused.isRefused(h2RouteOf(key))
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
                    val released = { kept: Boolean ->
                        events.emit("connectionReleased") { connectionReleased(data, HttpProtocolVersion.HTTP_2_0, kept) }
                    }
                    if (webSocketKeys == null) return h2Exchange(h2c, data, callContext, events, obtained.coalesced, released)
                    // RFC 8441: the WebSocket's Extended CONNECT; it holds its keys (RFC 6455 section 4.1) until the server
                    // answered, and that answer comes within the connect timeout, as over HTTP/1.1
                    try {
                        return connectingWithin(data) {
                            h2WebSocket(
                                h2c,
                                data,
                                callContext,
                                events,
                                webSocketCloseWaitMillis,
                                config.webSockets.maxMessageSize,
                                h2WebSocketOutputForTest,
                                { h2WebSocketClosingForTest?.invoke(it) },
                                h2WebSocketServerEndForTest,
                                released,
                            )
                        }
                    } finally {
                        obtained.held?.release()
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
                    // a connection that never worked (the server's SETTINGS never came) because the server refused this
                    // client in the handshake is not repeated: a new connection meets the same refusal after a full
                    // handshake (TLS 1.3: the server's certificate_required comes after the client's handshake ended). A
                    // connection that worked and was then lost (closed, reset, truncated: the TLS layer reports those as
                    // TlsException.Protocol) is repeated as RFC 9113 section 8.7 allows
                    if (++h2Repeats > 2 || (!h2c.client.serverSettingsReceived && e.cause.isHandshakeRefusal())) {
                        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                        diagnostics?.connectionWide(h2c.client.closeCause)
                        throw e.cause
                    }
                    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                    diagnostics?.let { it.attempts++ }
                    attempt++
                    events.emit("retry") { retry(data, attempt, e.cause) }
                    continue
                } catch (e: H2Misdirected) {
                    // RFC 9110 section 15.5.20: "A client that receives a 421 (Misdirected Request) response MAY retry the
                    // request, whether or not the request method is idempotent, over a different connection, such as a
                    // fresh connection specific to the target resource's origin". A coalesced request goes once more, on a
                    // connection of its own route; the connection carries no request of this host any more
                    h2c.hosts.record(url.host, accepted = false)
                    data.attributes.put(NoCoalescingKey, Unit)
                    if (e.bodyConsumed) {
                        throw io.kuicksilver.ktor.client.H3BodyConsumed(
                            "421 Misdirected Request on a connection of another origin (connection coalescing), and the " +
                                "request's streamed body was already consumed",
                            e,
                        )
                    }
                    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                    diagnostics?.let { it.attempts++ }
                    attempt++
                    events.emit("retry") { retry(data, attempt, e) }
                    continue
                } catch (e: H2Http11Required) {
                    // RFC 9113 section 7: the server wants this request over HTTP/1.1; the route offers only http/1.1 for a while
                    h2Refused.mark(h2RouteOf(key))
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
                } catch (e: Throwable) {
                    // the connection's end (one instance for every stream of it) is never this call's to carry
                    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                    if (e !is CancellationException) diagnostics?.connectionWide(h2c.client.closeCause)
                    throw e
                }
            }
            val conn = obtained.connection!!
            val reused = obtained.reused
            var held = obtained.held
            events.emit("connectionAcquired") { connectionAcquired(data, HttpProtocolVersion.HTTP_1_1, reused) }
            // RFC 9112 section 6.1: no Transfer-Encoding until the route is known to handle HTTP/1.1
            val configured = configuredHttp11(data, proxy, tunneled)
            val probeFirst = needsTransferEncoding(data) && !configured && !http11Routes.isKnown(key) && !http11Routes.wasProbed(key)
            var bodyJob: BodySender? = null
            // the whole request went out (headers and a body written in this call); a streamed body says so itself
            val requestOut = CompletableDeferred<Unit>()
            // nothing of an unfinished request is on the connection: before the request's head, or between a complete
            // first-contact probe and the request (prepareFirstContact may fail there)
            var between = true

            // RFC 9846 section 6.1: an exchange that failed after the whole request went out (a malformed response head,
            // a timeout, the call cancelled) leaves our write side whole: the connection ends with close_notify (a TLS 1.3
            // client cannot send an error alert). A request cut off, or a TLS session that failed, is closed at once.
            fun closeAfterFailure(e: Throwable?) {
                val sender = bodyJob
                val whole =
                    if (between) {
                        true
                    } else if (sender == null) {
                        requestOut.isCompleted
                    } else {
                        @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
                        sender.sent.isCompleted && sender.sent.getCompleted()
                    }
                val tlsFailed = generateSequence(e) { it.cause }.any { it is TlsException }
                if (whole && !tlsFailed) conn.closeOrderly() else conn.close()
            }

            /**
             * A timeout expired ([what]: the socket timeout, or a WebSocket's connect timeout): the reader is cut first, so the
             * call's timeout surfaces on time; then the close. The cut is the peer's silence
             * ([ConnectionEndedException.PeerUnresponsive]) only when the whole request was out and only the peer's answer was
             * awaited; while our own request was still going out (a request body the application produces slowly, or one
             * the peer stopped taking) it is a plain IOException: nothing says whose side stalled.
             */
            fun closeAfterExpiry(what: String = "the socket timeout expired") {
                val sender = bodyJob
                val awaitingThePeer =
                    !between &&
                        if (sender == null) {
                            requestOut.isCompleted
                        } else {
                            @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
                            sender.sent.isCompleted && sender.sent.getCompleted()
                        }
                val cut = if (awaitingThePeer) ConnectionEndedException.PeerUnresponsive(what) else kotlinx.io.IOException(what)
                inputCutForTest?.invoke(cut)
                conn.cancelInput(cut)
                closeAfterFailure(null)
            }

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
                    withSocketInactivityTimeout(data, activity, onExpiry = { closeAfterExpiry() }) {
                        // a new key for every connection a WebSocket handshake is sent on (RFC 6455 section 4.1)
                        val webSocketKey = if (webSocketKeys != null) newWebSocketKey() else null
                        var webSocket: H1WebSocketHandOver? = null
                        if (probeFirst) {
                            // first contact: an OPTIONS on the same connection shows the server's version before the
                            // request needs Transfer-Encoding; an HTTP/1.0 server gets the body framed by Content-Length
                            between = false
                            probeVersion(data, key, conn, output, input, proxy, tunneled, callContext)
                            between = true
                        }
                        // a server that answered the probe with another version: the body framed by Content-Length, once
                        // it ended within the connect timeout (or the request timeout when that is shorter)
                        if (!configured && !http11Routes.isKnown(key)) {
                            val connect = data.connectTimeoutMillis(config)
                            prepareFirstContact(data, data.requestTimeoutMillis()?.let { minOf(it, connect) } ?: connect)
                        }
                        between = false
                        writeHeaders(
                            data,
                            output,
                            overProxy = proxy != null && !tunneled,
                            tunneled = tunneled,
                            proxyAuthorization = proxy?.takeIf { !tunneled }?.basicAuthorization,
                            webSocketKey = webSocketKey,
                        )

                        suspend fun sendBody() {
                            bodySent = true
                            // a streamed body is sent while the response is read (as the CIO engine): the server may answer first
                            if (data.body.isStreamed() && data.firstContactBody() == null) {
                                bodyJob = sendBodyConcurrently(data, conn, output, callContext)
                            } else {
                                writeBody(data, output, callContext)
                                requestOut.complete(Unit)
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
                            webSocketKey = webSocketKey,
                            webSocketMaxMessageSize = config.webSockets.maxMessageSize,
                            webSocketCloseWaitMillis = webSocketCloseWaitMillis,
                            onHandOver = { webSocket = it },
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
                                        // with no request body still going out the connection ends in order (close_notify)
                                        val sender = bodyJob
                                        if (sender == null || (sender.sent.isCompleted && sender.failure == null)) {
                                            conn.closeOrderly()
                                        } else {
                                            conn.close()
                                        }
                                        bodyJob?.job?.cancel()
                                        released(false)
                                    }

                                    // a request body still being sent is not cut off: the connection closes when its
                                    // sender ends (sent, failed, or cancelled with the call)
                                    AfterResponse.CloseAfterUpload -> {
                                        val job = bodyJob?.job
                                        if (job == null) {
                                            conn.closeOrderly()
                                            released(false)
                                        } else {
                                            job.invokeOnCompletion { cause ->
                                                // in order once the body went out whole; a failed upload is cut off
                                                if (cause == null && bodyJob.failure == null) conn.closeOrderly() else conn.close()
                                                released(false)
                                            }
                                        }
                                    }

                                    // the connection ends with the WebSocket session: in the order of RFC 6455 section
                                    // 7.1.1 when the session ended in order (both Closes, its writer done), the server's
                                    // close first, within T2 (WebSocketLifetime); at once otherwise, cleanly (TLS
                                    // close_notify, a FIN: section 7.1.1, the client "SHOULD" close cleanly) when the
                                    // stream is whole and the socket took all of it: the frame guard stopped between frames
                                    // (that the writer ended says nothing: Ktor's ends its channel in order also when
                                    // cancelled inside a frame), and nothing waits in front of the kernel (a Close that went out,
                                    // the server's never came; a session cancelled while idle). It is reset otherwise: a
                                    // writer stopped inside a frame (behind a server that does not read, at the close
                                    // wait), frames still queued in front of the socket after the close wait, or a writer
                                    // that failed; a clean close would go on sending them after the close wait, or end a
                                    // cut frame as if the stream were whole
                                    AfterResponse.HandOver -> {
                                        val ws = webSocket
                                        if (ws != null) {
                                            webSocketConnectionForTest?.invoke(conn)
                                            ws.lifetime.invokeOnEnd { cause ->
                                                try {
                                                    // the end the frame guard held for Pongs after the client's Close goes first
                                                    ws.guard?.awaitWebSocketOutputEnd()
                                                    val failed = ws.output.closedCause != null
                                                    val writerDone = ws.output.endRequested && !failed
                                                    val end =
                                                        webSocketTransportEnd(
                                                            endedInOrder = cause == null,
                                                            failed = failed,
                                                            writerDone = writerDone,
                                                            atFrameBoundary = ws.guard?.isAtWebSocketFrameBoundary() == true,
                                                            drained = conn.outputDrained(),
                                                            cutByCloseWait = ws.lifetime.cutByCloseWait,
                                                        )
                                                    when (end) {
                                                        WebSocketTransportEnd.AfterServer -> {
                                                            conn.closeAfterWebSocket(
                                                                ws.lifetime.remainingTransportWaitMillis(),
                                                                ws.inputDone,
                                                                webSocketServerEndForTest,
                                                            ) { webSocketClosingForTest?.invoke(it) }
                                                        }

                                                        WebSocketTransportEnd.Orderly -> {
                                                            conn.closeOrderly()
                                                        }

                                                        WebSocketTransportEnd.Reset -> {
                                                            conn.abort()
                                                        }
                                                    }
                                                } finally {
                                                    conn.close() // a no-op after the close above; a cut-off one ends here
                                                    released(false)
                                                }
                                            }
                                        } else {
                                            callContext[Job]?.invokeOnCompletion {
                                                conn.close()
                                                released(false)
                                            }
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
                            null -> {
                                exchangeOnce()
                            }

                            else -> {
                                connectingWithin(data, onExpiry = {
                                    closeAfterExpiry("the WebSocket handshake was not answered within the connect timeout")
                                }) { exchangeOnce() }
                            }
                        }
                    } finally {
                        held?.release()
                    }
                // RFC 9112 section 6.1: "remembering the version of a prior received response"
                if (response.version.handlesHttp11()) http11Routes.mark(key)
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
            } catch (e: ProbeEndedConnection) {
                // the server closes the connection after its answer to the probe: the request goes on a new one; the
                // probe's exchange is complete, so the connection ends in order (close_notify, RFC 9846 section 6.1)
                held?.release()
                conn.closeOrderly()
                events.emit("connectionReleased") { connectionReleased(data, HttpProtocolVersion.HTTP_1_1, kept = false) }
                continue
            } catch (e: CancellationException) {
                held?.release()
                closeAfterFailure(e)
                events.emit("connectionReleased") { connectionReleased(data, HttpProtocolVersion.HTTP_1_1, kept = false) }
                throw e
            } catch (e: Throwable) {
                held?.release()
                closeAfterFailure(e)
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
     * RFC 9112 section 6.1 knowledge on first contact: sends `OPTIONS` for the request's target on [conn] (safe and
     * idempotent, RFC 9110 sections 9.2.1 and 9.2.2) and reads the answer to its end; its version marks the route as known
     * to handle HTTP/1.1, or as probed (not probed again). A server that does not keep the connection afterwards ends this
     * attempt with [ProbeEndedConnection]; what the route learned stays. Not used for a request that needs no
     * Transfer-Encoding, nor once the route is known or probed.
     */
    @OptIn(io.ktor.utils.io.InternalAPI::class)
    private suspend fun probeVersion(
        data: HttpRequestData,
        key: String,
        conn: H1Connection,
        output: ByteWriteChannel,
        input: ByteReadChannel,
        proxy: ResolvedProxy?,
        tunneled: Boolean,
        callContext: CoroutineContext,
    ) {
        val probe =
            io.ktor.client.request
                .HttpRequestBuilder()
                .apply {
                    url.takeFrom(data.url)
                    method = io.ktor.http.HttpMethod.Options
                }.build()
        writeHeaders(
            probe,
            output,
            overProxy = proxy != null && !tunneled,
            tunneled = tunneled,
            proxyAuthorization = proxy?.takeIf { !tunneled }?.basicAuthorization,
        )
        val after = CompletableDeferred<AfterResponse>()
        val response = readResponse(GMTDate(), probe, input, conn.output, callContext, conn.input) { after.complete(it) }
        (response.body as? ByteReadChannel)?.discard()
        val reusable = after.await() == AfterResponse.Reuse
        if (response.version.handlesHttp11()) http11Routes.mark(key) else http11Routes.markProbed(key)
        if (!reusable) throw ProbeEndedConnection()
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
            timeout = { data.connectTimeoutException(millis, it, WEBSOCKET_NOT_CONNECTED) },
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
     * TCP, TLS to an `https://` proxy, the proxy's tunnel (HTTP CONNECT or SOCKS5) and TLS; runs under [obtain]'s connect
     * timeout, which bounds every step of a proxy's handshake too.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private suspend fun connect(
        data: HttpRequestData,
        url: Url,
        secure: Boolean,
        proxy: ResolvedProxy?,
        key: String,
        dns: RequestDns,
        h2Ok: Boolean = false,
        connectStarted: kotlin.time.TimeMark =
            kotlin.time.TimeSource.Monotonic
                .markNow(),
        progress: TcpProgress? = null,
    ): PooledConnection {
        if (!secure) return connectOnce(data, url, false, proxy, key, dns, h2Ok, connectStarted, progress, null)
        // the origin's ECH (RFC 9849), also inside a proxy's tunnel; the TLS hop to an https proxy never offers it
        // (proxyTlsConfigFor), and a rejection there is the proxy's (echRejectionIn stops at a ProxyTlsException).
        // A rejection is retried once on a new connection with the server's retry configurations, or without ECH when it
        // sent none (section 6.1.6), within the same connect timeout
        val route = dns.echRoute(url.host) { config.tls.ech.listFor(it) }
        return withEchRetry(route) { offer -> connectOnce(data, url, true, proxy, key, dns, h2Ok, connectStarted, progress, offer) }
    }

    /** [connect] with the ECH [ech] offers (null for plain http). */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private suspend fun connectOnce(
        data: HttpRequestData,
        url: Url,
        secure: Boolean,
        proxy: ResolvedProxy?,
        key: String,
        dns: RequestDns,
        h2Ok: Boolean,
        connectStarted: kotlin.time.TimeMark,
        progress: TcpProgress?,
        ech: EchRoute.Offer?,
    ): PooledConnection {
        val (host, port) = if (proxy != null) proxy.host to proxy.port else url.host to url.port
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        progress?.stage = io.kuicksilver.ktor.client.ConnectStage.NameLookup // until an address is tried
        // through socks5:// (names resolved here) each address of the origin in turn while the proxy answers "network
        // unreachable" or "host unreachable" (RFC 1928 section 6, REP 3 and 4), each on a new connection to the proxy
        val socksTargets =
            if (proxy?.kind == ResolvedProxy.Kind.Socks5) socks5Targets(url.host, proxy.remoteDns, dns) else listOf(null)
        for ((attempt, socksTarget) in socksTargets.withIndex()) {
            // every address of the host as its two families arrive, sorted by RFC 6724 and alternating (RFC 8305); this
            // module's connects on Kotlin/Native, not ktor-network's (Ktor issue KTOR-10017, security, under coordinated
            // disclosure)
            val viaProxy = proxy != null

            // the literal each connected socket went to: the winner's is a direct HTTP/2 connection's destination, which
            // coalescing compares another origin's addresses with (ADR-0018); kept only when coalescing is on
            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
            val coalescingOn = config.pool.coalescing && proxy == null

            @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
            val connected = if (coalescingOn) kotlin.concurrent.atomics.AtomicReference(emptyList<Pair<Socket, TcpAddress>>()) else null

            // each address that fails is reported (connectFailed) as it fails, whatever the race then does
            @OptIn(
                io.kuicksilver.annotations.ExperimentalKuicksilverApi::class,
                io.kuicksilver.annotations.InternalKuicksilverApi::class,
            )
            val raw =
                io.kuicksilver.ktor.network.raceAddresses(
                    host,
                    dns.resolution(host, port),
                    config.network.happyEyeballsDelay ?: kotlin.time.Duration.INFINITE,
                    dns.order(),
                    connect = { a ->
                        val inet = a.toInet()
                        progress?.trying(inet, viaProxy)
                        try {
                            io.kuicksilver.ktor.network
                                .connectTcpAddress(selector, a)
                                .also { s ->
                                    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
                                    connected?.update { it + (s to a) }
                                }
                        } catch (e: Throwable) {
                            connectFailed(data, io.kuicksilver.ktor.client.ConnectStage.TcpConnect, inet, viaProxy, e)
                            throw e
                        } finally {
                            progress?.tried(inet)
                        }
                    },
                    close = { it.close() },
                )
            // the step on the connected socket, for a connect timeout that strikes during it: a proxy's handshake (TLS with an
            // https:// proxy included), else the TLS handshake with the origin
            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
            progress?.connected(
                raw.remoteAddress as? io.ktor.network.sockets.InetSocketAddress,
                when {
                    proxy != null -> io.kuicksilver.ktor.client.ConnectStage.ProxyHandshake
                    secure -> io.kuicksilver.ktor.client.ConnectStage.TlsHandshake
                    else -> null
                },
            )
            // an https:// proxy: everything from here on (the CONNECT or the absolute-form request, the credentials, the
            // origin's own TLS) goes inside TLS with the proxy, whose name its certificate must carry; the TLS socket
            // stands for the TCP one, so closing, aborting and the orderly close end both. Its failure is a failed proxy
            // handshake (connectFailed)
            val tcp =
                if (proxy?.tls == true) {
                    try {
                        proxyTls(raw, proxy)
                    } catch (e: Throwable) {
                        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                        connectFailed(
                            data,
                            io.kuicksilver.ktor.client.ConnectStage.ProxyHandshake,
                            raw.remoteAddress as? io.ktor.network.sockets.InetSocketAddress,
                            true,
                            e,
                        )
                        throw e
                    }
                } else {
                    raw
                }
            // set once an HTTP/2 connection has started on it: the transport is the connection's to close from then on
            var h2Owned = false
            try {
                val rawIn = tcp.openDeliveringReadChannel()
                val rawOut = tcp.openWriteChannel(autoFlush = true)
                try {
                    when {
                        proxy == null -> {}

                        socksTarget != null -> {
                            try {
                                socks5Connect(rawIn, rawOut, socksTarget, url.port, proxy.credentials, "$proxy")
                            } catch (e: io.kuicksilver.ktor.client.ProxyException) {
                                if ((e.replyCode != 3 && e.replyCode != 4) || attempt == socksTargets.lastIndex) throw e
                                // the next target goes on a new connection to the proxy: this refusal is a failed setup too
                                @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                                connectFailed(
                                    data,
                                    io.kuicksilver.ktor.client.ConnectStage.ProxyHandshake,
                                    tcp.remoteAddress as? io.ktor.network.sockets.InetSocketAddress,
                                    true,
                                    e,
                                )
                                tcp.close()
                                continue
                            }
                        }

                        // h2c through an HTTP proxy goes in a tunnel too: an absolute-form request is HTTP/1.1 (OkHttp's
                        // Route.requiresTunnel does the same for H2_PRIOR_KNOWLEDGE)
                        proxy.tunnels(data) || (h2Ok && !secure) -> {
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
                } catch (e: Throwable) {
                    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                    connectFailed(
                        data,
                        io.kuicksilver.ktor.client.ConnectStage.ProxyHandshake,
                        tcp.remoteAddress as? io.ktor.network.sockets.InetSocketAddress,
                        true,
                        e,
                    )
                    throw e
                }
                @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                progress?.stage = if (secure) io.kuicksilver.ktor.client.ConnectStage.TlsHandshake else null
                return if (secure) {
                    // through a proxy too: ALPN is inside the TLS session with the origin (OkHttp does the same)
                    val alpn = if (h2Ok) listOf("h2", "http/1.1") else listOf("http/1.1")
                    val tls =
                        try {
                            TlsConnection.client(
                                rawIn,
                                rawOut,
                                config.tlsConfigFor(url.host, alpn, quic = false, ech = ech),
                                callContextOrEmpty(),
                                sessions,
                            )
                        } catch (e: Throwable) {
                            tlsFailed(data, tcp, viaProxy, e)
                            throw e
                        }
                    progress?.stage = null // set up: a timeout from here on is no failure of the setup's steps
                    if (h2Ok && tls.negotiatedAlpn == "h2") {
                        // taken before the connection starts: the catches here close TLS (the inner one) and TCP (the outer
                        // one), not a started HTTP/2 connection, which owns the transport; what follows its start ends it
                        // itself (below)
                        val peerIp = WebSocketConnecting.peerIp(tcp.remoteAddress)

                        // the connection once made: an ALTSVC frame on a request stream names that stream's origin, which
                        // is not the connection's once it carries other origins (coalescing); read on the connection's reader
                        @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
                        val made = if (coalescingOn) kotlin.concurrent.atomics.AtomicReference<H2Conn?>(null) else null

                        // RFC 9113 section 3.2: h2 over TLS. Section 3.4: the request goes out right after our preface, without
                        // waiting for the server's; its preface (its SETTINGS) must still arrive within the connect timeout, or
                        // the connection ends with SETTINGS_TIMEOUT (h2Exchange maps that to the call's failure)
                        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                        val client =
                            try {
                                H2ClientConnection.start(
                                    tls.input,
                                    tls.output,
                                    h2Settings,
                                    h2Scope,
                                    config.http2.pingInterval ?: kotlin.time.Duration.INFINITE,
                                    closeTransport = {
                                        tls.close()
                                        tcp.close()
                                    },
                                    // the last GOAWAY is in tls.output: it goes out, then close_notify (RFC 9113 sections
                                    // 5.4.1 and 6.8, RFC 9846 section 6.1)
                                    // the read loop has stopped (the connection is closed): what the server still
                                    // sends is read and dropped, so its close_notify is not held behind it
                                    closeTransportGracefully = { closeOrderly(tls, rawOut, tcp, dropInput = true) },
                                    onChange = { h2.bump(key) },
                                    // RFC 9113 section 9.2.1: "An endpoint MUST treat a TLS renegotiation as a connection error
                                    // (Section 5.4.1) of type PROTOCOL_ERROR"; the TLS layer ends the input of an h2 connection
                                    // at the server's HelloRequest (TLS 1.2 only) and says so. Section 9.2.3: "HTTP/2 clients MUST
                                    // treat a TLS post-handshake CertificateRequest message as a connection error ... of type
                                    // PROTOCOL_ERROR"; OpenSSL refuses it (no post_handshake_auth offered) and the TLS layer says so
                                    connectionErrorOf = {
                                        if (tls.renegotiationAttempted || tls.postHandshakeMessageRefused) {
                                            io.kuicksilver.http2.Http2ErrorCode.PROTOCOL_ERROR
                                        } else {
                                            null
                                        }
                                    },
                                    // what the connect timeout left after TCP, the proxy and TLS (at least 1 ms)
                                    prefaceTimeout =
                                        (data.connectTimeoutMillis(config).milliseconds - connectStarted.elapsedNow())
                                            .coerceAtLeast(1.milliseconds)
                                            .also { prefaceTimeoutForTest?.invoke(it) },
                                    // RFC 7838 section 4: one on a request stream is for this connection's origin; one on
                                    // stream 0 only when its Origin is that origin. Never through a proxy. One on a request
                                    // stream of a connection that carries other origins too (coalescing) may be for one of
                                    // them, which the frame does not say: it is ignored (the field on the response is not)
                                    onAltSvc =
                                        if (proxy == null) {
                                            { origin, value ->
                                                @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
                                                if ((origin == null && made?.load()?.hosts?.anyAccepted() != true) ||
                                                    (
                                                        origin != null &&
                                                            io.kuicksilver.ktor.client
                                                                .isAltSvcFrameOrigin(origin, url)
                                                    )
                                                ) {
                                                    altSvcFrame(url, value)
                                                }
                                            }
                                        } else {
                                            null
                                        },
                                )
                            } catch (e: Throwable) {
                                tls.close()
                                throw e
                            }
                        h2Owned = true
                        try {
                            afterH2StartForTest?.invoke(client, tcp)
                            // a direct connection may carry other origins (coalescing): where it goes and what its server
                            // presented, kept from now on; through a proxy it never does
                            @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
                            val destination =
                                connected?.load()?.firstOrNull { it.first === raw }?.second?.let {
                                    io.kuicksilver.ktor.client.h3.Destination
                                        .of(it)
                                }
                            return H2Conn(
                                client,
                                key,
                                clock(),
                                peerIp,
                                tcp.localAddress as? io.ktor.network.sockets.InetSocketAddress,
                                tcp.remoteAddress as? io.ktor.network.sockets.InetSocketAddress,
                                viaProxy,
                                destination,
                                if (destination != null) tls.peerCertificates else emptyList(),
                                url.host,
                                if (destination != null) tls.stapleUntil else 0L,
                                tls.echStatus == io.kuicksilver.tls.EchStatus.Accepted,
                                tls.sessionReused,
                                destination != null,
                                connectTimeoutMillis = data.connectTimeoutMillis(config),
                                tlsVersion = tls.protocolVersion,
                            ).also {
                                @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
                                made?.store(it)
                            }
                        } catch (e: Throwable) {
                            // a fault of ours over a sound transport: GOAWAY (INTERNAL_ERROR), then close_notify, then the FIN
                            // (RFC 9113 sections 5.4.1 and 6.8, RFC 9846 section 6.1), bounded by the runtime, which closes the
                            // transport (the catch below leaves it alone); never hiding e
                            try {
                                client.abortInOrder(e)
                            } catch (s: Throwable) {
                                // only the GOAWAY's dispatch can throw, and the runtime has set up the transport's close
                                // (in order, hard within its bound) before it rethrows: a close here would cut that order
                                if (s !== e) e.addSuppressed(s)
                            }
                            throw e
                        }
                    }
                    // ALPN `http/1.1` (RFC 7301): the server agreed to speak HTTP/1.1 (RFC 9112 section 6.1 knowledge)
                    if (tls.negotiatedAlpn == "http/1.1") http11Routes.mark(key)
                    H1Connection(
                        tcp,
                        tls,
                        tls.input,
                        tls.output,
                        key,
                        clock(),
                        orderly = { closeOrderly(tls, rawOut, tcp, dropInput = true) },
                        tcpIn = rawIn,
                        tcpOut = rawOut,
                        viaProxy = viaProxy,
                    )
                } else if (h2Ok) {
                    // RFC 9113 section 3.3: h2c with prior knowledge, for an origin the application listed
                    // (http2 { priorKnowledge }): the preface and our SETTINGS go out at once, the request right after them
                    // (section 3.4); the server's preface must arrive within what the connect timeout left
                    val peerIp = WebSocketConnecting.peerIp(tcp.remoteAddress)

                    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                    val client =
                        H2ClientConnection.start(
                            rawIn,
                            rawOut,
                            h2Settings,
                            h2Scope,
                            config.http2.pingInterval ?: kotlin.time.Duration.INFINITE,
                            closeTransport = { tcp.close() },
                            // the last GOAWAY is in rawOut: it goes out, then the FIN (RFC 9113 sections 5.4.1 and 6.8)
                            closeTransportGracefully = { closeOrderly(null, rawOut, tcp) },
                            onChange = { h2.bump(key) },
                            prefaceTimeout =
                                (data.connectTimeoutMillis(config).milliseconds - connectStarted.elapsedNow())
                                    .coerceAtLeast(1.milliseconds),
                            // no ALTSVC frame is heard: nothing authenticates a cleartext server, and an http origin never
                            // learns an alternative (threat model 3.18), as its Alt-Svc fields are not
                            onAltSvc = null,
                        )
                    h2Owned = true
                    try {
                        afterH2StartForTest?.invoke(client, tcp)
                        H2Conn(
                            client,
                            key,
                            clock(),
                            peerIp,
                            tcp.localAddress as? io.ktor.network.sockets.InetSocketAddress,
                            tcp.remoteAddress as? io.ktor.network.sockets.InetSocketAddress,
                            viaProxy,
                            connectTimeoutMillis = data.connectTimeoutMillis(config),
                        )
                    } catch (e: Throwable) {
                        try {
                            client.abortInOrder(e)
                        } catch (s: Throwable) {
                            if (s !== e) e.addSuppressed(s)
                        }
                        throw e
                    }
                } else {
                    H1Connection(tcp, null, rawIn, rawOut, key, clock(), viaProxy = viaProxy)
                }
            } catch (e: Throwable) {
                if (!h2Owned) tcp.close()
                throw e
            }
        }
        throw kotlinx.io.IOException("no SOCKS5 destination for ${url.host}") // socks5Targets never returns an empty list
    }

    private fun callContextOrEmpty(): CoroutineContext = selector.coroutineContext

    /** A setup step of [data]'s TCP connection failed with [e] (a cancellation is none): the listener and the diagnostics hear it. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private fun connectFailed(
        data: HttpRequestData,
        stage: io.kuicksilver.ktor.client.ConnectStage,
        address: io.ktor.network.sockets.InetSocketAddress?,
        viaProxy: Boolean,
        e: Throwable,
    ) {
        if (e is CancellationException) return
        events.connectFailed(
            data,
            io.kuicksilver.ktor.client
                .ConnectFailure(io.kuicksilver.ktor.client.Transport.Tcp, stage, address, viaProxy, e),
        )
    }

    /**
     * The TLS handshake on [tcp] failed with [e]: reported with the socket's address ([connectFailed]), and the connection,
     * which never agreed on a protocol, becomes the call's ([io.kuicksilver.ktor.client.ProtocolDiagnostics.connection]).
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private fun tlsFailed(
        data: HttpRequestData,
        tcp: Socket,
        viaProxy: Boolean,
        e: Throwable,
    ) {
        if (e is CancellationException) return
        val remote = tcp.remoteAddress as? io.ktor.network.sockets.InetSocketAddress
        data.attributes.getOrNull(io.kuicksilver.ktor.client.KuicksilverDiagnosticsKey)?.connection =
            io.kuicksilver.ktor.client.TcpConnectionSnapshot(
                null,
                tcp.localAddress as? io.ktor.network.sockets.InetSocketAddress,
                remote,
                false,
                null,
                viaProxy,
                true,
                null,
            )
        connectFailed(data, io.kuicksilver.ktor.client.ConnectStage.TlsHandshake, remote, viaProxy, e)
    }

    /**
     * TLS with the `https://` [proxy] over [raw] ([KuicksilverEngineConfig.proxyTlsConfigFor]): the proxy's host as SNI and
     * reference identifier, ALPN `http/1.1`, resuming from [proxySessions]. A failed handshake (a certificate that does not verify, an alert, a connection
     * that ended) fails with [io.kuicksilver.ktor.client.ProxyTlsException] around the TLS layer's error; [raw] is closed
     * then (by `Socket.tls`). A cancellation (the connect timeout) passes as it is.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private suspend fun proxyTls(
        raw: Socket,
        proxy: ResolvedProxy,
    ): Socket {
        val tlsConfig =
            try {
                config.proxyTlsConfigFor(proxy.host)
            } catch (e: Throwable) {
                raw.close()
                throw e
            }
        return try {
            raw.tls(tlsConfig, callContextOrEmpty(), proxySessions)
        } catch (e: CancellationException) {
            throw e
        } catch (e: TlsException.Config) {
            throw e // the proxies { tls { } } block's own error, not the proxy's
        } catch (e: Throwable) {
            if (e !is TlsException && e !is kotlinx.io.IOException) throw e
            throw io.kuicksilver.ktor.client.ProxyTlsException(
                "TLS with the proxy $proxy failed: ${e.message ?: e::class.simpleName}",
                e,
            )
        }
    }

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
        // the families that answered, as the WebSocket keys have them (remoteHosts): a stalled family holds nothing back
        return dns
            .answered(name, 0)
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
        maxTotal = pool.maxConnections,
        maxPerRoute = pool.maxConnectionsPerRoute,
        maxIdlePerRoute = pool.maxIdleConnectionsPerRoute,
        idleTimeoutMillis = pool.idleTimeout.toMillisOrMax(),
        maxLifetimeMillis = pool.maxConnectionLifetime?.toMillisOrMax() ?: Long.MAX_VALUE,
    )

internal fun kotlin.time.Duration.toMillisOrMax(): Long = if (isInfinite()) Long.MAX_VALUE else inWholeMilliseconds

/** A body that streams (its end is not known up front): sent concurrently with reading the response. */
private fun OutgoingContent.isStreamed(): Boolean =
    when (this) {
        is OutgoingContent.ContentWrapper -> delegate().isStreamed()
        is OutgoingContent.ReadChannelContent, is OutgoingContent.WriteChannelContent -> true
        else -> false
    }

/**
 * RFC 8305 section 8, the Minimum Connection Attempt Delay: "Recommended to be 100 milliseconds. MUST NOT be less than 10
 * milliseconds." (section 5: "This minimum value is required to avoid congestion collapse in the presence of high
 * packet-loss rates."); the Maximum, [MAX_ATTEMPT_DELAY]: "Recommended to be 2 seconds."
 */
private val MIN_ATTEMPT_DELAY = 100.milliseconds

/** OkHttp has no floor; below 100 ms a PING timer would end connections on any ordinary delay. */
private val MIN_PING_INTERVAL = 100.milliseconds

/** The bound of an orderly close: the last bytes and close_notify out, and the peer's close_notify awaited, in all. */
internal val ORDERLY_CLOSE_TIMEOUT = 1.seconds

/** [H1Pool]'s answers from the pool: a permit to open a connection, or a change of the route's HTTP/2 connections. */
private val PERMIT = Any()
private val CHANGED = Any()
private val MAX_ATTEMPT_DELAY = 2.seconds

/**
 * The routes known to handle HTTP/1.1 requests (RFC 9112 section 6.1: "such knowledge might be in the form of specific
 * user configuration or by remembering the version of a prior received response"): an HTTP/1.1 response on the route, or
 * ALPN `http/1.1` on one of its TLS connections; and the routes whose probe was answered with another version (HTTP/1.0),
 * which are not probed again. Kept for the engine's lifetime, the most recent [MAX_ROUTES].
 */
internal class Http11Routes {
    private val lock = SpinLock()
    private val routes = LinkedHashMap<String, Boolean>()

    /** [route] handles HTTP/1.1. */
    fun mark(route: String) {
        lock.withLock { put(route, true) }
    }

    /** [route]'s probe was answered, not with HTTP/1.1; an answer with HTTP/1.1 later still counts. */
    fun markProbed(route: String) {
        lock.withLock { if (routes[route] != true) put(route, false) }
    }

    /** Under [lock]. */
    private fun put(
        route: String,
        http11: Boolean,
    ) {
        routes.remove(route)
        routes[route] = http11
        routes.evictEldest(MAX_ROUTES)
    }

    fun isKnown(route: String): Boolean = lock.withLock { routes[route] == true }

    fun wasProbed(route: String): Boolean = lock.withLock { route in routes }

    private companion object {
        const val MAX_ROUTES = 1000
    }
}

/** The server closed the connection after answering the first-contact probe ([H1Pool.probeVersion]). */
internal class ProbeEndedConnection : Exception("the server closed the connection after the OPTIONS probe")

/** How a client WebSocket's transport (HTTP/1.1, HTTP/3) ends once its session did ([webSocketTransportEnd]). */
internal enum class WebSocketTransportEnd {
    /** The session ended in order: the server closes first, this side follows within T2 (closeAfterWebSocket). */
    AfterServer,

    /** The stream is whole: what is queued goes out, then a FIN (over TLS close_notify first), bounded. */
    Orderly,

    /** A frame cut in the middle, a failed writer, or frames still queued when the close wait cut the session. */
    Reset,
}

/**
 * The end of a client WebSocket's transport (an HTTP/1.1 connection, an HTTP/3 stream) from what is left of its stream. Whole frames still queued in front of the
 * socket (the frame guard stopped between frames) go out in order unless the close wait cut the session
 * (`WebSocketLifetime.cutByCloseWait`: nothing it queued leaves after T1); a session cancelled by its call while idle is
 * closed in order whether or not the socket's writer has taken its last frames yet.
 *
 * Only the frame guard says the stream is whole, [writerDone] does not: Ktor's `WebSocketWriter` ends its channel with
 * `flushAndClose()` in a `finally`, also when it is cancelled inside a frame (the close wait cut it while a large frame
 * waited for a server that does not read), and that end reaches the connection as a writer that finished in order. A
 * FIN after it ended the cut frame as if the stream were whole: `ClientWebSocketCloseTest`'s server read
 * `[binary 16777216, cut]` in Docker, where its receive buffer grows to 32 MiB and the cancelled writer sometimes finished
 * its `finally` before this decision.
 */
internal fun webSocketTransportEnd(
    endedInOrder: Boolean,
    failed: Boolean,
    writerDone: Boolean,
    atFrameBoundary: Boolean,
    drained: Boolean,
    cutByCloseWait: Boolean,
): WebSocketTransportEnd =
    when {
        endedInOrder && writerDone && atFrameBoundary -> WebSocketTransportEnd.AfterServer
        !failed && atFrameBoundary && (drained || !cutByCloseWait) -> WebSocketTransportEnd.Orderly
        else -> WebSocketTransportEnd.Reset
    }

/**
 * What the TCP setup of one call is doing ([H1Pool.obtain]), so the connect timeout is reported where it struck
 * (`connectFailed`): the addresses being connected to, then the connected socket's address and the step on it (a proxy's
 * handshake, TLS). Written by the setup's coroutines, read once by the timeout.
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
internal class TcpProgress {
    private val connecting = kotlin.concurrent.atomics.AtomicReference(emptyList<io.ktor.network.sockets.InetSocketAddress>())

    @kotlin.concurrent.Volatile private var viaProxy = false

    @kotlin.concurrent.Volatile private var address: io.ktor.network.sockets.InetSocketAddress? = null

    /**
     * What the setup is doing: a wait before any address ([io.kuicksilver.ktor.client.ConnectStage.PoolWait],
     * `H2DialWait`, `NameLookup`), or the step on the connected socket (`ProxyHandshake`, `TlsHandshake`); null once set up.
     */
    @kotlin.concurrent.Volatile var stage: io.kuicksilver.ktor.client.ConnectStage? = null

    fun trying(
        a: io.ktor.network.sockets.InetSocketAddress,
        proxy: Boolean,
    ) {
        viaProxy = proxy
        while (true) {
            val now = connecting.load()
            if (connecting.compareAndSet(now, now + a)) return
        }
    }

    fun tried(a: io.ktor.network.sockets.InetSocketAddress) {
        while (true) {
            val now = connecting.load()
            if (connecting.compareAndSet(now, now - a)) return
        }
    }

    fun connected(
        a: io.ktor.network.sockets.InetSocketAddress?,
        step: io.kuicksilver.ktor.client.ConnectStage?,
    ) {
        address = a
        stage = step
    }

    /**
     * The connect timeout ended the setup with [timeout]: one per address still being connected to, else one for the step
     * on the connected socket (its address), else one for the name lookup before an address was tried; none once the
     * connection is set up (what the timeout then cut, an HTTP/2 preface or a health PING, is no step of the setup).
     */
    fun timedOut(timeout: Throwable): List<io.kuicksilver.ktor.client.ConnectFailure> {
        val step = stage
        val trying = connecting.load()
        val waiting =
            step == io.kuicksilver.ktor.client.ConnectStage.NameLookup || step == io.kuicksilver.ktor.client.ConnectStage.PoolWait ||
                step == io.kuicksilver.ktor.client.ConnectStage.H2DialWait
        val reports =
            when {
                trying.isNotEmpty() && (step == null || waiting) -> trying.map { io.kuicksilver.ktor.client.ConnectStage.TcpConnect to it }

                step != null -> listOf(step to if (waiting) null else address)

                // set up (a plain connection, or after TLS: an HTTP/2 preface, SETTINGS): no step of the setup failed
                else -> emptyList()
            }
        return reports.map { (st, a) ->
            io.kuicksilver.ktor.client
                .ConnectFailure(io.kuicksilver.ktor.client.Transport.Tcp, st, a, viaProxy, timeout)
        }
    }
}

/**
 * Whether the causes hold the peer's refusal of this client in the handshake: an alert it sent (but internal_error and
 * user_canceled, which say nothing about this client), or this side's failed verification of it (but an unknown
 * revocation status, which may be gone on the next attempt). A transport loss (TlsException.Protocol) is not one.
 */
internal fun Throwable.isHandshakeRefusal(): Boolean =
    generateSequence(this) { it.cause }.any {
        (it is io.kuicksilver.tls.TlsException.AlertReceived && it.code != 80 && it.code != 90) ||
            (it is io.kuicksilver.tls.TlsException.Verify && it.reason != io.kuicksilver.tls.VerifyReason.UnknownRevocationStatus)
    }
