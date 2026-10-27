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
import io.kuicksilver.ktor.client.Activity
import io.kuicksilver.ktor.client.ActivityInput
import io.kuicksilver.ktor.client.ActivityOutput
import io.kuicksilver.ktor.client.EngineEvents
import io.kuicksilver.ktor.client.H3ExchangeKey
import io.kuicksilver.ktor.client.KuicksilverEngineConfig
import io.kuicksilver.ktor.client.RequestDns
import io.kuicksilver.ktor.client.ResolvedProxy
import io.kuicksilver.ktor.client.connectTimeoutMillis
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
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.launch
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
     * response, so such a connection is not reused (as Go's net/http).
     */
    override val isOpen: Boolean get() = !closed && !input.isClosedForRead && !input.hasUnread

    override fun closeTransport() {
        tls?.close()
        socket.close()
    }
}

/**
 * HTTP/1.1 over TCP with TLS 1.3 (ADR-0009: no HTTP/2), with keep-alive and connection limits ([ConnectionPool]): at most
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
    init {
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

    /** Closes idle connections past their idle timeout or lifetime; the milliseconds until the next expiry, null when none is idle. */
    fun evictExpired(): Long? = pool.evictExpired()

    suspend fun closeAll() {
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
    ): Opened = obtain(data, keyOf(data, null), dns, null).let { Opened(it.first, it.second) }

    /** A connection [open] handed out and whether it came from the idle pool. */
    class Opened(
        val connection: H1Connection,
        val reused: Boolean,
    )

    /**
     * An idle connection for [key] (second: true), else a new one once the limits allow; waiting for room and connecting
     * share the connect timeout, as in the CIO engine ([ConnectTimeoutException]).
     */
    private suspend fun obtain(
        data: HttpRequestData,
        key: String,
        dns: RequestDns,
        proxy: ResolvedProxy?,
    ): Pair<H1Connection, Boolean> {
        var conn: H1Connection? = null
        var reused = false
        try {
            withTimeout(data.connectTimeoutMillis(config)) {
                val idle = pool.acquire(key)
                if (idle != null) {
                    conn = idle
                    reused = true
                } else {
                    try {
                        conn =
                            connect(data, data.url, data.url.protocol.isSecure(), proxy, key, dns)
                                .also { pool.adopt(it) }
                    } catch (e: Throwable) {
                        pool.releasePermit(key)
                        throw e
                    }
                }
            }
        } catch (e: CancellationException) {
            // a timeout that fired as the block returned: the connection is not handed out, so its slot comes back here
            conn?.let { if (reused) pool.release(it) else it.close() }
            if (e is TimeoutCancellationException) throw ConnectTimeoutException(data, e)
            throw e
        }
        return conn!! to reused
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
        while (true) {
            // a connection the race just opened is fresh and never earns the stale retry; an idle one it took from the pool does
            val (conn, reused) = given?.let { it.connection to it.reused } ?: obtain(data, key, dns, proxy)
            given = null
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
                val response =
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
                        readResponse(requestTime, data, input, conn.output, callContext, conn.input, continueBody) { after ->
                            val job = bodyJob

                            fun released(kept: Boolean) =
                                events.emit("connectionReleased") { connectionReleased(data, HttpProtocolVersion.HTTP_1_1, kept) }

                            fun settle(a: AfterResponse) {
                                when (a) {
                                    AfterResponse.Reuse -> {
                                        released(pool.release(conn))
                                    }

                                    AfterResponse.Close -> {
                                        conn.close()
                                        released(false)
                                    }

                                    AfterResponse.HandOver -> {
                                        callContext[Job]?.invokeOnCompletion {
                                            conn.close()
                                            released(false)
                                        }
                                    }
                                }
                            }
                            if (job == null || after != AfterResponse.Reuse) {
                                settle(after)
                            } else {
                                // reusable once the body is out
                                job.job.invokeOnCompletion { c ->
                                    settle(if (c == null && job.failure == null) AfterResponse.Reuse else AfterResponse.Close)
                                }
                            }
                        }
                    }
                // a 417 to a request that waited for 100 Continue only says that something on the way does not support
                // expectations: the request is repeated once without one (RFC 9110 section 10.1.1, as CIO); its body was
                // never sent, so it can be. The 417's connection was closed: it promised a body it never got
                if (response.statusCode == HttpStatusCode.ExpectationFailed && !bodySent && expectsContinue(data)) {
                    data.attributes.put(ExpectationFailedKey, Unit)
                    events.emit("retry") { retry(data, 2, IllegalStateException("417 Expectation Failed to Expect: 100-continue")) }
                    continue
                }
                return response
            } catch (e: CancellationException) {
                conn.close()
                events.emit("connectionReleased") { connectionReleased(data, HttpProtocolVersion.HTTP_1_1, kept = false) }
                throw e
            } catch (e: Throwable) {
                conn.close()
                // every connectionAcquired gets its connectionReleased, also when the exchange failed before a response
                events.emit("connectionReleased") { connectionReleased(data, HttpProtocolVersion.HTTP_1_1, kept = false) }
                bodyJob?.failure?.let { throw it }
                // a pooled connection the server already closed: one transparent retry on a fresh connection, for an
                // idempotent request with a replayable body only (a non-idempotent one may have been processed, RFC 9112 section 9.3.1);
                // a socket timeout is an IOException too, but a slow server, not a closed connection: it is not repeated.
                // `e !is TlsException` is intentionally not reached for a TLS failure read through the connection's channel
                // (it arrives wrapped): a TLS failure on a reused connection is the stale-connection case this retry is for
                if (reused && first && bodyJob == null && data.method.isIdempotent() &&
                    (e is ClosedReadChannelException || e is kotlinx.io.IOException) && e !is TlsException &&
                    e !is SocketTimeoutException
                ) {
                    first = false
                    events.emit("retry") { retry(data, 2, e) }
                    continue
                }
                throw e
            }
        }
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
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    sender.failure = e
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
        sender.job.invokeOnCompletion { c -> if (c != null) conn.close() }
        callContext[Job]?.invokeOnCompletion { sender.job.cancel() } // not a child: the call does not wait for it, it ends with the call
        return sender
    }

    private class BodySender {
        lateinit var job: Job

        @kotlin.concurrent.Volatile var failure: Throwable? = null
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
    ): H1Connection {
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
                    val tls =
                        TlsConnection.client(
                            rawIn,
                            rawOut,
                            config.tlsConfigFor(url.host, listOf("http/1.1")),
                            callContextOrEmpty(),
                            sessions,
                        )
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
private val MAX_ATTEMPT_DELAY = 2.seconds
