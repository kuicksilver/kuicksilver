// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client.h1

import io.ktor.client.engine.ProxyType
import io.ktor.client.engine.resolveAddress
import io.ktor.client.engine.type
import io.ktor.client.plugins.ConnectTimeoutException
import io.ktor.client.plugins.SocketTimeoutException
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.Url
import io.ktor.http.content.OutgoingContent
import io.ktor.http.isSecure
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.util.date.GMTDate
import io.ktor.util.network.address
import io.ktor.util.network.port
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.ClosedReadChannelException
import io.kuicksilver.ktor.client.EngineEvents
import io.kuicksilver.ktor.client.KuicksilverEngineConfig
import io.kuicksilver.ktor.client.connectTimeoutMillis
import io.kuicksilver.ktor.client.isIdempotent
import io.kuicksilver.ktor.client.platformCleartextPermitted
import io.kuicksilver.ktor.client.socketHost
import io.kuicksilver.ktor.client.socketTimeoutMillis
import io.kuicksilver.ktor.client.tlsConfigFor
import io.kuicksilver.ktor.network.connectTcp
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
import kotlin.coroutines.CoroutineContext

/** One HTTP/1.1 connection: TCP, optionally a CONNECT tunnel, optionally TLS; its pool slot comes back when it closes. */
internal class H1Connection(
    private val socket: Socket,
    private val tls: TlsConnection?,
    val input: ByteReadChannel,
    val output: ByteWriteChannel,
    val key: String,
    createdAt: Long = 0,
) : PooledConnection(key, createdAt) {
    override val isOpen: Boolean get() = !closed && !input.isClosedForRead

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
    /** The platform's cleartext policy (Android Network Security Configuration); replaced by tests. */
    internal var cleartextPermitted: (String) -> Boolean = { host -> platformCleartextPermitted(host) }

    /** Limits, keep-alive and idle expiry; internal for tests. */
    internal val pool = ConnectionPool<H1Connection>(config.poolLimits(), clock)

    /** This engine's TLS session tickets (resumption secrets stay native); cleared by [closeAll], so closing the engine drops them. */
    internal val sessions = SessionCache()

    /** Returns a connection that finished its exchange, or one that lost the protocol race unused. */
    fun recycle(c: H1Connection) = pool.release(c)

    /** Closes idle connections past their idle timeout or lifetime; the milliseconds until the next expiry, null when none is idle. */
    fun evictExpired(): Long? = pool.evictExpired()

    suspend fun closeAll() {
        pool.shutdown()
        sessions.clear()
    }

    private fun keyOf(data: HttpRequestData): String =
        data.url.let {
            "${it.protocol.name}://${it.host}:${it.port}|${config.proxy?.resolveAddress()}"
        }

    /**
     * A connection for [data]: an idle pooled one, else a new one (the HTTP/1.1 side of the h3/h1 race). [Opened.reused]
     * travels with it to [execute], so a pooled connection the server closed still earns the stale-connection retry.
     */
    suspend fun open(data: HttpRequestData): Opened = obtain(data, keyOf(data)).let { Opened(it.first, it.second) }

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
                        conn = connect(data, data.url, data.url.protocol.isSecure(), config.proxy != null, key).also { pool.adopt(it) }
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

    /** One exchange; [preopened] is a connection the race already obtained ([open]). */
    suspend fun execute(
        data: HttpRequestData,
        callContext: CoroutineContext,
        preopened: Opened? = null,
    ): HttpResponseData {
        val url = data.url
        val secure = url.protocol.isSecure()
        if (!secure) {
            val host = url.host.removePrefix("[").removeSuffix("]") // an IPv6 literal as the policy knows it
            if (!cleartextPermitted(host)) {
                throw io.kuicksilver.ktor.client
                    .cleartextNotPermitted(host)
            }
        }
        val proxy =
            config.proxy?.also {
                if (it.type !=
                    ProxyType.HTTP
                ) {
                    throw UnsupportedOperationException("the Kuicksilver engine supports HTTP proxies only, not ${it.type}")
                }
            }
        val key = keyOf(data)
        var first = true
        var given = preopened
        while (true) {
            // a connection the race just opened is fresh and never earns the stale retry; an idle one it took from the pool does
            val (conn, reused) = given?.let { it.connection to it.reused } ?: obtain(data, key)
            given = null
            events.emit("connectionAcquired") { connectionAcquired(data, HttpProtocolVersion.HTTP_1_1, reused) }
            var bodyJob: BodySender? = null
            try {
                val requestTime = GMTDate()
                writeHeaders(data, conn.output, overProxy = proxy != null && !secure, tunneled = proxy != null && secure)
                // a streamed body is sent while the response is read (as the CIO engine): the server may answer first
                if (data.body.isStreamed()) {
                    bodyJob =
                        sendBodyConcurrently(
                            data,
                            conn,
                            callContext,
                        )
                } else {
                    writeBody(data, conn.output, callContext)
                }
                val job = bodyJob
                return withSocketTimeout(data) {
                    readResponse(requestTime, data, conn.input, conn.output, callContext) { after ->
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
                            job.job.invokeOnCompletion { c -> settle(if (c == null) AfterResponse.Reuse else AfterResponse.Close) }
                        }
                    }
                }
            } catch (e: CancellationException) {
                conn.close()
                throw e
            } catch (e: Throwable) {
                conn.close()
                bodyJob?.failure?.let { throw it }
                // a pooled connection the server already closed: one transparent retry on a fresh connection, for an
                // idempotent request with a replayable body only (a non-idempotent one may have been processed, RFC 9112 section 9.3.1)
                if (reused && first && bodyJob == null && data.method.isIdempotent() &&
                    (e is ClosedReadChannelException || e is kotlinx.io.IOException) && e !is TlsException
                ) {
                    first = false
                    events.emit("retry") { retry(data, 2, e) }
                    continue
                }
                throw e
            }
        }
    }

    /** Writes the body in its own coroutine; a failure closes the connection (so the response read fails too) and is reported. */
    @OptIn(DelicateCoroutinesApi::class)
    private fun sendBodyConcurrently(
        data: HttpRequestData,
        conn: H1Connection,
        callContext: CoroutineContext,
    ): BodySender {
        val sender = BodySender()
        sender.job =
            GlobalScope.launch(callContext.minusKey(Job) + CoroutineName("kuicksilver-h1-request-body")) {
                try {
                    writeBody(data, conn.output, callContext)
                } catch (
                    e: Throwable,
                ) {
                    if (e !is CancellationException) sender.failure = e
                    throw e
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

    /** TCP, the proxy tunnel and TLS; runs under [obtain]'s connect timeout. */
    private suspend fun connect(
        data: HttpRequestData,
        url: Url,
        secure: Boolean,
        viaProxy: Boolean,
        key: String,
    ): H1Connection {
        val target =
            if (viaProxy) {
                // a NetworkAddress (java.net's on the JVM, ktor-utils' on Native), not ktor-network's InetSocketAddress
                config.proxy!!.resolveAddress().let { InetSocketAddress(socketHost(it.address), it.port) }
            } else {
                InetSocketAddress(
                    socketHost(url.host),
                    url.port,
                )
            }
        // the address itself, not `hostname`: on the JVM that is a reverse lookup (::1 -> "localhost" -> 127.0.0.1);
        // connectTcp, not ktor-network's native connect, which sends every IPv6 address as :: (docs/upstream/ktor-native-ipv6.md)
        val tcp = connectTcp(selector, target)
        try {
            val rawIn = tcp.openReadChannel()
            val rawOut = tcp.openWriteChannel(autoFlush = true)
            if (viaProxy &&
                secure
            ) {
                startTunnel(
                    url,
                    data.headers[HttpHeaders.UserAgent],
                    data.headers[HttpHeaders.ProxyAuthorization],
                    rawOut,
                    rawIn,
                )
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

    private fun callContextOrEmpty(): CoroutineContext = selector.coroutineContext
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
