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
import io.ktor.http.Url
import io.ktor.http.content.OutgoingContent
import io.ktor.http.isSecure
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.util.date.GMTDate
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.ClosedReadChannelException
import io.kuicksilver.ktor.client.KuicksilverEngineConfig
import io.kuicksilver.ktor.client.connectTimeoutMillis
import io.kuicksilver.ktor.client.isIdempotent
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
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlin.coroutines.CoroutineContext

/** One HTTP/1.1 connection: TCP, optionally a CONNECT tunnel, optionally TLS. */
internal class H1Connection(
    private val socket: Socket,
    private val tls: TlsConnection?,
    val input: ByteReadChannel,
    val output: ByteWriteChannel,
    val key: String,
) {
    var closed = false
        private set

    fun close() {
        if (closed) return
        closed = true
        tls?.close()
        socket.close()
    }
}

/**
 * HTTP/1.1 over TCP with TLS 1.3 (ADR-0009: no HTTP/2), with keep-alive: a connection whose response body ended
 * by its framing goes back to an idle list of at most `maxConnectionsPerHost` per origin; a stale idle connection is
 * replaced once, transparently, for idempotent requests only (RFC 9110 section 9.2.2, RFC 9112 section 9.3.1): a
 * request the server may have processed is never sent twice.
 */
internal class H1Pool(
    private val config: KuicksilverEngineConfig,
    private val selector: SelectorManager,
) {
    private val idle = HashMap<String, ArrayDeque<H1Connection>>()
    private val lock = Mutex()

    /** This engine's TLS session tickets (resumption secrets stay native); cleared by [closeAll], so closing the engine drops them. */
    internal val sessions = SessionCache()

    /** An idle connection the server has not closed yet (one it closed while idle is dropped here, not handed out). */
    private suspend fun take(key: String): H1Connection? =
        lock.withLock {
            val q = idle[key]
            var found: H1Connection? = null
            while (q != null && found == null) {
                val c = q.removeFirstOrNull() ?: break
                if (!c.input.isClosedForRead && !c.closed) found = c else c.close()
            }
            found
        }

    private fun give(c: H1Connection) {
        if (c.closed) return
        // released from a body reader's completion handler: no suspension there, so tryLock and close if contended
        if (!lock.tryLock()) {
            c.close()
            return
        }
        try {
            val q = idle.getOrPut(c.key) { ArrayDeque() }
            if (q.size <
                config.maxConnectionsPerHost
            ) {
                q.addLast(c)
            } else {
                c.close()
            }
        } finally {
            lock.unlock()
        }
    }

    /** Idle connections and the keys holding them (the resource probe). */
    internal suspend fun idleForProbe(): Pair<Int, Int> = lock.withLock { idle.values.sumOf { it.size } to idle.size }

    suspend fun closeAll() {
        lock.withLock {
            idle.values.forEach { q -> q.forEach { it.close() } }
            idle.clear()
        }
        sessions.clear()
    }

    private fun keyOf(data: HttpRequestData): String =
        data.url.let {
            "${it.protocol.name}://${it.host}:${it.port}|${config.proxy?.resolveAddress()}"
        }

    /** A connection for [data]: an idle pooled one, else a new one (the HTTP/1.1 side of the h3/h1 race). */
    suspend fun open(data: HttpRequestData): H1Connection {
        val key = keyOf(data)
        return take(key) ?: connect(data, data.url, data.url.protocol.isSecure(), config.proxy != null, key)
    }

    /** One exchange; [preopened] is a connection the race already set up. */
    suspend fun execute(
        data: HttpRequestData,
        callContext: CoroutineContext,
        preopened: H1Connection? = null,
    ): HttpResponseData {
        val url = data.url
        val secure = url.protocol.isSecure()
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
            // a connection the race just opened is fresh: it is not a pooled one and never earns the stale retry
            val reused = if (given == null) take(key) else null
            val conn = given ?: reused ?: connect(data, url, secure, proxy != null, key)
            given = null
            var bodyJob: BodySender? = null
            try {
                val requestTime = GMTDate()
                writeHeaders(data, conn.output, overProxy = proxy != null && !secure)
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
                        fun settle(a: AfterResponse) {
                            when (a) {
                                AfterResponse.Reuse -> give(conn)
                                AfterResponse.Close -> conn.close()
                                AfterResponse.HandOver -> callContext[Job]?.invokeOnCompletion { conn.close() }
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
                if (reused != null && first && bodyJob == null && data.method.isIdempotent() &&
                    (e is ClosedReadChannelException || e is kotlinx.io.IOException) && e !is TlsException
                ) {
                    first = false
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

    private suspend fun connect(
        data: HttpRequestData,
        url: Url,
        secure: Boolean,
        viaProxy: Boolean,
        key: String,
    ): H1Connection {
        val timeout = data.connectTimeoutMillis(config)
        return try {
            withTimeout(timeout) {
                val target =
                    if (viaProxy) {
                        config.proxy!!.resolveAddress().let { it as InetSocketAddress }
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
                    if (secure) {
                        val tls =
                            TlsConnection.client(
                                rawIn,
                                rawOut,
                                config.tlsConfigFor(url.host, listOf("http/1.1")),
                                callContextOrEmpty(),
                                sessions,
                            )
                        H1Connection(tcp, tls, tls.input, tls.output, key)
                    } else {
                        H1Connection(tcp, null, rawIn, rawOut, key)
                    }
                } catch (e: Throwable) {
                    tcp.close()
                    throw e
                }
            }
        } catch (e: TimeoutCancellationException) {
            throw ConnectTimeoutException(data, e)
        }
    }

    private fun callContextOrEmpty(): CoroutineContext = selector.coroutineContext
}

/** A body that streams (its end is not known up front): sent concurrently with reading the response. */
private fun OutgoingContent.isStreamed(): Boolean =
    when (this) {
        is OutgoingContent.ContentWrapper -> delegate().isStreamed()
        is OutgoingContent.ReadChannelContent, is OutgoingContent.WriteChannelContent -> true
        else -> false
    }
