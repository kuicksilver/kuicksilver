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
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.util.date.GMTDate
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.ClosedReadChannelException
import io.kuicksilver.ktor.client.KuicksilverEngineConfig
import io.kuicksilver.ktor.client.connectTimeoutMillis
import io.kuicksilver.ktor.client.socketTimeoutMillis
import io.kuicksilver.ktor.client.tlsConfigFor
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
 * replaced once, transparently.
 */
internal class H1Pool(
    private val config: KuicksilverEngineConfig,
    private val selector: SelectorManager,
) {
    private val idle = HashMap<String, ArrayDeque<H1Connection>>()
    private val lock = Mutex()

    /** This engine's TLS session tickets (resumption secrets stay native); cleared by [closeAll], so closing the engine drops them. */
    internal val sessions = SessionCache()

    private suspend fun take(key: String): H1Connection? = lock.withLock { idle[key]?.removeFirstOrNull() }

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
            val reused = given ?: take(key)
            given = null
            val conn = reused ?: connect(data, url, secure, proxy != null, key)
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
                // a pooled connection the server already closed: one transparent retry on a fresh connection (not for a streamed body)
                if (reused != null && first && bodyJob == null && (e is ClosedReadChannelException || e is kotlinx.io.IOException) &&
                    e !is TlsException
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
                            url.host,
                            url.port,
                        )
                    }
                val tcp = aSocket(selector).tcp().connect(target.hostname, target.port)
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
