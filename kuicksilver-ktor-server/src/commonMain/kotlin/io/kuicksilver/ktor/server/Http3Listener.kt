// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.http.HttpProtocolVersion
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.engine.handleFailure
import io.ktor.util.pipeline.execute
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.ktor.server.h3.H3Call
import io.kuicksilver.ktor.server.h3.WebSocketOverH3
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.activePath
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.Certificate
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** One HTTP/3 port: its accept loop, the supervisor of its connection handlers and the connections themselves (for GOAWAY at stop). */
internal class H3Listener(
    val endpoint: Http3Endpoint,
    val acceptJob: Job,
    val connections: CompletableJob,
) {
    private val lock = Mutex()
    private val set = HashSet<Http3Connection>()

    /**
     * The engine is stopping: accepting goes on (handshakes in flight when the stop began still complete, and the QUIC
     * endpoint's graceful shutdown waits for them), but every connection accepted from now on gets GOAWAY at once.
     */
    @kotlin.concurrent.Volatile
    var stopping = false

    suspend fun add(c: Http3Connection) = lock.withLock { set += c }

    suspend fun remove(c: Http3Connection) = lock.withLock { set -= c }

    suspend fun live(): List<Http3Connection> = lock.withLock { set.toList() }

    suspend fun size(): Int = lock.withLock { set.size }
}

/**
 * How a TLS connector binds its HTTP/3 endpoint on a given port, or null when it serves no HTTP/3: turned off, or a
 * connector with a `sniSelector` (QUIC cannot pick an identity per SNI name in v1; logged as a warning). [bindTcpAndUdp]
 * calls it with the port of the TCP socket it just bound, or, on its UDP-first attempts with `port = 0`, with 0 (the OS
 * picks the UDP port and TCP follows).
 */
internal fun KuicksilverApplicationEngine.http3Binder(tls: KuicksilverTlsConnector): (suspend (Int) -> Http3Endpoint)? {
    if (!configuration.http3) return null
    // RFC 9114 section 6.2: refused when the engine starts, not clamped (Http3Endpoint.bind refuses it too)
    configuration.http3Quic().maxUniStreams.let { n ->
        require(n >= 3) {
            "HTTP/3 needs quic.maxUniStreams >= 3 (RFC 9114 section 6.2: the client opens its control and QPACK streams), not $n"
        }
    }
    if (tls.sniSelector != null) {
        environment.log.warn("HTTP/3 is not served on ${tls.host}:${tls.port}: sniSelector is not supported by QUIC in v1")
        return null
    }
    return { port -> configuration.http3Bind(InetSocketAddress(tls.host, port), http3EndpointConfig(tls), http3Settings()) }
}

@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
private fun KuicksilverApplicationEngine.http3Settings(): Http3Settings {
    val s = configuration.http3Settings
    val connect = (configuration.webSocketsOverHttp3 || configuration.webTransport) && !s.enableConnectProtocol
    val wt = configuration.webTransport && !s.webTransport
    if (!connect && !wt) return s
    return s
        .toBuilder()
        .apply {
            if (connect) enableConnectProtocol = true
            if (wt) webTransport = true
        }.build()
}

@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
private fun KuicksilverApplicationEngine.http3EndpointConfig(tls: KuicksilverTlsConnector): QuicEndpointConfig {
    val quic = configuration.http3Quic()
    return QuicEndpointConfig
        .Builder()
        .apply {
            server =
                QuicServerConfig
                    .Builder(tls.tlsConfig(listOf(Http3Endpoint.H3)))
                    .apply {
                        this.quic = quic
                        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                        earlyData = configuration.quicEarlyData
                    }.build()
            connectionIdLength = quic.connectionIdLength
            loops = configuration.udpSocketCount
            configuration.quicAdmission?.let { admission = it }
            configuration.logger?.let { logger = it }
            listener = configuration.connectionListener
        }.build()
}

/** Serves HTTP/3 on [endpoint], already bound on [port] next to the TCP socket of [tls]. */
internal suspend fun KuicksilverApplicationEngine.startHttp3(
    scope: CoroutineScope,
    tls: KuicksilverTlsConnector,
    endpoint: Http3Endpoint,
    port: Int,
): H3Listener {
    with(scope) {
        h3Endpoints += endpoint
        h3Ports += port
        val local = InetSocketAddress(tls.host, port)
        // the handlers outlive the accept loop: at the grace deadline a stop closes the endpoint, which ends accepting
        val connections = SupervisorJob(coroutineContext[Job])
        lateinit var listener: H3Listener
        val acceptJob =
            launch(CoroutineName("http3-$port")) {
                while (true) {
                    val conn =
                        try {
                            endpoint.accept()
                        } catch (
                            e: CancellationException,
                        ) {
                            throw e
                        } catch (e: Throwable) {
                            environment.log.debug("HTTP/3 accept on port $port ended: $e")
                            break
                        }
                    afterH3AcceptForTest?.invoke()
                    listener.add(conn)
                    // after add(): a stop that began meanwhile either saw this connection in live() or is seen here (RFC 9114 5.2)
                    if (listener.stopping) launch { runCatching { conn.goAway() } }
                    // the peer's address now (a NAT rebinding right after the handshake moves it to another path)
                    val remote = (conn.quic.activePath ?: conn.quic.paths.firstOrNull())?.remoteAddress
                    events.emit("connectionOpened") { connectionOpened(HttpProtocolVersion.HTTP_3_0, remote) }
                    // the last resort: a failure that still reaches this coroutine is logged, not left uncaught (Native aborts on those)
                    launch(
                        connections +
                            CoroutineExceptionHandler { _, e -> environment.log.debug("HTTP/3 connection on port $port failed: $e") },
                    ) {
                        val peer = conn.quic.peerCertificates
                        try {
                            while (true) {
                                val req =
                                    try {
                                        conn.acceptRequest()
                                    } catch (
                                        e: CancellationException,
                                    ) {
                                        throw e
                                    } catch (e: Throwable) {
                                        break
                                    }
                                launch {
                                    // a request's failure (e.g. a WebSocket reader seeing the peer's reset) ends that request only
                                    try {
                                        handleHttp3(req, local, peer)
                                    } catch (e: CancellationException) {
                                        throw e
                                    } catch (e: Throwable) {
                                        environment.log.debug("HTTP/3 request on port $port failed: $e")
                                    }
                                }
                            }
                        } finally {
                            listener.remove(conn)
                            conn.close()
                            events.emit("connectionClosed") { connectionClosed(HttpProtocolVersion.HTTP_3_0, remote) }
                        }
                    }
                }
            }
        listener = H3Listener(endpoint, acceptJob, connections)
        h3ListenersForProbe += listener
        return listener
    }
}

private suspend fun KuicksilverApplicationEngine.handleHttp3(
    req: Http3ServerRequest,
    local: InetSocketAddress,
    peer: List<Certificate>,
) {
    // Extended CONNECT (RFC 9220): WebSockets and WebTransport go through Ktor's pipeline; other protocols are not served here
    val webSocket = req.method == "CONNECT" && req.protocol == WebSocketOverH3.PROTOCOL

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    val webTransport = configuration.webTransport && req.isWebTransport
    if (req.method == "CONNECT" && !webSocket && !webTransport) {
        runCatching { req.respond(501).finish() }
        return
    }
    // forwarded from early data by a gateway (RFC 8470 section 5.1): what the early-data policy does not declare replayable
    // cannot be made safe by waiting for this hop's handshake, so it gets 425 Too Early and never reaches the application
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    if (req.headers[EARLY_DATA_FIELD.lowercase()] != null && !configuration.http3Settings.earlyData.replayable(req)) {
        runCatching { req.respond(425).finish() }
        return
    }
    withContext(userDispatcher) requestContext@{
        val call =
            H3Call(
                applicationProvider(),
                req,
                local,
                peer,
                this@requestContext.coroutineContext,
                engineDispatcher,
                userDispatcher,
                webSocket,
                webTransport,
            )
        events.emit("requestStarted") { requestStarted(HttpProtocolVersion.HTTP_3_0, call) }
        var failure: Throwable? = null
        try {
            pipeline.execute(call)
        } catch (error: Throwable) {
            failure = error
            handleFailure(call, error)
        } finally {
            events.emit("requestEnded") { requestEnded(HttpProtocolVersion.HTTP_3_0, call, failure) }
        }
    }
}

/**
 * The QUIC settings of the HTTP/3 listeners: [quic][KuicksilverApplicationEngine.Configuration.quic] with `quicMaxIdleTimeout`
 * and `qlog`, and `resetStreamAt` with [webTransport][KuicksilverApplicationEngine.Configuration.webTransport] (its streams keep
 * their header when reset, draft-ietf-webtrans-http3-16 section 4.4).
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
internal fun KuicksilverApplicationEngine.Configuration.http3Quic(): QuicConfig {
    val base =
        quicMaxIdleTimeout?.takeUnless { quicAssigned }?.let { idle -> quicConfig { maxIdleTimeout = idle } } ?: quic
    val withQlog = qlog?.let { sink -> base.toBuilder().apply { qlog = sink }.build() } ?: base
    return if (webTransport && !withQlog.resetStreamAt) withQlog.toBuilder().apply { resetStreamAt = true }.build() else withQlog
}
