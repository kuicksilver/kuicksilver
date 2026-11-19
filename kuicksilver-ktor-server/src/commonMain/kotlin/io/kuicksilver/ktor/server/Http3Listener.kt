// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.http.HttpProtocolVersion
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.engine.handleFailure
import io.ktor.util.pipeline.execute
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.http3.awaitAbandoned
import io.kuicksilver.http3.handlerEnded
import io.kuicksilver.http3.holdStreamUntilHandled
import io.kuicksilver.http3.resetIfUnanswered
import io.kuicksilver.ktor.server.h1.httpDateNow
import io.kuicksilver.ktor.server.h3.H3Call
import io.kuicksilver.ktor.server.h3.WebSocketOverH3
import io.kuicksilver.quic.AdmissionDecision
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.activePath
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.sniSelectedFor
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
import kotlin.time.Duration.Companion.seconds

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
 * How a TLS connector binds its HTTP/3 endpoint on a given port, or null when it serves no HTTP/3 (turned off). [bindTcpAndUdp]
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
    return { port -> configuration.http3Bind(InetSocketAddress(tls.host, port), http3EndpointConfig(tls), http3Settings()) }
}

@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
private fun KuicksilverApplicationEngine.http3Settings(): Http3Settings {
    val s = h3SettingsWithin(configuration.http3Settings, configuration.requestHeaderTimeoutSeconds.seconds)
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

/**
 * [settings] with its field-section deadline bounded by the engine's request-head deadline [headerTimeout]: a request
 * head over HTTP/3 has no more time than one over HTTP/1.1 or HTTP/2 ([h2SettingsWithin]).
 */
internal fun h3SettingsWithin(
    settings: Http3Settings,
    headerTimeout: kotlin.time.Duration,
): Http3Settings =
    if (settings.maxHeaderBlockTime <=
        headerTimeout
    ) {
        settings
    } else {
        settings.toBuilder().apply { maxHeaderBlockTime = headerTimeout }.build()
    }

@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
private fun KuicksilverApplicationEngine.http3EndpointConfig(tls: KuicksilverTlsConnector): QuicEndpointConfig {
    val quic = configuration.http3Quic()
    return QuicEndpointConfig
        .Builder()
        .apply {
            server =
                QuicServerConfig
                    .Builder(tls.tlsConfig(listOf(Http3Endpoint.H3), null, quic = true))
                    .apply {
                        this.quic = quic
                        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                        earlyData = configuration.quicEarlyData
                    }.build()
            connectionIdLength = quic.connectionIdLength
            loops = configuration.udpSocketCount
            maxConnections = configuration.quicMaxConnections
            maxConnectionsPerIp = configuration.quicMaxConnectionsPerIp
            acceptQueue = configuration.quicAcceptQueue
            // the HTTP/3 switch first: under Drain every new client is refused with CONNECTION_REFUSED, statelessly, whatever the
            // policy (RFC 9000 section 5.2.2: a server that refuses a new connection SHOULD send an Initial CONNECTION_CLOSE with
            // CONNECTION_REFUSED; sections 10.2.3 and 20.1)
            val policy = configuration.quicAdmission ?: admission
            admission =
                ConnectionAdmission { attempt ->
                    if (advertising == Http3Advertising.Drain) REFUSED else policy.admit(attempt)
                }
            configuration.logger?.let { logger = it }
            listener = configuration.connectionListener
            loadBalancer = configuration.quicLoadBalancer
        }.build()
}

/** The admission answer to every new client while [Http3Advertising.Drain] is set. */
private val REFUSED = AdmissionDecision.Close(TransportError.CONNECTION_REFUSED)

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
        val noDf = endpoint.dontFragmentUnavailable
        if (noDf != null) {
            h3NoDfFamily[port] = noDf
            environment.log.warn("HTTP/3 on port $port is not served for ${noDf.label}: its UDP socket cannot set Don't Fragment for it")
        }
        h3StatusList =
            h3StatusList +
            Http3Status(
                port,
                served = true,
                notServedFamily = noDf,
                reason =
                    noDf?.let {
                        io.kuicksilver.quic.QuicException
                            .DontFragmentUnavailable(it, "the UDP socket cannot set Don't Fragment for it")
                    },
            )
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
                    h3ConnectionForTest?.invoke(conn)
                    listener.add(conn)
                    // after add(): a stop or a switch to Drain that began meanwhile either saw this connection in live() or is seen
                    // here (RFC 9114 5.2)
                    if (listener.stopping) {
                        launch { runCatching { stopGoAway(conn) } }
                    } else if (advertising == Http3Advertising.Drain) {
                        launch { runCatching { conn.goAway() } }
                    }
                    // the peer's address now (a NAT rebinding right after the handshake moves it to another path)
                    val remote = (conn.quic.activePath ?: conn.quic.paths.firstOrNull())?.remoteAddress
                    events.emit("connectionOpened") { connectionOpened(HttpProtocolVersion.HTTP_3_0, remote) }
                    // the last resort: a failure that still reaches this coroutine is logged, not left uncaught (Native aborts on those)
                    val served =
                        launch(
                            connections +
                                CoroutineExceptionHandler { _, e -> environment.log.debug("HTTP/3 connection on port $port failed: $e") },
                        ) {
                            val peer = conn.quic.peerCertificates

                            // the identity and policy an sniSelector chose hold for its name only (RFC 9110 section 7.4), as on TCP
                            @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
                            val authorityCheck =
                                AuthorityCheck(
                                    conn.quic.localCertificates,
                                    tls.trustedGateway,
                                    if (tls.sniSelector != null) SniChoice(conn.quic.sniSelectedFor) else null,
                                )
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
                                    // the request's stream counts toward the client's stream limit until its handler returned,
                                    // also when the client reset it meanwhile (Rapid Reset, CVE-2023-44487; RFC 9114 section 10.5)
                                    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
                                    req.holdStreamUntilHandled()
                                    launch {
                                        val handler =
                                            launch {
                                                // a request's failure (e.g. a WebSocket reader seeing the peer's reset) ends that request only
                                                try {
                                                    beforeH3HandlerForTest?.invoke()
                                                    handleHttp3(req, local, peer, authorityCheck)
                                                } catch (e: CancellationException) {
                                                    throw e
                                                } catch (e: Throwable) {
                                                    environment.log.debug("HTTP/3 request on port $port failed: $e")
                                                }
                                            }
                                        // a client that abandons the request (STOP_SENDING, or a reset) cancels its handler, which gives
                                        // the stream back at once; a handler that ignores the cancellation keeps holding it, so the
                                        // client still never has more handlers than streams (as Go's CVE-2023-44487 fix)
                                        val watch =
                                            launch {
                                                @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
                                                req.awaitAbandoned()
                                                handler.cancel(CancellationException("the client abandoned the request"))
                                            }
                                        try {
                                            handler.join()
                                        } finally {
                                            watch.cancel()
                                            // a request whose handler never got to answer or reset it (cancelled by the watch
                                            // before its work began) still ends: STOP_SENDING and a reset, H3_REQUEST_CANCELLED
                                            // (RFC 9114 section 4.1.1); left open, it kept its receive half and held the GOAWAY
                                            // idle close for the connection's life
                                            @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
                                            req.resetIfUnanswered(Http3ErrorCode.REQUEST_CANCELLED)
                                            @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
                                            req.handlerEnded()
                                        }
                                    }
                                }
                            } finally {
                                afterH3RequestsAcceptedForTest?.invoke()
                                listener.remove(conn)
                                conn.close()
                            }
                        }
                    // the engine is done with the connection once the requests it accepted (this job's children) ended too:
                    // a client that closes as soon as it has its answer must not see connectionClosed before requestEnded
                    served.invokeOnCompletion {
                        events.emit("connectionClosed") { connectionClosed(HttpProtocolVersion.HTTP_3_0, remote) }
                    }
                }
            }
        listener = H3Listener(endpoint, acceptJob, connections)
        h3ListenersForProbe += listener
        return listener
    }
}

/**
 * The engine's `Alt-Svc` on HTTP/3 responses: nothing under [Http3Advertising.On] (the client already uses the alternative),
 * `clear` otherwise (RFC 7838 sections 2.2 and 3), so a client on HTTP/3 also drops the alternative; none with `altSvc = false`.
 */
private val KuicksilverApplicationEngine.h3AltSvc: () -> String?
    get() =
        if (!configuration.altSvc) {
            { null }
        } else {
            { if (advertising == Http3Advertising.On) null else "clear" }
        }

private suspend fun KuicksilverApplicationEngine.handleHttp3(
    req: Http3ServerRequest,
    local: InetSocketAddress,
    peer: List<Certificate>,
    authorityCheck: AuthorityCheck,
) {
    // Extended CONNECT (RFC 9220): WebSockets (when webSocketsOverHttp3 is on, also with Extended CONNECT advertised for
    // WebTransport) and WebTransport go through Ktor's pipeline; other protocols are not served here and get 501 (section 3).
    // Upgrade tokens match in any case (RFC 9110 section 7.8)
    val webSocket =
        configuration.webSocketsOverHttp3 && req.method == "CONNECT" && req.protocol.equals(WebSocketOverH3.PROTOCOL, ignoreCase = true)

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    val webTransport = configuration.webTransport && req.isWebTransport
    if (req.method == "CONNECT" && !webSocket && !webTransport) {
        runCatching { req.respond(501).finish() }
        return
    }
    // RFC 9110 section 7.4 (RFC 9114 section 3.3): a request for a host this connection's certificate does not name gets 421
    // and never reaches the application; the stream ends, the connection serves the client's other requests
    authorityCheck.rejection(req.scheme, req.authority)?.let { why ->
        environment.log.debug(why)
        runCatching { req.respond(MISDIRECTED_REQUEST, io.kuicksilver.http3.Http3Headers(listOf("date" to httpDateNow()))).finish() }
        return
    }
    // forwarded from early data by a gateway (RFC 8470 section 5.1): what the early-data policy does not declare replayable
    // cannot be made safe by waiting for this hop's handshake, so it gets 425 Too Early and never reaches the application
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    if (req.headers[EARLY_DATA_FIELD.lowercase()] != null && !configuration.http3Settings.earlyData.replayable(req)) {
        // RFC 9110 section 6.6.1: Date on every 2xx to 4xx
        runCatching { req.respond(425, io.kuicksilver.http3.Http3Headers(listOf("date" to httpDateNow()))).finish() }
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
                beforeH3UpgradeForTest,
                h3AltSvc,
                configuration.webSocketMaxMessageSize,
            )
        events.emit("requestStarted") { requestStarted(HttpProtocolVersion.HTTP_3_0, call) }
        // RFC 9110 section 10.1.1: `Expect: 100-continue` with content to follow gets an immediate 100 (Continue) as the call
        // starts, as on HTTP/1.1 and HTTP/2 (the head-determined final statuses, 425 and 501, went out above). Before, it
        // was never sent over HTTP/3, and the client held its content back until its own wait ended
        if (req.headers["expect"]?.lowercase() == "100-continue" && req.headers["content-length"] != "0" && !req.body.isClosedForRead) {
            runCatching { req.sendInformational(100) } // a stream that failed meanwhile fails the read that follows
        }
        var failure: Throwable? = null
        try {
            pipeline.execute(call)
        } catch (error: Throwable) {
            failure = error
            handleFailure(call, error)
        } finally {
            // a call that failed after Ktor committed its response (an upgrade that failed before its answer went out)
            // cannot get the 500 any more: the response is abandoned after partial processing, so the stream is reset with
            // H3_REQUEST_CANCELLED (RFC 9114 section 4.1.1), never left waiting for an answer
            if (!call.response.answered) runCatching { req.reset(Http3ErrorCode.REQUEST_CANCELLED) }
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
