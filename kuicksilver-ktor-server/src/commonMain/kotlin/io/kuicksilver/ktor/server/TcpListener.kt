// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.http.HttpHeaders
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.HttpStatusCode
import io.ktor.http.cio.Request
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.SocketAddress
import io.ktor.network.sockets.isClosed
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.engine.handleFailure
import io.ktor.server.request.ApplicationReceivePipeline
import io.ktor.server.response.respond
import io.ktor.util.network.NetworkAddress
import io.ktor.util.pipeline.PipelinePhase
import io.ktor.util.pipeline.execute
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.ktor.network.abort
import io.kuicksilver.ktor.network.bindTcp
import io.kuicksilver.ktor.network.bytesSent
import io.kuicksilver.ktor.network.engineSelector
import io.kuicksilver.ktor.network.openDeliveringReadChannel
import io.kuicksilver.ktor.network.setCloseTimeout
import io.kuicksilver.ktor.network.tlsServer
import io.kuicksilver.ktor.server.h1.H1Call
import io.kuicksilver.ktor.server.h1.H1Connection
import io.kuicksilver.ktor.server.h1.H1RequestScope
import io.kuicksilver.ktor.server.h1.httpDateNow
import io.kuicksilver.ktor.server.h1.requestEndsConnection
import io.kuicksilver.ktor.server.h1.sendStallTimeout
import io.kuicksilver.ktor.server.h1.splitAbsoluteForm
import io.kuicksilver.ktor.server.h1.startH1Pipeline
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeMark
import kotlin.time.TimeSource

internal class TcpServer(
    val rootJob: Job,
    val acceptJob: Job,
    val socket: CompletableDeferred<ServerSocket>,
    /** The HTTP/3 endpoint bound on the same port as [socket], completed before it; null without HTTP/3. */
    val h3Endpoint: CompletableDeferred<Http3Endpoint?>,
    /** Completed when the server stops: its HTTP/1.1 connections read no further request ([startH1Pipeline]). */
    val draining: CompletableJob,
    /** The parent of its HTTP/1.1 connections, listed for the probe ([KuicksilverApplicationEngine.tcpConnectionsForProbe]). */
    val connections: Job,
    /** Its `maxTcpConnections` and `maxTcpConnectionsPerIp`, listed for the probe ([KuicksilverApplicationEngine.tcpLimitsForProbe]). */
    val limits: TcpLimits,
)

/** `port = 0`: TCP + UDP pairs tried before HTTP/3 is given up for the connector. */
internal const val EPHEMERAL_PAIR_ATTEMPTS = 16

/**
 * Binds the TCP socket of [l] and, with [h3], its HTTP/3 endpoint on the same port number. With `port = 0` the pair is
 * retried up to [EPHEMERAL_PAIR_ATTEMPTS] times when a side fails to bind ([mayBeTaken]; a refused configuration fails the
 * start at once), then HTTP/3 is skipped with a warning and HTTP/1.1 is served alone. The
 * attempts alternate which side the OS picks: first the TCP port, whose UDP twin may be taken, then a free UDP port, whose
 * TCP twin may be taken, and so on. Retrying only the TCP side is not enough where the OS hands out TCP ports one after
 * the other (Windows does): every retry then lands on the next number, and a run of taken UDP ports (handed out one after
 * the other too) refuses them all. A fixed port whose UDP side cannot be bound fails the start, as before. A platform
 * without a QUIC server (UnsupportedOperationException) skips HTTP/3 at once.
 */
private suspend fun KuicksilverApplicationEngine.bindTcpAndUdp(
    selector: SelectorManager,
    l: KuicksilverApplicationEngine.Listener,
    h3: (suspend (Int) -> Http3Endpoint)?,
): Pair<ServerSocket, Http3Endpoint?> {
    val ephemeral = l.config.port == 0
    if (h3 == null) return bindTcp(selector, l.config.host, l.config.port) to null
    var last: Throwable? = null
    repeat(if (ephemeral) EPHEMERAL_PAIR_ATTEMPTS else 1) { attempt ->
        if (ephemeral && attempt % 2 == 1) {
            // the UDP side first: the OS picks a UDP port that is free, then TCP takes the same number
            val endpoint =
                try {
                    h3(0)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: UnsupportedOperationException) {
                    environment.log.warn("HTTP/3 is not served: ${e.message}")
                    return bindTcp(selector, l.config.host, l.config.port) to null
                } catch (e: Throwable) {
                    if (!mayBeTaken(e)) throw e
                    environment.log.debug("no free UDP port ($e); trying another TCP + UDP pair")
                    last = e
                    return@repeat
                }
            val port = endpoint.localAddress.port
            try {
                return bindTcp(selector, l.config.host, port) to endpoint
            } catch (e: CancellationException) {
                releaseFailedPair(endpoint)
                throw e
            } catch (e: Throwable) {
                // released before the next attempt and before the start returns: its UDP port is free again then
                releaseFailedPair(endpoint)
                if (!mayBeTaken(e)) throw e
                environment.log.debug("TCP port $port is taken ($e); trying another TCP + UDP pair")
                last = e
                return@repeat
            }
        }
        val server = bindTcp(selector, l.config.host, l.config.port)
        val port = (server.localAddress as? InetSocketAddress)?.port ?: l.config.port
        try {
            return server to h3(port)
        } catch (e: CancellationException) {
            server.close()
            throw e
        } catch (e: UnsupportedOperationException) {
            environment.log.warn("HTTP/3 is not served on port $port: ${e.message}")
            return server to null
        } catch (e: Throwable) {
            if (!ephemeral || !mayBeTaken(e)) {
                server.close()
                throw e
            }
            environment.log.debug("UDP port $port is taken ($e); trying another TCP + UDP pair")
            server.close()
            last = e
        }
    }
    environment.log.warn(
        "HTTP/3 is not served: no TCP + UDP pair free on one port number after $EPHEMERAL_PAIR_ATTEMPTS attempts ($last)",
    )
    return bindTcp(selector, l.config.host, l.config.port) to null
}

/**
 * Closes the HTTP/3 endpoint of a pair that failed and waits until its UDP socket is released, also when cancelled, for at
 * most [RELEASE_WAIT]: a release that hangs must not hold the start; it is logged and the start goes on.
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
private suspend fun KuicksilverApplicationEngine.releaseFailedPair(endpoint: Http3Endpoint) =
    withContext(NonCancellable) {
        withTimeoutOrNull(RELEASE_WAIT) { endpoint.closeAndJoin() }
            ?: environment.log.warn("the HTTP/3 endpoint on UDP ${endpoint.localAddress.port} was not released within $RELEASE_WAIT")
    }

/** How long [releaseFailedPair] waits for a failed pair's endpoint. */
private val RELEASE_WAIT: Duration = 5.seconds

/**
 * Whether [e], from binding one side of an ephemeral TCP + UDP pair, may come from a port that is in use, so that another
 * pair may succeed: anything but a refused configuration (an argument or state the endpoint rejects, a TLS identity it
 * cannot use, a failure of the native layer: loading, ABI, OpenSSL internals), which fails every attempt alike and so
 * fails the start at once, as with a fixed port (review 2026-10-28 last3 R2). The address-in-use failure itself has no common type (`java.net.BindException` on the JVM, ktor's
 * `PosixException` on Kotlin/Native, an `IOException` from ksl), so the refusals are what is named.
 */
private fun mayBeTaken(e: Throwable): Boolean =
    e !is IllegalArgumentException && e !is IllegalStateException && e !is TlsException && e !is io.kuicksilver.native.KslException

/** The accept loop of one TCP connector, after Ktor CIO's `httpServer`, with a TLS handshake per connection. */
@OptIn(InternalAPI::class)
internal fun KuicksilverApplicationEngine.startTcp(
    scope: CoroutineScope,
    l: KuicksilverApplicationEngine.Listener,
    h3Ready: Job,
): TcpServer {
    val h3 = l.tls?.let { http3Binder(it) }
    val h3Endpoint = CompletableDeferred<Http3Endpoint?>()
    with(scope) {
        val socket = CompletableDeferred<ServerSocket>()
        val latch: CompletableJob = Job()
        val rootJob = launch(CoroutineName("kuicksilver-server-${l.config}"), start = CoroutineStart.UNDISPATCHED) { latch.join() }
        val selector = engineSelector(coroutineContext) // a socket closed on it is released at once (EngineSelector.kt)
        val timeout = configuration.connectionIdleTimeoutSeconds.seconds

        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        val headerTimeout = configuration.requestHeaderTimeoutSeconds.seconds
        val sendTimeout = configuration.sendStallTimeoutForTest ?: sendStallTimeout(timeout)
        val connections = SupervisorJob(rootJob)
        // completed when accepting ends (the engine stops): connections read no further request, idle ones close at once
        val draining: CompletableJob = Job()
        tcpConnectionsForProbe += connections

        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        val limits = TcpLimits(configuration.maxTcpConnections, configuration.maxTcpConnectionsPerIp)
        tcpLimitsForProbe += limits
        val tlsConfig = l.tls?.let { tcpTlsConfig(it) }
        l.tls?.let { warnTls12H2WithoutRsa(it, configuration.http2, environment.log) }
        // RFC 9113 section 3.2: `h2` only over TLS, and only where it was offered (no h2c on a plain connector)
        val h2Offered = tlsConfig != null && H2_ALPN in tlsConfig.alpn
        val scheme = if (l.tls != null) "https" else "http"
        val acceptJob =
            launch(rootJob + CoroutineName("accept-${l.config}")) {
                val (server, endpoint) =
                    try {
                        bindTcpAndUdp(selector, l, h3)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Throwable) {
                        // a start that cannot bind fails the start ([socket]), not this coroutine: a failure thrown out of it
                        // reached no handler, which aborts the process on Kotlin/Native
                        socket.completeExceptionally(e)
                        h3Endpoint.completeExceptionally(e)
                        return@launch
                    }
                h3Endpoint.complete(endpoint)
                server.use {
                    socket.complete(server)
                    h3Ready.join()
                    val port = (server.localAddress as? InetSocketAddress)?.port ?: l.config.port
                    // the last resort, as for HTTP/3 connections: a failure that still reaches a connection's coroutine
                    // is logged, not left to the thread's uncaught exception handler (a crash on Android, an abort on Native)
                    val connectionScope =
                        CoroutineScope(
                            coroutineContext + connections + CoroutineName("connection") +
                                CoroutineExceptionHandler {
                                    _,
                                    e,
                                    ->
                                    environment.log.debug("TCP connection (HTTP/1.1 or HTTP/2) on port $port failed: $e")
                                },
                        )
                    val acceptFailures = AcceptFailureReporter(ACCEPT_FAILURE_LOG_INTERVAL) { environment.log.warn("${l.config}: $it") }
                    val refusals = RefusalReporter(ACCEPT_FAILURE_LOG_INTERVAL) { environment.log.warn("${l.config}: $it") }
                    val perIpRefusals = RefusalReporter(ACCEPT_FAILURE_LOG_INTERVAL) { environment.log.warn("${l.config}: $it") }
                    try {
                        // the checks cheapest first: a slot of maxTcpConnections before accept (none free: the backlog holds
                        // the client), maxTcpConnectionsPerIp right after it (no lock, no suspension), then the HTTP/2
                        // repeat offenders (a lock while the table is not empty), and only then the TLS handshake
                        acceptLoop(
                            accept = { server.accept() },
                            isClosed = { server.isClosed },
                            onError = acceptFailures::report,
                            limits = limits,
                            ipKeyOf = { peerIpKey(it.remoteAddress as? InetSocketAddress) },
                            refuse = { client ->
                                // the address before the abort: on the JVM and Android it is read from the channel, which
                                // throws once closed (the listener then got a null address for a known client)
                                val from = runCatching { client.remoteAddress as? InetSocketAddress }.getOrNull()
                                client.abort()
                                perIpRefusals.report(
                                    from?.let { peerAddressBytes(it) }?.let { describeIp(it) } ?: "an unknown address",
                                    "it holds ${limits.maxPerIp} connections already (maxTcpConnectionsPerIp)",
                                )
                                events.emit("connectionRefused") { connectionRefused(HttpProtocolVersion.HTTP_1_1, from, REFUSED_PER_IP) }
                                refusedPerIp.update { it + 1 } // after the event: a test that sees the count sees the event
                            },
                        ) { client, lease ->
                            // the slot and the address count until the descriptor is released, however the connection ends
                            // (HTTP/1.1 or HTTP/2, a refusal below, a failed handshake, a stop); aborted sockets release it at once
                            openTcpSockets.update { it + 1 }
                            client.socketContext.invokeOnCompletion {
                                lease.release()
                                openTcpSockets.update { it - 1 }
                            }
                            // with http2RepeatOffenderPenalty, a client whose HTTP/2 connections keep earning ENHANCE_YOUR_CALM
                            // waits out its penalty: closed here, before the TLS handshake costs anything (threat model 3.23)
                            val from = runCatching { client.remoteAddress as? InetSocketAddress }.getOrNull()
                            val refused =
                                try {
                                    h2Offenders?.refuses(from) == true
                                } catch (e: CancellationException) {
                                    client.abort() // the loop stops while the table's lock is awaited: the accepted socket goes too
                                    throw e
                                }
                            if (refused) {
                                client.abort()
                                refusals.report(RepeatOffenders.describe(from), "its HTTP/2 connections kept ending in ENHANCE_YOUR_CALM")
                                events.emit("connectionRefused") {
                                    connectionRefused(HttpProtocolVersion.HTTP_1_1, from, REFUSED_REPEAT_OFFENDER)
                                }
                                refusedOffenders.update { it + 1 } // after the event: a test that sees the count sees the event
                                return@acceptLoop
                            }
                            // the request-head deadline of the first request counts from here, the TLS handshake included
                            val accepted = TimeSource.Monotonic.markNow()
                            client.setCloseTimeout(null) // the engine bounds the close (closeWithin), on progress
                            // a stop between accept() and here leaves the scope cancelled: the coroutine still starts and
                            // aborts the socket, which releases its slot (a plain launch never ran, nor its finally)
                            connectionScope.launchOrElse(onCancelled = { client.abort() }) {
                                val sock: Socket
                                val peer: List<Certificate>
                                val own: List<Certificate>
                                var sni: SniChoice? = null
                                val remote = client.remoteAddress as? InetSocketAddress
                                if (tlsConfig != null) {
                                    val t =
                                        try {
                                            // a handshake that completes as the deadline fires (or a stop comes) is
                                            // dropped by the timeout: its TLS session is aborted, not leaked
                                            withTimeoutOrRelease(headerTimeout, { it.abort() }) { client.tlsServer(tlsConfig) }
                                                ?: throw IOException("No TLS handshake within the request header timeout ($headerTimeout)")
                                        } catch (e: Throwable) {
                                            // never a close without a bound (the socket has none of its own): it would keep
                                            // the connection's maxTcpConnections slot while the client takes nothing. A FIN
                                            // (and an alert, if one is pending) for as long as the close moves, then an abort;
                                            // a stop aborts at once
                                            if (e is CancellationException) {
                                                client.abort()
                                            } else {
                                                closeWithin(client, { client.abort() }, sendTimeout)
                                            }
                                            if (e !is CancellationException) {
                                                events.emit(
                                                    "tlsHandshakeFailed",
                                                ) { tlsHandshakeFailed(remote, e) }
                                            }
                                            return@launchOrElse
                                        } // a failed handshake ends only this connection
                                    t.setCloseTimeout(null)
                                    sock = t
                                    peer = t.peerCertificates
                                    own = t.localCertificates
                                    if (l.tls.sniSelector != null) sni = SniChoice(t.sniSelectedFor)
                                } else {
                                    sock = client
                                    peer = emptyList()
                                    own = emptyList()
                                }
                                // RFC 9110 section 7.4: an https request for a host this connection's certificate does not name, or over a plain
                                // connection, gets 421
                                val authorityCheck = AuthorityCheck(own, l.trustedGateway, sni)
                                val altSvc = if (l.tls != null && configuration.altSvc) http3AltSvc(port) else NO_ALT_SVC
                                if (h2Offered && (sock as? io.kuicksilver.ktor.network.TlsSocket)?.negotiatedAlpn == H2_ALPN) {
                                    return@launchOrElse serveH2(
                                        sock,
                                        remote,
                                        peer,
                                        authorityCheck,
                                        altSvc,
                                        (headerTimeout - accepted.elapsedNow()).coerceAtLeast(Duration.ZERO),
                                        timeout,
                                        headerTimeout,
                                        sendTimeout,
                                        draining,
                                    )
                                }
                                events.emit("connectionOpened") { connectionOpened(HttpProtocolVersion.HTTP_1_1, remote) }
                                var connection: H1Connection? = null
                                try {
                                    // inside the try: a socket whose channels cannot be opened is still closed below
                                    connection =
                                        H1Connection(
                                            sock.openDeliveringReadChannel(),
                                            sock.openWriteChannel(),
                                            sock.remoteAddress.toNetworkAddress(),
                                            sock.localAddress.toNetworkAddress(),
                                        )
                                    startH1Pipeline(
                                        connection,
                                        timeout,
                                        headerTimeout,
                                        (headerTimeout - accepted.elapsedNow()).coerceAtLeast(Duration.ZERO),
                                        draining = draining,
                                        sendTimeout = sendTimeout,
                                    ) { request -> handleRequest(this, request, scheme, peer, authorityCheck, altSvc) }.join()
                                } finally {
                                    // a client cut for not reading has had the stall deadline already: no second one for the close
                                    val stall = if (connection?.clientStoppedReading == true) Duration.ZERO else sendTimeout
                                    closeWithin(sock, { sock.abort() }, stall)
                                    events.emit("connectionClosed") { connectionClosed(HttpProtocolVersion.HTTP_1_1, remote) }
                                }
                            }
                        }
                    } catch (e: IOException) {
                        coroutineContext.cancel()
                    } finally {
                        server.close()
                        draining.complete()
                        connections.complete()
                        connections.join()
                    }
                }
            }
        acceptJob.invokeOnCompletion { cause ->
            cause?.let { socket.completeExceptionally(it) }
            latch.complete()
        }
        rootJob.invokeOnCompletion { selector.close() }
        return TcpServer(rootJob, acceptJob, socket, h3Endpoint, draining, connections, limits)
    }
}

/** The ALPN protocol ID of HTTP/2 over TLS (RFC 9113 section 3.2). */
internal const val H2_ALPN = "h2"

/**
 * The TLS configuration of a TCP connector: ALPN `h2` before `http/1.1` when [KuicksilverApplicationEngine.Configuration.http2]
 * is set (the server picks by its own order, so a client that offers both gets HTTP/2, RFC 7301 section 3.2), else
 * `http/1.1` alone. A connector with `versions = TlsVersions.Tls12And13` offers `h2` over TLS 1.2 too: RFC 9113 section 9.2,
 * "Implementations of HTTP/2 MUST use TLS version 1.2 [TLS12] or higher", and the TLS 1.2 profile meets sections 9.2.1 and
 * 9.2.2 (compression and renegotiation off, a renegotiation attempt a connection error of type PROTOCOL_ERROR in [serveH2];
 * only ECDHE suites with an AEAD, none of them on the Appendix A list; groups of 255 bits and more, no finite-field DHE; and
 * TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 with P-256 for an RSA certificate). The handshake has no deadline of its own (`TlsConfig`'s
 * 10 s): it is part of the first request's head, which [KuicksilverApplicationEngine.Configuration.requestHeaderTimeoutSeconds]
 * bounds from the accepted connection on. With the 10 s of its own a client on a slow, lossy path (200 ms, 5 % loss)
 * whose Finished needed retransmissions was cut at 10 s after it had sent its request, well inside the documented 30 s.
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
internal fun KuicksilverApplicationEngine.tcpTlsConfig(tls: KuicksilverTlsConnector): io.kuicksilver.tls.TlsConfig =
    tls.tlsConfig(if (configuration.http2) listOf(H2_ALPN, "http/1.1") else listOf("http/1.1"), Duration.INFINITE, quic = false)

/**
 * HTTP/3 is announced only where it is served (turned on together with the UDP listener), and as `http3Advertising` says at
 * the moment each response head goes out: `h3` under [Http3Advertising.On], `clear` (RFC 7838 section 3) otherwise.
 */
private fun KuicksilverApplicationEngine.http3AltSvc(port: Int): () -> String? {
    if (port !in h3Ports) return NO_ALT_SVC
    val h3 = "h3=\":$port\"; ma=86400"
    return { if (advertising == Http3Advertising.On) h3 else ALT_SVC_CLEAR }
}

/** No `Alt-Svc` from the engine: plain HTTP, `altSvc = false`, or a port without HTTP/3. */
private val NO_ALT_SVC: () -> String? = { null }

/** RFC 7838 section 3: every alternative cached for the origin is invalidated. */
private const val ALT_SVC_CLEAR = "clear"

private suspend fun KuicksilverApplicationEngine.handleRequest(
    scope: H1RequestScope,
    request: Request,
    scheme: String,
    peer: List<Certificate>,
    authorityCheck: AuthorityCheck,
    altSvc: () -> String?,
) {
    with(scope) {
        // final statuses the head alone determines, answered by the engine as over HTTP/2 and HTTP/3: no call is made, so
        // neither the application's routing nor its send pipeline (StatusPages, logging, compression) runs, and no 100 goes
        // out before them (RFC 9110 section 10.1.1)
        // RFC 9110 section 7.4: the target URI's authority is the absolute-form's, else Host (RFC 9112 section 3.3), and its
        // scheme the absolute-form's, else the connection's; CONNECT's authority-form names a tunnel's destination, not an
        // origin
        val absolute = splitAbsoluteForm(request.uri.toString())
        val targetScheme = if (absolute != null) request.uri.toString().substringBefore(':') else scheme
        val misdirected =
            if (request.method.value == "CONNECT") {
                null
            } else {
                authorityCheck.rejection(targetScheme, absolute?.first ?: request.headers[HttpHeaders.Host]?.toString())
            }
        if (misdirected != null) {
            environment.log.debug(misdirected)
            return respondFromEngine(scope, request, MisdirectedRequestStatus)
        }
        // forwarded from early data by a gateway and not replayable: 425, it cannot be made safe by waiting (RFC 8470 section 5.1)
        if (request.headers[EARLY_DATA_FIELD] != null &&
            request.method.value !in io.kuicksilver.http3.Http3EarlyDataPolicy.SAFE_METHODS
        ) {
            return respondFromEngine(scope, request, HttpStatusCode.TooEarly)
        }
        withContext(userDispatcher) requestContext@{
            val call =
                H1Call(
                    applicationProvider(),
                    request,
                    input,
                    output,
                    engineDispatcher,
                    userDispatcher,
                    upgraded,
                    remoteAddress,
                    localAddress,
                    this@requestContext.coroutineContext,
                    scheme,
                    peer,
                    altSvc,
                    closing,
                    endsConnection,
                    fields,
                    configuration.webSocketMaxMessageSize,
                )
            events.emit("requestStarted") { requestStarted(HttpProtocolVersion.HTTP_1_1, call) }
            var failure: Throwable? = null
            try {
                addHandlerForExpectedHeader(call)
                run {
                    // RFC 9110 section 10.1.1: an HTTP/1.1 request with content and `Expect: 100-continue` gets "an immediate
                    // 100 (Continue) response" unless its head alone determines a final status (those went out before the
                    // application was asked: 400, 413, 431, 421, 425 above). Before, it went out only when the application first
                    // read the content, so a handler that waited before it decided held the client's content back
                    if (continueSent != null) {
                        output.writeStringUtf8("HTTP/1.1 100 Continue\r\n\r\n")
                        output.flush()
                        continueSent.complete() // the body deadline starts now: the client sends the content after this
                    }
                    pipeline.execute(call)
                }
            } catch (error: Throwable) {
                failure = error
                handleFailure(call, error)
            } finally {
                events.emit("requestEnded") { requestEnded(HttpProtocolVersion.HTTP_1_1, call, failure) }
                call.release()
            }
        }
    }
}

/**
 * Answers [request] with [status] and no content from the engine itself, the way the HTTP/2 and HTTP/3 paths answer it:
 * `Date` (RFC 9110 section 6.6.1), `Content-Length: 0`, and `Connection: close` when the connection ends after it (the
 * server stopping, or the request's own close, RFC 9112 section 9.6), which [H1RequestScope.endsConnection] reports to the
 * pipeline. Content the request carries is drained by the pipeline as for any response that left it unread.
 */
private suspend fun respondFromEngine(
    scope: H1RequestScope,
    request: Request,
    status: HttpStatusCode,
) {
    try {
        val close =
            scope.closing() ||
                requestEndsConnection(HttpProtocolVersion.parse(request.version), scope.fields.getAll(HttpHeaders.Connection).orEmpty())
        val head =
            "HTTP/1.1 ${status.value} ${status.description}\r\nDate: ${httpDateNow()}\r\nContent-Length: 0\r\n" +
                (if (close) "Connection: close\r\n" else "") + "\r\n"
        scope.output.writeStringUtf8(head)
        scope.output.flush()
        scope.endsConnection?.complete(close)
    } finally {
        scope.output.flushAndClose()
        request.release()
    }
}

// From Ktor CIO: an expectation other than 100-continue is answered 417 when the application reads the content (RFC 9110
// section 10.1.1, a MAY); `100 Continue` itself goes out at dispatch (handleRequest)
private fun addHandlerForExpectedHeader(call: H1Call) {
    val expectedHeaderPhase = PipelinePhase("ExpectedHeaderPhase")
    call.request.pipeline.insertPhaseBefore(ApplicationReceivePipeline.Before, expectedHeaderPhase)
    call.request.pipeline.intercept(expectedHeaderPhase) {
        val request = call.request
        val version = HttpProtocolVersion.parse(request.local.version)
        val expectHeader = request.headers[HttpHeaders.Expect]?.lowercase()
        val contentLength = request.headers[HttpHeaders.ContentLength]?.toLongOrNull()
        val hasBody = request.headers[HttpHeaders.TransferEncoding] != null || (contentLength != null && contentLength > 0)
        if (expectHeader == null || version == HttpProtocolVersion.HTTP_1_0 || !hasBody) return@intercept
        if (expectHeader != "100-continue") call.respond(message = HttpStatusCode.ExpectationFailed)
    }
}

private fun SocketAddress.toNetworkAddress(): NetworkAddress? = (this as? InetSocketAddress)?.let { NetworkAddress(it.hostname, it.port) }

/** The pause after the first of consecutive failed accepts; it doubles per failure up to [ACCEPT_BACKOFF_MAX]. */
internal val ACCEPT_BACKOFF_MIN: Duration = 5.milliseconds

/** The longest pause between failed accepts. */
internal val ACCEPT_BACKOFF_MAX: Duration = 1.seconds

/**
 * Accepts connections and hands each to [serve] until cancelled. A failed [accept] (EMFILE or ENFILE with the
 * descriptor table full, ENOBUFS, ENOMEM) is reported to [onError] with the pause that follows it: 5 ms, doubling per
 * consecutive failure up to 1 s, and back to 5 ms after the next successful accept, as Go's `net/http` `Server.Serve`
 * does for temporary accept errors. Retrying at once spins at full CPU for as long as the condition lasts. A failure
 * while [isClosed] (the listening socket was closed) is rethrown at once; cancellation ends the loop during a pause too.
 *
 * [limits] bound what is accepted, cheapest check first: a slot of `maxTcpConnections` is taken before [accept] (none free:
 * the loop waits and the OS backlog holds new clients), then right after it the client's address ([ipKeyOf]) is counted
 * against `maxTcpConnectionsPerIp`; a client over it goes to [refuse], which closes it, and is never served. A client
 * handed to [serve] comes with its [TcpLease], which [serve] releases when the client's socket is released; a failed or
 * cancelled accept, a refusal, and a [serve] that throws give the slot back here.
 */
internal suspend fun <S : Any> acceptLoop(
    accept: suspend () -> S,
    isClosed: () -> Boolean,
    onError: (IOException, Duration) -> Unit,
    limits: TcpLimits = TcpLimits(Int.MAX_VALUE, null),
    ipKeyOf: (S) -> String? = { null },
    refuse: (S) -> Unit = {},
    serve: suspend (S, TcpLease) -> Unit,
): Nothing {
    var pause = Duration.ZERO
    while (true) {
        limits.awaitSlot()
        val client =
            try {
                accept()
            } catch (e: IOException) {
                limits.cancelSlot()
                if (isClosed()) throw e
                pause = if (pause == Duration.ZERO) ACCEPT_BACKOFF_MIN else (pause * 2).coerceAtMost(ACCEPT_BACKOFF_MAX)
                onError(e, pause)
                delay(pause)
                continue
            } catch (e: Throwable) {
                limits.cancelSlot()
                throw e
            }
        pause = Duration.ZERO
        val lease = limits.lease()
        // an address that cannot be read (the peer is gone already) is not counted per address
        val key =
            try {
                ipKeyOf(client)
            } catch (_: Exception) {
                null
            }
        if (!limits.admit(lease, key)) {
            try {
                refuse(client)
            } finally {
                lease.release()
            }
            continue
        }
        try {
            serve(client, lease)
        } catch (e: Throwable) {
            lease.release()
            throw e
        }
    }
}

/**
 * [withTimeoutOrNull] that loses nothing [block] made: kotlinx's drops the block's result when the deadline fires while
 * the block finishes its last non-suspending steps, or when the caller is cancelled as it resumes (its KDoc: "the timeout
 * event is asynchronous with respect to the code running in the block"). Such a result goes to [release]; null after the
 * deadline, and the caller's cancellation is rethrown.
 */
internal suspend fun <T : Any> withTimeoutOrRelease(
    timeout: Duration,
    release: (T) -> Unit,
    block: suspend () -> T,
): T? {
    var made: T? = null
    val result =
        try {
            withTimeoutOrNull(timeout) { block().also { made = it } }
        } catch (e: Throwable) {
            made?.let(release)
            throw e
        }
    if (result == null) made?.let(release)
    return result
}

/**
 * Launches [block] even when this scope is already cancelled ([CoroutineStart.ATOMIC]), and then runs [onCancelled]
 * instead of it: what the caller handed over (an accepted socket) is released either way. A plain `launch` on a cancelled
 * scope never runs its body, nor a `finally` in it.
 */
internal fun CoroutineScope.launchOrElse(
    onCancelled: () -> Unit,
    block: suspend CoroutineScope.() -> Unit,
): Job =
    @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
    launch(start = CoroutineStart.ATOMIC) {
        if (!isActive) {
            onCancelled()
            return@launch
        }
        block()
    }

/**
 * Closes [sock] gracefully (what was written is still sent, then TLS `close_notify` and FIN) for as long as the drain
 * makes progress, and aborts it with [abort] once nothing has moved for [stall]: a slow reader's last response is never
 * cut short, a client that reads nothing cannot hold the descriptor. The engine owns this bound (its sockets have none of
 * their own, `setCloseTimeout(null)` at accept): progress is [progress] (the bytes the kernel has taken, `bytesSent`),
 * looked at every [poll]; where it is not known, [stall] bounds the whole close. A cancelled caller (the engine's hard
 * stop) aborts at once. Returns once the socket's job has completed, which is when its descriptor is released, or after
 * at most [ABORT_WAIT] more, so the engine reports a connection closed only when it is.
 */
internal suspend fun closeWithin(
    sock: Socket,
    abort: () -> Unit,
    stall: Duration,
    progress: () -> Long? = { sock.bytesSent },
    poll: Duration = minOf(CLOSE_POLL, stall),
) {
    sock.close()
    val closed =
        try {
            drainedWhileMoving(sock, stall, progress, poll)
        } catch (_: CancellationException) {
            false
        }
    if (closed) return
    abort()
    val released = withContext(NonCancellable) { withTimeoutOrNull(ABORT_WAIT) { sock.socketContext.join() } } != null
    if (!released) sock.socketContext.cancel() // the last resort; the descriptor may then wait for the loops to notice
}

/** Waits for [sock] to close; false once [progress] has not moved for [stall] (counted in steps of [poll]). */
private suspend fun drainedWhileMoving(
    sock: Socket,
    stall: Duration,
    progress: () -> Long?,
    poll: Duration,
): Boolean {
    var last = progress()
    var quiet = Duration.ZERO
    while (true) {
        if (withTimeoutOrNull(poll) { sock.socketContext.join() } != null) return true
        val now = progress()
        if (now == null || now == last) {
            quiet += poll
            if (quiet >= stall) return false
        } else {
            last = now
            quiet = Duration.ZERO
        }
    }
}

/** How often [closeWithin] looks at a closing socket's progress. */
private val CLOSE_POLL: Duration = 1.seconds

/** How long [closeWithin] waits for an aborted socket to release its descriptor. */
private val ABORT_WAIT: Duration = 3.seconds

/** [KuicksilverServerEventListener.connectionRefused] reason: the client's address holds `maxTcpConnectionsPerIp` connections. */
internal const val REFUSED_PER_IP = "per-IP limit"

/** [KuicksilverServerEventListener.connectionRefused] reason: the client's address serves an `http2RepeatOffenderPenalty`. */
internal const val REFUSED_REPEAT_OFFENDER = "HTTP/2 repeat offender"

/**
 * Logs the connections closed at accept for one reason (an address under an HTTP/2 penalty, [RepeatOffenders]; an address
 * at `maxTcpConnectionsPerIp`, [TcpLimits]): the first at once, then at most one line per [interval], saying how many were
 * left out, as [AcceptFailureReporter]. A flooding client reconnects as fast as it can, and a line per refusal would flood
 * the log in its place. Used from the one accept-loop coroutine only.
 */
internal class RefusalReporter(
    private val interval: Duration,
    private val timeSource: TimeSource = TimeSource.Monotonic,
    private val log: (String) -> Unit,
) {
    private var lastLogged: TimeMark? = null
    private var leftOut = 0

    fun report(
        who: String,
        why: String,
    ) {
        val last = lastLogged
        if (last != null && last.elapsedNow() < interval) {
            leftOut++
            return
        }
        val more = if (leftOut > 0) " ($leftOut more since the last report)" else ""
        log("Refused a connection from $who: $why$more")
        lastLogged = timeSource.markNow()
        leftOut = 0
    }
}

/** At most one accept-failure warning per this interval. */
internal val ACCEPT_FAILURE_LOG_INTERVAL: Duration = 10.seconds

/**
 * Logs accept failures: the first at once, then at most one line per [interval], saying how many were left out. With
 * the descriptor table full they come every second (the longest pause of [acceptLoop]) for as long as it lasts, and a
 * line each would flood the log. Used from the one accept-loop coroutine only.
 */
internal class AcceptFailureReporter(
    private val interval: Duration,
    private val timeSource: TimeSource = TimeSource.Monotonic,
    private val log: (String) -> Unit,
) {
    private var lastLogged: TimeMark? = null
    private var leftOut = 0

    fun report(
        e: IOException,
        pause: Duration,
    ) {
        val last = lastLogged
        if (last != null && last.elapsedNow() < interval) {
            leftOut++
            return
        }
        val more = if (leftOut > 0) " ($leftOut more failures since the last report)" else ""
        log("Accept failed: $e; retrying in $pause$more")
        lastLogged = timeSource.markNow()
        leftOut = 0
    }
}
