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
import io.ktor.network.sockets.openReadChannel
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
import io.kuicksilver.ktor.network.setCloseTimeout
import io.kuicksilver.ktor.network.tlsServer
import io.kuicksilver.ktor.server.h1.H1Call
import io.kuicksilver.ktor.server.h1.H1Connection
import io.kuicksilver.ktor.server.h1.H1RequestScope
import io.kuicksilver.ktor.server.h1.sendStallTimeout
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
        val tlsConfig = l.tls?.let { tcpTlsConfig(it) }
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
                                CoroutineExceptionHandler { _, e -> environment.log.debug("HTTP/1.1 connection on port $port failed: $e") },
                        )
                    val acceptFailures = AcceptFailureReporter(ACCEPT_FAILURE_LOG_INTERVAL) { environment.log.warn("${l.config}: $it") }
                    try {
                        acceptLoop(
                            accept = { server.accept() },
                            isClosed = { server.isClosed },
                            onError = acceptFailures::report,
                        ) { client ->
                            // the request-head deadline of the first request counts from here, the TLS handshake included
                            val accepted = TimeSource.Monotonic.markNow()
                            openTcpSockets.update { it + 1 }
                            client.setCloseTimeout(null) // the engine bounds the close (closeWithin), on progress
                            client.socketContext.invokeOnCompletion { openTcpSockets.update { it - 1 } }
                            connectionScope.launch {
                                val sock: Socket
                                val peer: List<Certificate>
                                val remote = client.remoteAddress as? InetSocketAddress
                                if (tlsConfig != null) {
                                    val t =
                                        try {
                                            withTimeoutOrNull(headerTimeout) { client.tlsServer(tlsConfig) }
                                                ?: throw IOException("No TLS handshake within the request header timeout ($headerTimeout)")
                                        } catch (e: Throwable) {
                                            client.close()
                                            if (e !is CancellationException) {
                                                events.emit(
                                                    "tlsHandshakeFailed",
                                                ) { tlsHandshakeFailed(remote, e) }
                                            }
                                            return@launch
                                        } // a failed handshake ends only this connection
                                    t.setCloseTimeout(null)
                                    sock = t
                                    peer = t.peerCertificates
                                } else {
                                    sock = client
                                    peer = emptyList()
                                }
                                val altSvc = if (l.tls != null && configuration.altSvc) http3AltSvc(port) else NO_ALT_SVC
                                if (h2Offered && (sock as? io.kuicksilver.ktor.network.TlsSocket)?.negotiatedAlpn == H2_ALPN) {
                                    return@launch serveH2(
                                        sock,
                                        remote,
                                        peer,
                                        altSvc,
                                        (headerTimeout - accepted.elapsedNow()).coerceAtLeast(Duration.ZERO),
                                        timeout,
                                        headerTimeout,
                                        sendTimeout,
                                        draining,
                                    )
                                }
                                events.emit("connectionOpened") { connectionOpened(HttpProtocolVersion.HTTP_1_1, remote) }
                                val connection =
                                    H1Connection(
                                        sock.openReadChannel(),
                                        sock.openWriteChannel(),
                                        sock.remoteAddress.toNetworkAddress(),
                                        sock.localAddress.toNetworkAddress(),
                                    )
                                try {
                                    startH1Pipeline(
                                        connection,
                                        timeout,
                                        headerTimeout,
                                        (headerTimeout - accepted.elapsedNow()).coerceAtLeast(Duration.ZERO),
                                        draining = draining,
                                        sendTimeout = sendTimeout,
                                    ) { request -> handleRequest(this, request, scheme, peer, altSvc) }.join()
                                } finally {
                                    // a client cut for not reading has had the stall deadline already: no second one for the close
                                    closeWithin(sock, { sock.abort() }, if (connection.clientStoppedReading) Duration.ZERO else sendTimeout)
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
        return TcpServer(rootJob, acceptJob, socket, h3Endpoint, draining, connections)
    }
}

/** The ALPN protocol ID of HTTP/2 over TLS (RFC 9113 section 3.2). */
internal const val H2_ALPN = "h2"

/**
 * The TLS configuration of a TCP connector: ALPN `h2` before `http/1.1` when [KuicksilverApplicationEngine.Configuration.http2]
 * is set (the server picks by its own order, so a client that offers both gets HTTP/2, RFC 7301 section 3.2), else
 * `http/1.1` alone. HTTP/2 is offered only over TLS 1.3: RFC 9113 section 9.2.1 makes a TLS 1.2 renegotiation a
 * connection error, which the TLS layer cannot report (OpenSSL refuses renegotiation on its own, ksl_ctx.c), and section
 * 9.2.2 restricts the TLS 1.2 cipher suites; the server negotiates TLS 1.3 only, so this holds for every connector.
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
internal fun KuicksilverApplicationEngine.tcpTlsConfig(tls: KuicksilverTlsConnector): io.kuicksilver.tls.TlsConfig {
    val h1 = tls.tlsConfig(listOf("http/1.1"))
    if (!configuration.http2 || h1.versions != io.kuicksilver.tls.TlsVersions.Tls13) return h1
    return tls.tlsConfig(listOf(H2_ALPN, "http/1.1"))
}

/**
 * HTTP/3 is announced only where it is served (turned on together with the UDP listener), and as [http3Advertising] says at
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
    altSvc: () -> String?,
) {
    with(scope) {
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
                )
            events.emit("requestStarted") { requestStarted(HttpProtocolVersion.HTTP_1_1, call) }
            var failure: Throwable? = null
            try {
                addHandlerForExpectedHeader(output, call, continueSent)
                // forwarded from early data by a gateway and not replayable: 425, it cannot be made safe by waiting (RFC 8470 section 5.1)
                if (request.headers[EARLY_DATA_FIELD] != null &&
                    request.method.value !in io.kuicksilver.http3.Http3EarlyDataPolicy.SAFE_METHODS
                ) {
                    call.respond(HttpStatusCode.TooEarly)
                } else {
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

// From Ktor CIO: 100-continue for requests that ask for it.
private fun addHandlerForExpectedHeader(
    output: ByteWriteChannel,
    call: H1Call,
    continueSent: CompletableJob?,
) {
    val expectedHeaderPhase = PipelinePhase("ExpectedHeaderPhase")
    call.request.pipeline.insertPhaseBefore(ApplicationReceivePipeline.Before, expectedHeaderPhase)
    call.request.pipeline.intercept(expectedHeaderPhase) {
        val request = call.request
        val version = HttpProtocolVersion.parse(request.local.version)
        val expectHeader = request.headers[HttpHeaders.Expect]?.lowercase()
        val contentLength = request.headers[HttpHeaders.ContentLength]?.toLongOrNull()
        val hasBody = request.headers[HttpHeaders.TransferEncoding] != null || (contentLength != null && contentLength > 0)
        if (expectHeader == null || version == HttpProtocolVersion.HTTP_1_0 || !hasBody) return@intercept
        if (expectHeader != "100-continue") {
            call.respond(message = HttpStatusCode.ExpectationFailed)
        } else {
            output.writeStringUtf8("HTTP/1.1 100 Continue\r\n\r\n")
            output.flush()
            continueSent?.complete() // the body deadline starts now: the client sends the body after this
        }
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
 */
internal suspend fun <S : Any> acceptLoop(
    accept: suspend () -> S,
    isClosed: () -> Boolean,
    onError: (IOException, Duration) -> Unit,
    serve: (S) -> Unit,
): Nothing {
    var pause = Duration.ZERO
    while (true) {
        val client =
            try {
                accept()
            } catch (e: IOException) {
                if (isClosed()) throw e
                pause = if (pause == Duration.ZERO) ACCEPT_BACKOFF_MIN else (pause * 2).coerceAtMost(ACCEPT_BACKOFF_MAX)
                onError(e, pause)
                delay(pause)
                continue
            }
        pause = Duration.ZERO
        serve(client)
    }
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
