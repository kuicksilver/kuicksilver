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
import io.kuicksilver.ktor.network.bindTcp
import io.kuicksilver.ktor.network.engineSelector
import io.kuicksilver.ktor.network.tlsServer
import io.kuicksilver.ktor.server.h1.H1Call
import io.kuicksilver.ktor.server.h1.H1Connection
import io.kuicksilver.ktor.server.h1.H1RequestScope
import io.kuicksilver.ktor.server.h1.startH1Pipeline
import io.kuicksilver.tls.Certificate
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.time.Duration.Companion.seconds

internal class TcpServer(
    val rootJob: Job,
    val acceptJob: Job,
    val socket: CompletableDeferred<ServerSocket>,
    /** The HTTP/3 endpoint bound on the same port as [socket], completed before it; null without HTTP/3. */
    val h3Endpoint: CompletableDeferred<Http3Endpoint?>,
)

/** `port = 0`: TCP + UDP pairs tried before HTTP/3 is given up for the connector. */
internal const val EPHEMERAL_PAIR_ATTEMPTS = 16

/**
 * Binds the TCP socket of [l] and, with [h3], its HTTP/3 endpoint on the same port number. With `port = 0` the OS picks
 * a TCP port whose UDP twin may be taken: the pair is retried (the TCP socket closed) up to [EPHEMERAL_PAIR_ATTEMPTS]
 * times, then HTTP/3 is skipped with a warning and HTTP/1.1 is served alone. A fixed port whose UDP side cannot be bound
 * fails the start, as before. A platform without a QUIC server (UnsupportedOperationException) skips HTTP/3 at once.
 */
private suspend fun KuicksilverApplicationEngine.bindTcpAndUdp(
    selector: SelectorManager,
    l: KuicksilverApplicationEngine.Listener,
    h3: (suspend (Int) -> Http3Endpoint)?,
): Pair<ServerSocket, Http3Endpoint?> {
    val ephemeral = l.config.port == 0
    var last: Throwable? = null
    repeat(
        if (h3 == null) {
            1
        } else if (ephemeral) {
            EPHEMERAL_PAIR_ATTEMPTS
        } else {
            1
        },
    ) {
        val server = bindTcp(selector, l.config.host, l.config.port)
        if (h3 == null) return server to null
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
            if (!ephemeral) {
                server.close()
                throw e
            }
            environment.log.debug("UDP port $port is taken ($e); trying another TCP + UDP pair")
            server.close()
            last = e
        }
    }
    environment.log.warn(
        "HTTP/3 is not served: no free UDP port next to an ephemeral TCP one after $EPHEMERAL_PAIR_ATTEMPTS attempts ($last)",
    )
    return bindTcp(selector, l.config.host, l.config.port) to null
}

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
        val connections = SupervisorJob(rootJob)
        // completed when accepting ends (the engine stops): connections read no further request, idle ones close at once
        val draining = Job()
        tcpConnectionsForProbe += connections
        val tlsConfig = l.tls?.tlsConfig(listOf("http/1.1"))
        val scheme = if (l.tls != null) "https" else "http"
        val acceptJob =
            launch(rootJob + CoroutineName("accept-${l.config}")) {
                val (server, endpoint) = bindTcpAndUdp(selector, l, h3)
                h3Endpoint.complete(endpoint)
                server.use {
                    socket.complete(server)
                    h3Ready.join()
                    val connectionScope = CoroutineScope(coroutineContext + connections + CoroutineName("connection"))
                    val port = (server.localAddress as? InetSocketAddress)?.port ?: l.config.port
                    try {
                        while (true) {
                            val client: Socket =
                                try {
                                    server.accept()
                                } catch (e: kotlinx.io.IOException) {
                                    continue
                                }
                            connectionScope.launch {
                                val sock: Socket
                                val peer: List<Certificate>
                                val remote = client.remoteAddress as? InetSocketAddress
                                if (tlsConfig != null) {
                                    val t =
                                        try {
                                            client.tlsServer(tlsConfig)
                                        } catch (e: Throwable) {
                                            client.close()
                                            if (e !is CancellationException) {
                                                events.emit(
                                                    "tlsHandshakeFailed",
                                                ) { tlsHandshakeFailed(remote, e) }
                                            }
                                            return@launch
                                        } // a failed handshake ends only this connection
                                    sock = t
                                    peer = t.peerCertificates
                                } else {
                                    sock = client
                                    peer = emptyList()
                                }
                                val altSvc = if (l.tls != null && configuration.altSvc) http3AltSvc(port) else null
                                events.emit("connectionOpened") { connectionOpened(HttpProtocolVersion.HTTP_1_1, remote) }
                                try {
                                    val connection =
                                        H1Connection(
                                            sock.openReadChannel(),
                                            sock.openWriteChannel(),
                                            sock.remoteAddress.toNetworkAddress(),
                                            sock.localAddress.toNetworkAddress(),
                                        )
                                    startH1Pipeline(
                                        connection,
                                        timeout,
                                        draining,
                                    ) { request -> handleRequest(this, request, scheme, peer, altSvc) }.join()
                                } finally {
                                    sock.close()
                                    events.emit("connectionClosed") { connectionClosed(HttpProtocolVersion.HTTP_1_1, remote) }
                                }
                            }
                        }
                    } catch (e: kotlinx.io.IOException) {
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
        return TcpServer(rootJob, acceptJob, socket, h3Endpoint)
    }
}

/** HTTP/3 is announced only where it is served (turned on together with the UDP listener). */
private fun KuicksilverApplicationEngine.http3AltSvc(port: Int): String? = if (port in h3Ports) "h3=\":$port\"; ma=86400" else null

private suspend fun KuicksilverApplicationEngine.handleRequest(
    scope: H1RequestScope,
    request: Request,
    scheme: String,
    peer: List<Certificate>,
    altSvc: String?,
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
                )
            events.emit("requestStarted") { requestStarted(HttpProtocolVersion.HTTP_1_1, call) }
            var failure: Throwable? = null
            try {
                addHandlerForExpectedHeader(output, call)
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
        }
    }
}

private fun SocketAddress.toNetworkAddress(): NetworkAddress? = (this as? InetSocketAddress)?.let { NetworkAddress(it.hostname, it.port) }
