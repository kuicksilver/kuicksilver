// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
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
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.cio.backend.ServerIncomingConnection
import io.ktor.server.cio.backend.ServerRequestScope
import io.ktor.server.cio.backend.startServerConnectionPipeline
import io.ktor.server.engine.handleFailure
import io.ktor.server.request.ApplicationReceivePipeline
import io.ktor.server.response.respond
import io.ktor.util.network.NetworkAddress
import io.ktor.util.pipeline.PipelinePhase
import io.ktor.util.pipeline.execute
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.network.tlsServer
import io.kuicksilver.ktor.server.h1.H1Call
import io.kuicksilver.tls.Certificate
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
)

/** The accept loop of one TCP connector, after Ktor CIO's `httpServer`, with a TLS handshake per connection. */
@OptIn(InternalAPI::class)
internal fun KuicksilverApplicationEngine.startTcp(
    scope: CoroutineScope,
    l: KuicksilverApplicationEngine.Listener,
    h3Ready: Job,
): TcpServer {
    with(scope) {
        val socket = CompletableDeferred<ServerSocket>()
        val latch: CompletableJob = Job()
        val rootJob = launch(CoroutineName("kuicksilver-server-${l.config}"), start = CoroutineStart.UNDISPATCHED) { latch.join() }
        val selector = SelectorManager(coroutineContext)
        val timeout = configuration.connectionIdleTimeoutSeconds.seconds
        val connections = SupervisorJob(rootJob)
        val tlsConfig = l.tls?.tlsConfig(listOf("http/1.1"))
        val scheme = if (l.tls != null) "https" else "http"
        val acceptJob =
            launch(rootJob + CoroutineName("accept-${l.config}")) {
                val server = aSocket(selector).tcp().bind(l.config.host, l.config.port)
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
                                if (tlsConfig != null) {
                                    val t =
                                        try {
                                            client.tlsServer(tlsConfig)
                                        } catch (e: Throwable) {
                                            client.close()
                                            return@launch
                                        } // a failed handshake ends only this connection
                                    sock = t
                                    peer = t.peerCertificates
                                } else {
                                    sock = client
                                    peer = emptyList()
                                }
                                val altSvc = if (l.tls != null && configuration.altSvc) http3AltSvc(port) else null
                                try {
                                    val connection =
                                        ServerIncomingConnection(
                                            sock.openReadChannel(),
                                            sock.openWriteChannel(),
                                            sock.remoteAddress.toNetworkAddress(),
                                            sock.localAddress.toNetworkAddress(),
                                        )
                                    startServerConnectionPipeline(
                                        connection,
                                        timeout,
                                    ) { request -> handleRequest(this, request, scheme, peer, altSvc) }.join()
                                } finally {
                                    sock.close()
                                }
                            }
                        }
                    } catch (e: kotlinx.io.IOException) {
                        coroutineContext.cancel()
                    } finally {
                        server.close()
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
        return TcpServer(rootJob, acceptJob, socket)
    }
}

/** HTTP/3 is announced only where it is served (turned on together with the UDP listener). */
private fun KuicksilverApplicationEngine.http3AltSvc(port: Int): String? = if (port in h3Ports) "h3=\":$port\"; ma=86400" else null

private suspend fun KuicksilverApplicationEngine.handleRequest(
    scope: ServerRequestScope,
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
            try {
                addHandlerForExpectedHeader(output, call)
                pipeline.execute(call)
            } catch (error: Throwable) {
                handleFailure(call, error)
            } finally {
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
