// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.ios

import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.incomingConnections
import io.kuicksilver.quic.incomingStreams
import io.kuicksilver.quic.quicEndpointConfig
import io.kuicksilver.quic.quicServerConfig
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.supervisorScope

/**
 * "Server mode": one QUIC endpoint on `[::]:port` (dual-stack, so IPv4 and IPv6 peers on the LAN reach it) that speaks
 * HTTP/3 (ALPN `h3`, a small HTML page) and the raw echo protocol (ALPN [ECHO_ALPN]) on the same port. On iOS a server is
 * a foreground-only feature: the system suspends the app, and with it the socket, shortly after it leaves the screen.
 */
internal class SampleServer private constructor(private val endpoint: QuicEndpoint, private val log: (String) -> Unit) {
    val port: Int get() = endpoint.localAddress.port
    private var job: Job? = null

    private fun start(scope: CoroutineScope) {
        job = scope.launch {
            supervisorScope {
                endpoint.incomingConnections().collect { c -> launch { serve(c) } }
            }
        }
    }

    private suspend fun serve(connection: QuicConnection) {
        val peer = connection.paths.firstOrNull()?.remoteAddress.show()
        log("server: connection from $peer, ALPN ${connection.negotiatedAlpn}")
        try {
            if (connection.negotiatedAlpn == "h3") serveHttp3(connection) else serveEcho(connection)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            log("server: $peer closed (${e::class.simpleName}: ${e.message})")
        }
    }

    private suspend fun serveHttp3(quic: QuicConnection) = supervisorScope {
        val h3 = Http3Connection.server(quic)
        while (true) {
            val request = h3.acceptRequest()
            launch {
                log("server: ${request.method} ${request.path} from ${request.remoteAddress.show()}")
                val page = page(request.path ?: "/", request.remoteAddress.show()).encodeToByteArray()
                val writer = request.respond(200, Http3Headers.of("content-type" to "text/html; charset=utf-8", "content-length" to page.size.toString()))
                writer.output.writeFully(page)
                writer.finish()
            }
        }
    }

    private suspend fun serveEcho(quic: QuicConnection) = supervisorScope {
        quic.incomingStreams().collect { stream ->
            launch {
                val buf = ByteArray(16 * 1024)
                while (true) {
                    val n = stream.input.readAvailable(buf, 0, buf.size)
                    if (n <= 0) break
                    stream.output.writeFully(buf, 0, n)
                    stream.output.flush()
                }
                stream.output.flushAndClose()
            }
        }
    }

    fun close() {
        job?.cancel(); endpoint.close()
    }

    companion object {
        /** Binds `[::]:[port]` (0 picks a free port) and starts serving in [scope]. */
        suspend fun start(port: Int, scope: CoroutineScope, log: (String) -> Unit): SampleServer {
            val endpoint = QuicEndpoint.bind(InetSocketAddress("::", port), quicEndpointConfig { server = quicServerConfig(serverTls()) })
            return SampleServer(endpoint, log).also { it.start(scope); log("server: listening on [::]:${it.port} (h3 and $ECHO_ALPN)") }
        }

        private fun page(path: String, peer: String): String =
            """<!doctype html><html><head><meta charset="utf-8"><title>Kuicksilver on iOS</title></head>
              |<body><h1>Hello over HTTP/3</h1><p>Served by Kuicksilver from an iPhone.</p>
              |<p>path: ${escape(path)}<br>you: ${escape(peer)}</p></body></html>
              |""".trimMargin()

        private fun escape(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    }
}

