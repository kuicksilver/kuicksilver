// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.ktor.utils.io.ExperimentalKtorApi::class)

package io.kuicksilver.engineinterop

import io.ktor.server.cio.CIO
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.sslConnector
import io.ktor.server.netty.Netty
import io.ktor.websocket.WebSocketDeflateExtension
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.ktor.server.Kuicksilver
import kotlinx.coroutines.runBlocking

/** The Ktor server engines of the bench. */
internal enum class ServerEngine(
    val label: String,
) {
    /** Kuicksilver's engine: HTTP/1.1 and HTTP/2 over TLS (HTTP/2 on), HTTP/3 on the same port, or cleartext HTTP/1.1. */
    Kuicksilver("Kuicksilver"),

    /** Ktor's Netty engine (Netty 4.2): HTTP/1.1 and HTTP/2 over TLS with ALPN, HTTP/3 (quiche) when asked for. */
    Netty("Ktor Netty"),

    /** Ktor's CIO engine: cleartext HTTP/1.1 only (it has no TLS and no HTTP/2). */
    Cio("Ktor CIO"),
}

/** A started server: its port, its scheme and what its application saw. */
internal class RunningServer(
    val engine: ServerEngine,
    val tls: Boolean,
    val port: Int,
    val probe: Probe,
    private val server: EmbeddedServer<*, *>,
) : AutoCloseable {
    val scheme get() = if (tls) "https" else "http"
    val wsScheme get() = if (tls) "wss" else "ws"

    fun url(path: String) = "$scheme://127.0.0.1:$port$path"

    fun wsUrl(path: String) = "$wsScheme://127.0.0.1:$port$path"

    /** Ktor's stop: stop accepting, wait up to [graceMillis] for running calls, cut what is left at [timeoutMillis]. */
    suspend fun stop(
        graceMillis: Long,
        timeoutMillis: Long,
    ) = server.stopSuspend(graceMillis, timeoutMillis)

    override fun close() = runBlocking { server.stopSuspend(0, 2_000) }
}

/**
 * Starts [engine] on a free loopback port: over TLS with the test identity when [tls] (Kuicksilver and Netty), with
 * HTTP/2 on Kuicksilver's connector when [http2], and HTTP/3 on Netty when [http3] (ours always listens for HTTP/3 next
 * to TCP). [deflate] installs the server's permessage-deflate: PerMessageDeflate on ours, Ktor's WebSocketDeflateExtension
 * on Ktor's engines.
 */
internal fun startServer(
    engine: ServerEngine,
    tls: Boolean,
    http2: Boolean = true,
    http3: Boolean = false,
    deflate: Boolean = false,
): RunningServer {
    val probe = Probe()
    val server: EmbeddedServer<*, *> =
        when (engine) {
            ServerEngine.Kuicksilver -> {
                embeddedServer(Kuicksilver, configure = {
                    if (tls) {
                        tlsConnector(Pki.identity()) {
                            host = "127.0.0.1"
                            port = 0
                        }
                    } else {
                        connector {
                            host = "127.0.0.1"
                            port = 0
                        }
                    }
                    this.http2 = http2
                    shutdownGracePeriod = 0
                }) { interopModule(probe, if (deflate) ({ install(PerMessageDeflate) }) else null) }
            }

            ServerEngine.Netty -> {
                embeddedServer(Netty, configure = {
                    if (tls) {
                        sslConnector(Pki.serverKeyStore, Pki.KEY_ALIAS, { Pki.password }, { Pki.password }) {
                            host = "127.0.0.1"
                            port = 0
                        }
                    } else {
                        connector {
                            host = "127.0.0.1"
                            port = 0
                        }
                    }
                    if (http3) enableHttp3()
                    shutdownGracePeriod = 0
                }) { interopModule(probe, if (deflate) ({ install(WebSocketDeflateExtension) }) else null) }
            }

            ServerEngine.Cio -> {
                require(!tls) { "Ktor's CIO server has no TLS" }
                embeddedServer(CIO, configure = {
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                    shutdownGracePeriod = 0
                }) { interopModule(probe, if (deflate) ({ install(WebSocketDeflateExtension) }) else null) }
            }
        }
    server.start(wait = false)
    val port =
        runBlocking {
            server.engine
                .resolvedConnectors()
                .first()
                .port
        }
    return RunningServer(engine, tls, port, probe, server)
}
