// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.application.Application
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.ktor.network.tls
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

internal object ServerFixtures {
    val testCa = Certificate(TestCerts.testCa)

    fun identity(): TlsIdentity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())

    fun clientTls(
        alpn: List<String> = listOf("http/1.1"),
        trust: TrustConfig = TrustConfig.AnchoredCa(listOf(testCa)),
        identity: TlsIdentity? = null,
    ): TlsConfig =
        tlsConfig(TlsRole.Client) {
            this.alpn = alpn
            serverName = "server.test"
            this.trust = trust
            this.identity = identity
        }
}

internal typealias Server = EmbeddedServer<KuicksilverApplicationEngine, KuicksilverApplicationEngine.Configuration>

/** Starts a server with one TLS connector on a free loopback port; returns it and the port. */
internal suspend fun tlsServer(
    configure: KuicksilverApplicationEngine.Configuration.() -> Unit = {},
    connector: KuicksilverTlsConnector.Builder.() -> Unit = {},
    module: Application.() -> Unit,
): Pair<Server, Int> {
    val server =
        embeddedServer(Kuicksilver, configure = {
            tlsConnector(ServerFixtures.identity()) {
                host = "127.0.0.1"
                port = 0
                connector()
            }
            configure()
        }, module = module)
    server.startSuspend(wait = false)
    return server to
        server.engine
            .resolvedConnectors()
            .first()
            .port
}

/** Sends [request] over TCP (TLS when [tls] is set) and returns everything the server sent until it closed. */
internal suspend fun rawHttp(
    port: Int,
    request: String,
    tls: TlsConfig? = ServerFixtures.clientTls(),
): String {
    val selector = SelectorManager(Dispatchers.Default)
    try {
        val tcp = aSocket(selector).tcp().connect("127.0.0.1", port)
        val socket: Socket = if (tls != null) tcp.tls(tls) else tcp
        try {
            val w = socket.openWriteChannel(autoFlush = true)
            val r = socket.openReadChannel()
            w.writeStringUtf8(request)
            w.flush()
            val out = StringBuilder()
            val b = ByteArray(8192)
            while (true) {
                val n = r.readAvailable(b, 0, b.size)
                if (n < 0) break
                out.append(b.decodeToString(0, n))
            }
            return out.toString()
        } finally {
            socket.close()
        }
    } finally {
        selector.close()
    }
}

/**
 * [rawHttp] for a client on a slow link: it reads at most [chunk] bytes every [pause] (a paced reader, not a wait for an
 * event), so the server's buffers fill and a response takes a while to arrive.
 */
internal suspend fun slowHttp(
    port: Int,
    request: String,
    tls: TlsConfig? = ServerFixtures.clientTls(),
    chunk: Int = 64 * 1024,
    pause: kotlin.time.Duration = 20.milliseconds,
): String {
    val selector = SelectorManager(Dispatchers.Default)
    try {
        val tcp = aSocket(selector).tcp().connect("127.0.0.1", port) { receiveBufferSize = 64 * 1024 }
        val socket: Socket = if (tls != null) tcp.tls(tls) else tcp
        try {
            val w = socket.openWriteChannel(autoFlush = true)
            val r = socket.openReadChannel()
            w.writeStringUtf8(request)
            w.flush()
            val out = StringBuilder()
            val b = ByteArray(chunk)
            while (true) {
                val n = r.readAvailable(b, 0, b.size)
                if (n < 0) break
                out.append(b.decodeToString(0, n))
                kotlinx.coroutines.delay(pause)
            }
            return out.toString()
        } finally {
            socket.close()
        }
    } finally {
        selector.close()
    }
}

internal fun serverTest(block: suspend () -> Unit) = runBlocking { withTimeout(60.seconds) { block() } }

private var quicServerProbe: Boolean? = null

/**
 * Whether a QUIC server can run here: the JVM and Android always, Kotlin/Native where the accelerated UDP transport exists
 * (ADR-0006). Learned once by binding a server endpoint the way the engine does, so the HTTP/3 tests turn on by themselves
 * on every platform that gains a QUIC server.
 */
internal suspend fun quicServerSupported(): Boolean =
    quicServerProbe ?: run {
        val config =
            QuicEndpointConfig
                .Builder()
                .apply {
                    server =
                        QuicServerConfig
                            .Builder(
                                tlsConfig(TlsRole.Server) {
                                    identity = ServerFixtures.identity()
                                    alpn = listOf(Http3Endpoint.H3)
                                },
                            ).build()
                }.build()
        try {
            QuicEndpoint.bind(InetSocketAddress("127.0.0.1", 0), config).closeAndJoin()
            true
        } catch (_: UnsupportedOperationException) {
            false
        }
    }.also { quicServerProbe = it }

/** A [serverTest] that needs the HTTP/3 listener: it passes without running where no QUIC server can run. */
internal fun h3ServerTest(block: suspend () -> Unit) = serverTest { if (quicServerSupported()) block() }
