// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.Application
import io.ktor.server.application.serverConfig
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.applicationEnvironment
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.ktor.server.KuicksilverApplicationEngine
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.time.Duration.Companion.seconds
import io.kuicksilver.ktor.server.Kuicksilver as KuicksilverServer

// Every test selector of this module runs on Dispatchers.IO, as ktor-network wants it: an ActorSelectorManager blocks its
// thread in select() (up to 500 ms) while a read is pending, and on Dispatchers.Default (two threads on a two-core device,
// the CI emulators) a few of them starve the QUIC loops and TLS pumps that run there.
internal object ClientFixtures {
    val testCa = Certificate(TestCerts.testCa)
    val trust: TrustConfig = TrustConfig.AnchoredCa(listOf(testCa))

    fun identity(): TlsIdentity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
}

internal typealias TestServer = EmbeddedServer<KuicksilverApplicationEngine, KuicksilverApplicationEngine.Configuration>

/**
 * A Kuicksilver server engine on [host] (IPv4 loopback) and [port] (0: a free one): TLS (HTTP/1.1 + HTTP/3) unless [plain];
 * returns it and its port. A start that fails (the port is taken) stops the engine before it rethrows.
 */
internal suspend fun testServer(
    plain: Boolean = false,
    host: String = "127.0.0.1",
    port: Int = 0,
    configure: KuicksilverApplicationEngine.Configuration.() -> Unit = {},
    log: CapturedLog? = null,
    module: Application.() -> Unit,
): Pair<TestServer, Int> {
    val configuration: KuicksilverApplicationEngine.Configuration.() -> Unit = {
        if (plain) {
            connector {
                this.host = host
                this.port = port
            }
        } else {
            tlsConnector(ClientFixtures.identity()) {
                this.host = host
                this.port = port
            }
        }
        configure()
    }
    val server =
        if (log == null) {
            embeddedServer(KuicksilverServer, configure = configuration, module = module)
        } else {
            // a test that provokes server-side errors on purpose takes them in [log] instead of printing them
            embeddedServer(KuicksilverServer, serverConfig(applicationEnvironment { this.log = log }) { module(module) }, configuration)
        }
    try {
        server.startSuspend(false)
    } catch (e: Throwable) {
        runCatching { server.stopSuspend(0, 0) }
        throw e
    }
    return server to
        server.engine
            .resolvedConnectors()
            .first()
            .port
}

/** A client with the test trust; HTTP/1.1 only unless [discovery] says otherwise. */
internal fun testClient(
    discovery: Http3DiscoveryMode = Http3DiscoveryMode.H1Only,
    engine: KuicksilverEngineConfig.() -> Unit = {},
    block: HttpClientConfig<KuicksilverEngineConfig>.() -> Unit = {},
): HttpClient =
    HttpClient(Kuicksilver) {
        engine {
            trust = ClientFixtures.trust
            http3 { this.discovery = discovery }
            engine()
        }
        block()
    }

/**
 * Two sockets on one port number, both owned by the test: [first] and [second] bind the port they are given (0: a free
 * one) and return what they bound with its port. The attempts alternate which side takes a free port, the other then
 * binding that number: first [first], then [second], and so on; a side that finds the number taken (by an unrelated
 * process or connection: a free port of one socket kind or address says nothing about another) gets the pair released
 * ([releaseFirst], [releaseSecond]) and the next attempt goes. Retrying one order only is not enough where the OS hands
 * out free ports one after the other (Windows does): every retry lands on the next number, and a run of taken twins
 * (TCP ports held by the client connections of earlier tests, TIME_WAIT included) refused all twenty UDP-first attempts
 * on the Windows CI, as the server engine's own pairing had found (`bindTcpAndUdp`). Only a failure that may come from a
 * port in use is retried ([mayBeTaken]); any other is thrown at once, the held side released first. A release that
 * throws does not hide the bind failure (it is added as suppressed).
 */
internal suspend fun <A, B> bindOnSamePort(
    first: suspend (port: Int) -> Pair<A, Int>,
    releaseFirst: suspend (A) -> Unit,
    second: suspend (port: Int) -> Pair<B, Int>,
    releaseSecond: suspend (B) -> Unit,
): Triple<A, B, Int> {
    var last: Throwable? = null
    repeat(SAME_PORT_ATTEMPTS) { attempt ->
        try {
            return if (attempt % 2 == 0) {
                val (a, port) = first(0)
                Triple(a, bindTwin(a, releaseFirst) { second(port) }, port)
            } else {
                val (b, port) = second(0)
                Triple(bindTwin(b, releaseSecond) { first(port) }, b, port)
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Throwable) {
            if (!mayBeTaken(e)) throw e
            last = e
        }
    }
    throw IllegalStateException("no port free for both sockets after $SAME_PORT_ATTEMPTS attempts", last)
}

/** [bind] the twin of [held]; when that fails (cancellation included) [held] is released, a failing release suppressed. */
private suspend fun <H, T> bindTwin(
    held: H,
    release: suspend (H) -> Unit,
    bind: suspend () -> Pair<T, Int>,
): T =
    try {
        bind().first
    } catch (e: Throwable) {
        try {
            release(held)
        } catch (r: Throwable) {
            e.addSuppressed(r)
        }
        throw e
    }

/**
 * Whether [e], from binding one side of a pair, may come from a port in use, so that another pair may succeed: as the
 * server engine's `mayBeTaken`, anything but a refused configuration, which would fail every attempt alike. The
 * address-in-use failure has no common type (`java.net.BindException` on the JVM, ktor's `PosixException` on
 * Kotlin/Native, an `IOException` from ksl).
 */
internal fun mayBeTaken(e: Throwable): Boolean =
    e !is IllegalArgumentException &&
        e !is IllegalStateException &&
        e !is io.kuicksilver.tls.TlsException &&
        e !is io.kuicksilver.native.KslException

internal const val SAME_PORT_ATTEMPTS = 20

internal fun clientTest(block: suspend () -> Unit) = runBlocking { withTimeout(60.seconds) { block() } }

private var quicServerProbe: Boolean? = null

/**
 * Whether a QUIC server can run here: the JVM and Android always, Kotlin/Native where the accelerated UDP transport exists
 * (ADR-0006). Learned once by binding a server endpoint the way the Ktor server engine does, so the H3 tests turn on by
 * themselves on every platform that gains a QUIC server.
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
                                    identity = ClientFixtures.identity()
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

/** A [clientTest] that needs a QUIC server (HTTP/3 peer): it passes without running where no QUIC server can run. */
internal fun h3Test(block: suspend () -> Unit) = clientTest { if (quicServerSupported()) block() }
