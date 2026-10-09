// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.application.Application
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.network.tls
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
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

internal fun serverTest(block: suspend () -> Unit) = runBlocking { withTimeout(60.seconds) { block() } }
