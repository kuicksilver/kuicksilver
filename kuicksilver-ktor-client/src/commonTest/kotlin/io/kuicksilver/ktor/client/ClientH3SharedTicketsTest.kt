// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.ipLiteral
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * The HTTP/3 pool's endpoints (the wildcard one and one per loopback family) share one session-ticket cache: a name that
 * resolves to 127.0.0.1 and to ::1 (`localhost`) resumes, in 0-RTT, over the family its next connection takes.
 */
class ClientH3SharedTicketsTest {
    private val loopback6 = TcpAddress(ByteArray(16).also { it[15] = 1 }, 0)
    private val loopback4 = TcpAddress(byteArrayOf(127, 0, 0, 1), 0)

    /** An HTTP/3 server answering "ok" on [local], 0-RTT on, its accepted connections sent to [accepted]. */
    private suspend fun CoroutineScope.server(
        local: InetSocketAddress,
        tls: io.kuicksilver.tls.TlsConfig,
        accepted: Channel<Http3Connection>,
    ): Http3Endpoint {
        val ep =
            Http3Endpoint.bind(
                local,
                QuicEndpointConfig
                    .Builder()
                    .apply { server = QuicServerConfig.Builder(tls).apply { earlyData = true }.build() }
                    .build(),
            )
        launch {
            runCatching {
                while (true) {
                    val conn = ep.accept()
                    accepted.send(conn)
                    launch {
                        runCatching {
                            while (true) {
                                val r = conn.acceptRequest()
                                launch {
                                    runCatching {
                                        r
                                            .respond(
                                                200,
                                                Http3Headers(emptyList()),
                                            ).also { it.output.writeStringUtf8("ok") }
                                            .finish()
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return ep
    }

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun aTicketFromIpv4ResumesOverIpv6() =
        h3Test {
            coroutineScope {
                // one TLS configuration, so both server endpoints take the same ticket keys
                val tls =
                    tlsConfig(TlsRole.Server) {
                        alpn = listOf(Http3Endpoint.H3)
                        identity = ClientFixtures.identity()
                    }
                val accepted = Channel<Http3Connection>(Channel.UNLIMITED)
                val ep4 = server(InetSocketAddress("127.0.0.1", 0), tls, accepted)
                val port = ep4.localAddress.port
                val ep6 = runCatching { server(InetSocketAddress("::1", port), tls, accepted) }.getOrNull()
                try {
                    if (ep6 == null) {
                        println("aTicketFromIpv4ResumesOverIpv6 skipped: needs ::1 with port $port free")
                        return@coroutineScope
                    }
                    var v6Only = false
                    testClient(Http3DiscoveryMode.H3Only, engine = {
                        http3 { earlyData = true }
                        familyResolverForTest = { _, v6 -> if (v6 == v6Only) listOf(if (v6) loopback6 else loopback4) else emptyList() }
                    }).use { c ->
                        val engine = c.engine as KuicksilverEngine
                        assertEquals("ok", c.get("https://server.test:$port/").bodyAsText())
                        val first = withTimeout(10.seconds) { accepted.receive() }
                        assertEquals(
                            "127.0.0.1",
                            first.quic.paths
                                .first()
                                .remoteAddress
                                .ipLiteral(),
                        )
                        // the ticket arrives after the handshake: forget the connection, so the next request resumes
                        engine.h3.dropConnectionsForTest().forEach { it.close() }
                        v6Only = true
                        assertEquals("ok", c.get("https://server.test:$port/").bodyAsText())
                        val second = withTimeout(10.seconds) { accepted.receive() }
                        assertEquals(
                            "::1",
                            second.quic.paths
                                .first()
                                .remoteAddress
                                .ipLiteral(),
                        )
                        assertEquals(true, second.quic.earlyDataAccepted, "resumed in 0-RTT over ::1 with the ticket of 127.0.0.1")
                    }
                } finally {
                    ep4.close()
                    ep6?.close()
                    coroutineContext[kotlinx.coroutines.Job]?.children?.forEach { it.cancel() }
                }
            }
        }
}
