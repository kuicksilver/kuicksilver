// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)

package io.kuicksilver.http3.connectudp

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.H3Fixtures
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.connectUdp
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.IoCapabilities
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.seconds

/**
 * Proxied QUIC: a QUIC connection, and HTTP/3 on it, whose UDP socket is a CONNECT-UDP tunnel ([io.kuicksilver.http3.UdpTunnel.asDatagramIo]).
 * The connection to the proxy runs on sockets that set Don't Fragment, so DPLPMTUD lifts its path MTU above 1200 and the
 * inner connection's 1200-byte datagrams fit its HTTP datagrams.
 */
class ProxiedQuicTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun http3ThroughTheProxy() =
        h3Test {
            val pair = H3Pair.open(serverSettings = proxySettings, df = true)
            ProxyRig(pair) { f -> allowAllConfig(f) }.use { rig ->
                rig.serveAll()
                val targetAddress = InetSocketAddress("192.0.2.80", 443)
                val targetIo = pair.quic.net.open(targetAddress)
                val target =
                    QuicEndpoint.bind(
                        targetAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                server = QuicServerConfig.Builder(H3Fixtures.server()).build()
                                runtime { crypto = NullCryptoProvider }
                                runtime { io = { targetIo } }
                            }.build(),
                    )
                val seenFrom = CompletableDeferred<InetSocketAddress>()
                rig.background {
                    val h3 = Http3Connection.server(target.accept())
                    val req = h3.acceptRequest()
                    seenFrom.complete(req.remoteAddress)
                    val w = req.respond(200, Http3Headers(listOf("x-path" to req.path.orEmpty())))
                    w.output.writeStringUtf8("hello through the proxy")
                    w.finish()
                }
                val tunnel = pair.client.connectUdp(template, "192.0.2.80", 443)
                val inner =
                    QuicEndpoint.bind(
                        InetSocketAddress("127.0.0.1", 0), // handed to the factory below, which ignores it
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                runtime { crypto = NullCryptoProvider }
                                runtime { io = { tunnel.asDatagramIo() } }
                            }.build(),
                    )
                try {
                    val q =
                        withTimeout(
                            20.seconds,
                        ) { inner.connect(tunnel.remoteAddress, QuicClientConfig.Builder(H3Fixtures.client()).build()) }
                    val h3 = Http3Connection.client(q)
                    val response = withTimeout(10.seconds) { h3.request(http3Request("GET", "server.test", "/via/masque")) }
                    assertEquals(200, response.status)
                    assertEquals("/via/masque", response.headers["x-path"])
                    assertEquals("hello through the proxy", response.body.readAllBytes().decodeToString())
                    // the target saw the proxy's socket, not the client
                    assertEquals(rig.proxySocket(1).port, seenFrom.await().port)
                    h3.close()
                } finally {
                    inner.close()
                    target.close()
                }
                // the inner endpoint closed its socket, which closed the tunnel: the proxy's socket follows
                withTimeout(10.seconds) { rig.socketsClosed.receive() }
            }
        }

    /** The tunnel's socket has no ECN, GSO or DF, answers for the target and refuses a second taker. */
    @Test fun tunnelSocketShape() =
        h3Test {
            ProxyRig(H3Pair.open(serverSettings = proxySettings)) { f -> allowAllConfig(f) }.use { rig ->
                rig.serveAll()
                val got = rig.echo(echoAt)
                val tunnel = rig.pair.client.connectUdp(template, "192.0.2.50", 5000)
                val io = tunnel.asDatagramIo()
                assertFailsWith<IllegalStateException> { tunnel.asDatagramIo() }
                assertEquals(IoCapabilities.Portable.df, io.capabilities.value.df)
                assertEquals(false, io.capabilities.value.ecnSend)
                val out = PacketBatch(2, 1500)
                val payload = "via socket".encodeToByteArray()
                out.buffer(0).copyFrom(payload, 0, 0, payload.size)
                out.setLength(0, payload.size)
                out.setAddress(0, InetSocketAddress("198.51.100.1", 9)) // any address: a tunnel has one target
                assertEquals(1, io.trySend(out))
                assertContentEquals(payload, withTimeout(5.seconds) { got.receive() })
                val into = PacketBatch(2, 1500)
                assertEquals(1, withTimeout(5.seconds) { io.receive(into) })
                assertEquals(tunnel.remoteAddress, into.address(0))
                assertEquals(
                    "echo:via socket",
                    ByteArray(into.length(0)).also { into.buffer(0).copyTo(it, 0, 0, it.size) }.decodeToString(),
                )
                out.close()
                into.close()
                io.close()
                withTimeout(10.seconds) { rig.socketsClosed.receive() }
                PacketBatch(1, 1500).use { b -> assertFailsWith<Exception> { withTimeout(5.seconds) { io.receive(b) } } }
            }
        }

    private fun allowAllConfig(f: suspend (InetSocketAddress) -> io.kuicksilver.quic.DatagramIo) =
        io.kuicksilver.http3.UdpProxyConfig(targetFilter = io.kuicksilver.http3.UdpTargetFilter.AllowAll, socketFactory = f)
}
