// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * CONNECT-UDP (RFC 9298) against our own proxy over real UDP on loopback, with OpenSSL: a UDP echo through the tunnel,
 * then HTTP/3 to a real HTTP/3 server through it (proxied QUIC). The proxy may reach only 127.0.0.1, and every socket is
 * bound there.
 */
class RealUdpConnectUdpTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val loopback = InetSocketAddress("127.0.0.1", 0)

    /** The proxy's target sockets. */
    private val opened = java.util.concurrent.CopyOnWriteArrayList<DatagramIo>()

    private suspend fun proxyServer(): Pair<Http3Endpoint, UdpProxy> {
        val endpoint =
            Http3Endpoint.bind(
                loopback,
                QuicEndpointConfig
                    .Builder()
                    .apply { server = QuicServerConfig.Builder(H3Fixtures.server()).build() }
                    .build(),
                http3Settings { enableConnectProtocol = true },
            )
        val proxy =
            UdpProxy(
                UdpProxyConfig(
                    targetFilter = UdpTargetFilter.addresses("127.0.0.1"),
                    socketFactory = { DatagramIo.open(loopback).also { opened += it } },
                ),
            )
        return endpoint to proxy
    }

    private fun kotlinx.coroutines.CoroutineScope.serve(
        endpoint: Http3Endpoint,
        proxy: UdpProxy,
    ) = launch {
        val conn = endpoint.accept()
        coroutineScope {
            while (true) {
                val r = conn.acceptRequest()
                launch { proxy.serve(r) }
            }
        }
    }

    @Test fun udpEchoThroughTheProxy() =
        runBlocking {
            withTimeout(60.seconds) {
                val (proxyEndpoint, proxy) = proxyServer()
                val echo = DatagramIo.open(loopback)
                val client = Http3Endpoint.bind(loopback)
                try {
                    val serving = serve(proxyEndpoint, proxy)
                    val echoing =
                        launch {
                            PacketBatch(4, 1500).use { b ->
                                while (true) {
                                    b.count = 0
                                    echo.receive(b)
                                    for (i in 0 until b.count) {
                                        val answer = "echo:".encodeToByteArray() + b.buffer(i).toByteArray(b.length(i))
                                        b.buffer(i).copyFrom(answer, 0, 0, answer.size)
                                        b.setLength(i, answer.size) // back to the sender: the slot keeps its address
                                    }
                                    echo.send(b)
                                }
                            }
                        }
                    val conn = client.connect(proxyEndpoint.localAddress, H3Fixtures.client())
                    val tunnel = conn.connectUdp(UdpProxyTemplate.wellKnown("server.test"), "127.0.0.1", echo.localAddress.port)
                    tunnel.send("over real UDP".encodeToByteArray())
                    assertContentEquals("echo:over real UDP".encodeToByteArray(), withTimeout(10.seconds) { tunnel.payloads.first() })
                    assertEquals(1, proxy.stats.toTargets)
                    // RFC 9298 section 3.1: "In IPv4, the Don't Fragment (DF) bit MUST be set, if possible": the default,
                    // accelerated socket sets it (the portable one cannot)
                    assertEquals(
                        true,
                        opened
                            .single()
                            .capabilities.value.df,
                    )
                    tunnel.close()
                    withTimeout(10.seconds) { proxy.activeTunnels.first { it == 0 } }
                    echoing.cancel()
                    serving.cancel()
                    conn.close()
                } finally {
                    client.close()
                    echo.close()
                    proxyEndpoint.close()
                }
            }
        }

    @Test fun http3ThroughTheProxyOverRealUdp() =
        runBlocking {
            withTimeout(60.seconds) {
                val (proxyEndpoint, proxy) = proxyServer()
                val target =
                    Http3Endpoint.bind(
                        loopback,
                        QuicEndpointConfig
                            .Builder()
                            .apply { server = QuicServerConfig.Builder(H3Fixtures.server()).build() }
                            .build(),
                    )
                val client = Http3Endpoint.bind(loopback)
                val seen = CompletableDeferred<InetSocketAddress>()
                try {
                    val serving = serve(proxyEndpoint, proxy)
                    val targetServing =
                        launch {
                            val c = target.accept()
                            val r = c.acceptRequest()
                            seen.complete(r.remoteAddress)
                            val w = r.respond(200)
                            w.output.writeStringUtf8("proxied ${r.path}")
                            w.finish()
                        }
                    val conn = client.connect(proxyEndpoint.localAddress, H3Fixtures.client())
                    val tunnel = conn.connectUdp(UdpProxyTemplate.wellKnown("server.test"), "127.0.0.1", target.localAddress.port)
                    val inner = Http3Endpoint.bind(loopback, QuicEndpointConfig.Builder().apply { io = { tunnel.asDatagramIo() } }.build())
                    try {
                        val h3 = withTimeout(30.seconds) { inner.connect(tunnel.remoteAddress, H3Fixtures.client()) }
                        val response = withTimeout(10.seconds) { h3.request(http3Request("GET", "server.test", "/masque")) }
                        assertEquals(200, response.status)
                        assertEquals("proxied /masque", response.body.readAllBytes().decodeToString())
                        // the target's peer is the proxy's socket, not the client's
                        assertEquals(false, seen.await().port == client.localAddress.port)
                        h3.close()
                    } finally {
                        inner.close()
                    }
                    targetServing.cancel()
                    serving.cancel()
                    conn.close()
                } finally {
                    client.close()
                    target.close()
                    proxyEndpoint.close()
                }
            }
        }
}

/** The privilege probe of RFC 9298 section 6.1's Packet Too Big against the real `ksl`: never on macOS or Windows; on Linux only with CAP_NET_RAW. */
class PacketTooBigProbeTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun probeMatchesThePlatform() {
        val p =
            io.kuicksilver.quic.PacketTooBigSender
                .probe()
        val os = System.getProperty("os.name").lowercase()
        if (!os.contains("linux")) assertEquals(false, p.available, p.reason)
        // a message is built by the native code, whatever the privilege (nothing is sent)
        val out = ByteArray(io.kuicksilver.native.KslConst.ICMP_PTB_MAX)
        val target =
            ByteArray(20).also {
                it[0] = 4
                it[1] = 1
                it[2] = 0xbb.toByte()
                it[3] = 198.toByte()
                it[4] = 51
                it[5] = 100
                it[6] =
                    7
            }
        val local =
            ByteArray(20).also {
                it[0] = 4
                it[1] = 0xc3.toByte()
                it[2] = 0x50
                it[3] = 192.toByte()
                it[4] = 0
                it[5] = 2
                it[6] =
                    1
            }
        assertEquals(
            8 + 20 + 8 + 1400 - 880,
            io.kuicksilver.native.Ksl
                .icmpPtbBuild(out, target, local, ByteArray(1400), 1400, 1280),
        )
        assertEquals(3, out[0].toInt())
        assertEquals(
            0,
            io.kuicksilver.native.Ksl
                .icmpPtbBuild(out, target, local, ByteArray(10), 10, 1280),
            "an MTU above the datagram",
        )
    }
}
