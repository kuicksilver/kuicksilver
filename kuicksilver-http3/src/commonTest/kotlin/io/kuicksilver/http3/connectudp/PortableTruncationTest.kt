// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.connectudp

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.UdpProxyConfig
import io.kuicksilver.http3.UdpTargetFilter
import io.kuicksilver.http3.connectUdp
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.IoPreference
import io.kuicksilver.quic.PacketBatch
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * RFC 9298 section 5 carries "the unmodified payload of a UDP packet": a target datagram larger than the proxy's link MTU
 * is dropped whole, never forwarded cut. The portable sockets (NIO on the JVM, ktor-network on Kotlin/Native) truncate a
 * datagram to their slot; the proxy's slot is one byte longer than the link carries, so a cut one is recognised. HTTP/3
 * datagrams are off, so a payload of any size would reach the client as a DATAGRAM capsule.
 */
class PortableTruncationTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun negative_aTargetDatagramAboveTheLinkMtuIsDroppedNotCut() =
        h3Test {
            val off = http3Settings { h3Datagram = false }
            val pair =
                H3Pair.open(
                    serverSettings =
                        http3Settings {
                            enableConnectProtocol = true
                            h3Datagram = false
                        },
                    clientSettings = off,
                )
            val proxySocket = CompletableDeferred<DatagramIo>()
            val loopback = InetSocketAddress("127.0.0.1", 0)
            val target = DatagramIo.open(loopback, IoPreference.Portable)
            val rig =
                ProxyRig(pair) { _ ->
                    UdpProxyConfig(
                        targetFilter = UdpTargetFilter.addresses("127.0.0.1"),
                        socketFactory = { DatagramIo.open(loopback, IoPreference.Portable).also { proxySocket.complete(it) } },
                    )
                }
            rig.serveAll()
            try {
                rig.use { r ->
                    val t = r.pair.client.connectUdp(template, "127.0.0.1", target.localAddress.port)
                    val to = InetSocketAddress("127.0.0.1", withTimeout(5.seconds) { proxySocket.await() }.localAddress.port)
                    PacketBatch(1, 2048).use { b ->
                        for (size in listOf(1600, 5)) {
                            b.count = 0
                            b.buffer(0).copyFrom(ByteArray(size) { 7 }, 0, 0, size)
                            b.setLength(0, size)
                            b.setAddress(0, to)
                            target.send(b)
                        }
                    }
                    // the 5-byte one arrives; the 1600-byte one was dropped whole, not cut to the link's 1500
                    assertEquals(5, withTimeout(10.seconds) { t.payloads.first() }.size)
                    assertEquals(1, rig.proxy.stats.droppedTooLargeFromTarget)
                    t.close()
                }
            } finally {
                target.close()
            }
        }
}
