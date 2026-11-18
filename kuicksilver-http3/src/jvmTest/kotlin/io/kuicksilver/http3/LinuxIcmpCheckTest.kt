// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, InternalKuicksilverApi::class)

package io.kuicksilver.http3

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.ipLiteral
import io.kuicksilver.tls.KslIcmp
import io.kuicksilver.tls.KslUdpSocket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The CONNECT-UDP proxy's ICMP paths on Linux with the privilege to open raw sockets (CAP_NET_RAW), end to end over real
 * UDP on 127.0.0.1: RFC 9298 section 6.1's Packet Too Big as the kernel of the target takes it, and section 3.1's closing
 * on a port unreachable, which a forged one (RFC 8085 section 5.2) does not do. Run by tools/interop/icmp-linux-check.sh
 * in the Linux image with `--cap-add=NET_RAW` (KSL_ICMP_LINUX_CHECK=1); elsewhere each test says it was skipped.
 */
class LinuxIcmpCheckTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val loopback = InetSocketAddress("127.0.0.1", 0)
    private val lo = byteArrayOf(127, 0, 0, 1)

    /** Whether this run is the Linux check; there the privilege is required, not skipped. */
    private fun enabled(name: String): Boolean {
        if (System.getenv("KSL_ICMP_LINUX_CHECK") != "1") {
            println("$name skipped: run by tools/interop/icmp-linux-check.sh (Linux, CAP_NET_RAW)")
            return false
        }
        val probe =
            io.kuicksilver.quic.PacketTooBigSender
                .probe()
        assertTrue(probe.available, "the Linux check needs raw ICMP sockets: ${probe.reason}")
        return true
    }

    /**
     * A proxy on 127.0.0.1 reaching 127.0.0.1 only, its target sockets bound to [targetBind] and kept in [opened]; a client
     * connection to it.
     */
    private class Rig(
        val endpoint: Http3Endpoint,
        val proxy: UdpProxy,
        val client: Http3Endpoint,
        val opened: java.util.concurrent.CopyOnWriteArrayList<DatagramIo>,
    )

    private suspend fun <T> withProxy(
        targetBind: InetSocketAddress = loopback,
        block: suspend CoroutineScope.(Rig, Http3Connection) -> T,
    ): T {
        val opened = java.util.concurrent.CopyOnWriteArrayList<DatagramIo>()
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
                    refuseOwnAddresses = false, // proxy and target share this host's loopback by construction
                    socketFactory = { DatagramIo.open(targetBind).also { opened += it } },
                ),
            )
        proxy.impl.unreachablePoll = 50.milliseconds
        val client = Http3Endpoint.bind(loopback)
        return try {
            coroutineScope {
                val serving =
                    launch {
                        val conn = endpoint.accept()
                        coroutineScope {
                            while (true) {
                                val r = conn.acceptRequest()
                                launch { proxy.serve(r) }
                            }
                        }
                    }
                val conn = client.connect(endpoint.localAddress, H3Fixtures.client())
                try {
                    block(Rig(endpoint, proxy, client, opened), conn)
                } finally {
                    serving.cancel()
                    conn.close()
                }
            }
        } finally {
            client.close()
            endpoint.close()
        }
    }

    /** A target socket of our own (DF, so its error queue takes the Packet Too Big), on 127.0.0.1. */
    private fun target(): KslUdpSocket = KslUdpSocket.open(KslUdpSocket.encodeAddress(lo, 0), KslUdpSocket.DF)

    private fun KslUdpSocket.port(): Int = KslUdpSocket.portOf(localAddress)

    private fun KslUdpSocket.sendTo(
        to: InetSocketAddress,
        payload: ByteArray,
    ) {
        PacketBuffer.allocate(payload.size).use { b ->
            b.copyFrom(payload, 0, 0, payload.size)
            assertEquals(1, send(arrayOf(b), intArrayOf(payload.size), KslUdpSocket.encodeAddress(lo, to.port), byteArrayOf(0), 1))
        }
    }

    /** One receive call on [s] (which drains its error queue), [ms] at most. */
    private fun KslUdpSocket.pump(ms: Int) {
        PacketBuffer.allocate(2048).use { b ->
            receive(arrayOf(b), IntArray(1), ByteArray(KslUdpSocket.ADDR_LEN), ByteArray(1), 1, ms)
        }
    }

    /**
     * Section 6.1: a target datagram too large for the client's DATAGRAM frames is dropped and answered with a Packet Too
     * Big from the proxy socket's address; the target's kernel takes it as one for the datagram it sent (so its checksum,
     * quote and addresses are right), with the MTU the client can carry. The proxy socket here is bound to 127.0.0.1, so
     * the message leaves from the socket's own address.
     */
    @Test fun packetTooBigReachesTheTarget() =
        runBlocking {
            if (!enabled("packetTooBigReachesTheTarget")) return@runBlocking
            packetTooBigReaches(loopback)
        }

    /**
     * The same from a proxy socket on the wildcard address, as the default socketFactory binds: the message leaves from the
     * destination the socket reported for the datagram (IP_PKTINFO), 127.0.0.1.
     */
    @Test fun packetTooBigFromAWildcardSocketReachesTheTarget() =
        runBlocking {
            if (!enabled("packetTooBigFromAWildcardSocketReachesTheTarget")) return@runBlocking
            packetTooBigReaches(InetSocketAddress("0.0.0.0", 0))
        }

    private suspend fun packetTooBigReaches(targetBind: InetSocketAddress) {
        withTimeout(60.seconds) {
            withProxy(targetBind) { rig, conn ->
                val t = target()
                try {
                    val tunnel = conn.connectUdp(UdpProxyTemplate.wellKnown("server.test"), "127.0.0.1", t.port())
                    tunnel.send("hi".encodeToByteArray()) // the proxy's socket exists once the tunnel carried one
                    val proxySocket = rig.opened.single().localAddress
                    // a wildcard socket has no address of its own to answer from: what arrives came from the datagram's
                    assertEquals(targetBind.ipLiteral(), proxySocket.ipLiteral(), "the proxy socket bound as asked")
                    val payload = ByteArray(1400) { (0x40 + it % 64).toByte() }
                    t.sendTo(proxySocket, payload)
                    val quote = ByteArray(KslUdpSocket.PTB_QUOTE)
                    val meta = IntArray(2)
                    val dst = ByteArray(KslUdpSocket.ADDR_LEN)
                    // off the runBlocking thread: the receive blocks, and the proxy and both endpoints run there
                    val took =
                        withContext(Dispatchers.IO) {
                            withTimeoutOrNull(20.seconds) {
                                while (!t.takePacketTooBig(quote, meta, dst)) {
                                    ensureActive() // the receives do not suspend: the timeout ends the loop here
                                    t.pump(50)
                                }
                                true
                            } ?: false
                        }
                    assertTrue(took, "no Packet Too Big reached the target; proxy stats: ${rig.proxy.stats}")
                    assertEquals(1, rig.proxy.stats.packetTooBigSent)
                    assertEquals(0, rig.proxy.stats.packetTooBigNoSource)
                    assertEquals(0, rig.proxy.stats.packetTooBigFailed)
                    assertEquals(PacketTooBigStatus.Available, rig.proxy.stats.packetTooBig)
                    assertTrue(meta[1] in 1200 until payload.size + 28, "the MTU the client carries: ${meta[1]}")
                    assertContentEquals(payload.copyOf(meta[0]), quote.copyOf(meta[0]), "the quote: our datagram's start")
                    assertEquals(proxySocket.port, KslUdpSocket.portOf(dst), "for the datagram sent to the proxy socket")
                    tunnel.close()
                } finally {
                    t.close()
                }
            }
        }
    }

    /** Section 3.1: the kernel's port unreachable for a closed target port (quoting what the tunnel sent) closes the tunnel. */
    @Test fun aRealPortUnreachableClosesTheTunnel() =
        runBlocking {
            if (!enabled("aRealPortUnreachableClosesTheTunnel")) return@runBlocking
            withTimeout(60.seconds) {
                withProxy { rig, conn ->
                    val closed = target().let { s -> s.port().also { s.close() } } // a port of ours, closed now
                    val tunnel = conn.connectUdp(UdpProxyTemplate.wellKnown("server.test"), "127.0.0.1", closed)
                    tunnel.send("to a closed port".encodeToByteArray())
                    val e = assertFailsWith<Throwable> { withTimeout(10.seconds) { tunnel.stream.capsules.toList() } }
                    assertEquals(
                        Http3ErrorCode.CONNECT_ERROR,
                        io.kuicksilver.http3.connectudp
                            .h3Code(e),
                        "$e",
                    )
                    assertEquals(1, rig.proxy.stats.closedUnreachable)
                }
            }
        }

    /**
     * RFC 8085 section 5.2: a forged port unreachable (right addresses and ports, a payload the tunnel never sent) is
     * ignored and the tunnel keeps working; one quoting what it sent closes it, so the forged one did reach the proxy.
     */
    @Test fun aForgedPortUnreachableIsIgnored() =
        runBlocking {
            if (!enabled("aForgedPortUnreachableIsIgnored")) return@runBlocking
            withTimeout(60.seconds) {
                withProxy { rig, conn ->
                    val echo = DatagramIo.open(loopback)
                    try {
                        val echoing =
                            launch {
                                PacketBatch(4, 1500).use { b ->
                                    while (true) {
                                        b.count = 0
                                        echo.receive(b)
                                        echo.send(b) // back to the sender: the slots keep their addresses
                                    }
                                }
                            }
                        val tunnel = conn.connectUdp(UdpProxyTemplate.wellKnown("server.test"), "127.0.0.1", echo.localAddress.port)
                        tunnel.send("real payload".encodeToByteArray())
                        assertContentEquals("real payload".encodeToByteArray(), withTimeout(10.seconds) { tunnel.payloads.first() })
                        val proxyPort =
                            rig.opened
                                .single()
                                .localAddress.port
                        forgePortUnreachable(proxyPort, echo.localAddress.port, "forged!".encodeToByteArray())
                        withTimeout(10.seconds) {
                            rig.proxy.impl.changes
                                .first { rig.proxy.stats.ignoredUnreachable >= 1 }
                        }
                        tunnel.send("still open".encodeToByteArray())
                        assertContentEquals("still open".encodeToByteArray(), withTimeout(10.seconds) { tunnel.payloads.first() })
                        assertEquals(0, rig.proxy.stats.closedUnreachable)
                        forgePortUnreachable(proxyPort, echo.localAddress.port, "real pay".encodeToByteArray())
                        assertFailsWith<Throwable> { withTimeout(10.seconds) { tunnel.stream.capsules.toList() } }
                        assertEquals(1, rig.proxy.stats.closedUnreachable)
                        echoing.cancel()
                    } finally {
                        echo.close()
                    }
                }
            }
        }

    /**
     * An ICMP port unreachable (type 3 code 3) to 127.0.0.1:[proxyPort], quoting the IPv4 and UDP headers of a datagram
     * 127.0.0.1:[proxyPort] -> 127.0.0.1:[targetPort] and [payload], sent through a raw socket as an off-path forger would.
     */
    private fun forgePortUnreachable(
        proxyPort: Int,
        targetPort: Int,
        payload: ByteArray,
    ) {
        val ip = ByteArray(20)
        ip[0] = 0x45
        val total = 28 + payload.size
        ip[2] = (total ushr 8).toByte()
        ip[3] = total.toByte()
        ip[6] = 0x40
        ip[8] = 64
        ip[9] = 17
        lo.copyInto(ip, 12)
        lo.copyInto(ip, 16)
        checksum(ip).let {
            ip[10] = (it ushr 8).toByte()
            ip[11] = it.toByte()
        }
        val udp = ByteArray(8)
        udp[0] = (proxyPort ushr 8).toByte()
        udp[1] = proxyPort.toByte()
        udp[2] = (targetPort ushr 8).toByte()
        udp[3] = targetPort.toByte()
        udp[4] = ((8 + payload.size) ushr 8).toByte()
        udp[5] = (8 + payload.size).toByte()
        val msg = byteArrayOf(3, 3, 0, 0, 0, 0, 0, 0) + ip + udp + payload
        checksum(msg).let {
            msg[2] = (it ushr 8).toByte()
            msg[3] = it.toByte()
        }
        val fd = KslIcmp.open(4, IntArray(1))
        assertTrue(fd >= 0, "a raw ICMP socket")
        try {
            val to = KslUdpSocket.encodeAddress(lo, proxyPort)
            val from = KslUdpSocket.encodeAddress(lo, 0)
            assertTrue(KslIcmp.send(fd, msg, msg.size, to, from), "the forged message sent")
        } finally {
            KslIcmp.close(fd)
        }
    }

    /** RFC 1071. */
    private fun checksum(b: ByteArray): Int {
        var s = 0L
        var i = 0
        while (i + 1 < b.size) {
            s += ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)
            i += 2
        }
        if (b.size % 2 == 1) s += (b[b.size - 1].toInt() and 0xff) shl 8
        while (s ushr 16 != 0L) s = (s and 0xffff) + (s ushr 16)
        return (s.inv() and 0xffff).toInt()
    }
}
