// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.EcnState
import io.kuicksilver.quic.api.readExactly
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.KslUdpSocket
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The accelerated transport (ADR-0006) on real Linux, macOS and Windows loopback (GSO/GRO on Linux; USO/URO and ECN on Windows
 * only where the Windows version grants them, so those assertions follow the granted capabilities there); elsewhere `open`
 * answers null and the tests report skipped (JUnit assumptions).
 */
class KslDatagramIoTest {
    private val lo = InetSocketAddress("127.0.0.1", 0)
    private val linux = System.getProperty("os.name").lowercase().contains("linux")
    private val windows = System.getProperty("os.name").lowercase().contains("windows")

    /** ECN on [io]: always on Linux and macOS, on Windows only when IP_ECN was granted (10 2004+ / Server 2022). */
    private fun ecnExpected(io: KslDatagramIo): Boolean = !windows || io.capabilities.value.let { it.ecnSend && it.ecnReceive }

    /** Whether this host's accelerated socket marks and reads ECN (a throwaway socket's grant). */
    private fun hostEcn(): Boolean = assertNotNull(KslDatagramIo.open(lo)).let { io -> ecnExpected(io).also { io.close() } }

    private fun ready(): Boolean {
        KslLoader.ensureLoaded()
        return KslUdpSocket.supported
    }

    @Test fun loopbackBatchSendReceive() =
        runBlocking {
            assumeTrue(ready(), "needs the accelerated socket (Linux, macOS, Windows)")
            val a = assertNotNull(KslDatagramIo.open(lo))
            val b = assertNotNull(KslDatagramIo.open(lo))
            try {
                val out = PacketBatch(32)
                for (i in 0 until 32) {
                    val n =
                        100 + i * 37
                    out.buffer(i).copyFrom(ByteArray(n) { (it + i).toByte() }, 0, 0, n)
                    out.setLength(i, n)
                    out.setAddress(i, b.localAddress)
                }
                assertEquals(32, a.send(out))
                val inb = PacketBatch(32)
                withTimeout(5.seconds) { while (inb.count < 32) b.receive(inb) }
                for (i in 0 until 32) {
                    val n =
                        100 + i * 37
                    assertEquals(n, inb.length(i))
                    assertContentEquals(ByteArray(n) { (it + i).toByte() }, inb.buffer(i).toByteArray(n))
                    assertEquals(a.localAddress.port, inb.address(i)!!.port)
                }
                out.close()
                inb.close()
            } finally {
                a.close()
                b.close()
            }
        }

    /** A wildcard bind is dual-stack, as NIO: a client on 0.0.0.0:0 reaches an IPv6 server and an IPv4 one, and IPv4 peers come back as IPv4 (review of k7/macos-server). */
    @Test fun wildcardBindReachesBothFamilies() =
        runBlocking {
            assumeTrue(ready(), "needs the accelerated socket (Linux, macOS)")
            val v6 = runCatching { KslDatagramIo.open(InetSocketAddress("::1", 0)) }.getOrNull()
            assumeTrue(v6 != null, "needs an IPv6 loopback")
            val w = assertNotNull(KslDatagramIo.open(InetSocketAddress("0.0.0.0", 0)))
            val v4 = assertNotNull(KslDatagramIo.open(lo))
            try {
                assertContentEquals(ByteArray(4), w.localAddress.resolveAddress(), "0.0.0.0 asked, 0.0.0.0 reported")
                for ((peer, to) in listOf(
                    v4 to InetSocketAddress("127.0.0.1", v4.localAddress.port),
                    v6!! to InetSocketAddress("::1", v6.localAddress.port),
                )) {
                    val out = PacketBatch(1)
                    out.buffer(0).copyFrom(ByteArray(40) { 7 }, 0, 0, 40)
                    out.setLength(0, 40)
                    out.setAddress(0, to)
                    assertEquals(1, w.send(out), "send to $to")
                    val inb = PacketBatch(1)
                    withTimeout(5.seconds) { while (inb.count < 1) peer.receive(inb) }
                    assertEquals(40, inb.length(0), "received from 0.0.0.0 at $to")
                    val back = inb.address(0)!!
                    assertEquals(w.localAddress.port, back.port)
                    out.setAddress(0, InetSocketAddress(if (peer === v4) "127.0.0.1" else "::1", w.localAddress.port))
                    assertEquals(1, peer.send(out))
                    val reply = PacketBatch(1)
                    withTimeout(5.seconds) { while (reply.count < 1) w.receive(reply) }
                    val from = reply.address(0)!!
                    assertEquals(peer.localAddress.port, from.port)
                    assertContentEquals(
                        if (peer ===
                            v4
                        ) {
                            byteArrayOf(127, 0, 0, 1)
                        } else {
                            ByteArray(16) {
                                if (it ==
                                    15
                                ) {
                                    1
                                } else {
                                    0
                                }
                            }
                        },
                        from.resolveAddress(),
                        "an IPv4 peer is IPv4, not v4-mapped",
                    )
                    out.close()
                    inb.close()
                    reply.close()
                }
            } finally {
                w.close()
                v4.close()
                v6!!.close()
            }
        }

    /** A refused accelerated socket (a sandbox, limits) falls back to the portable one instead of failing the bind (review of k7/macos-server). */
    @Test fun refusedSocketFallsBackToPortable() =
        runBlocking {
            assumeTrue(ready(), "needs the accelerated socket (Linux, macOS)")
            val real = KslDatagramIo.socketOpener
            val unassigned = KslUdpSocket.encodeAddress(byteArrayOf(192.toByte(), 0, 2, 1), 0)
            var refused = 0
            KslDatagramIo.socketOpener = { _, f, failed ->
                refused++
                KslUdpSocket.openOrNull(unassigned, f, failed)
            } // EADDRNOTAVAIL from the kernel, as an EPERM from a sandbox would be
            try {
                val io = DatagramIo.open(lo)
                try {
                    assertEquals(1, refused)
                    assertTrue(io !is KslDatagramIo, "portable socket expected, got $io")
                    assertTrue(io.localAddress.port != 0)
                } finally {
                    io.close()
                }
            } finally {
                KslDatagramIo.socketOpener = real
            }
        }

    @Test fun capabilitiesReportAccelerated() =
        runBlocking {
            assumeTrue(ready(), "needs the accelerated socket (Linux, macOS, Windows)")
            val a = assertNotNull(KslDatagramIo.open(lo))
            try {
                val c = a.capabilities.value
                if (windows) {
                    assertEquals(c.ecnSend, c.ecnReceive, "ecn both ways or not at all")
                } else {
                    assertTrue(c.ecnSend && c.ecnReceive, "ecn")
                    assertEquals(linux, c.gsoMaxSegments >= 2, "gso on Linux only")
                    assertEquals(linux, c.gro, "gro on Linux only")
                }
                assertTrue(c.df, "df")
                assertTrue(c.batch >= 16, "batch")
            } finally {
                a.close()
            }
        }

    @Test fun gsoCoalescesSameDestination() =
        runBlocking {
            assumeTrue(ready(), "needs the accelerated socket (Linux, macOS, Windows)")
            val a = assertNotNull(KslDatagramIo.open(lo))
            val b = assertNotNull(KslDatagramIo.open(lo))
            try {
                if (linux) assertTrue(a.capabilities.value.gsoMaxSegments >= 16, "loopback grants GSO")
                val gso = a.capabilities.value.gsoMaxSegments >= 16
                val ecn = ecnExpected(a) && ecnExpected(b)
                val out = PacketBatch(16)
                for (i in 0 until 16) {
                    out.buffer(i).copyFrom(ByteArray(1200) { i.toByte() }, 0, 0, 1200)
                    out.setLength(i, 1200)
                    out.setAddress(i, b.localAddress)
                    out.setEcn(i, Ecn.Ect0)
                }
                assertEquals(16, a.send(out))
                val inb = PacketBatch(16)
                withTimeout(5.seconds) { while (inb.count < 16) b.receive(inb) }
                for (i in 0 until 16) {
                    assertEquals(1200, inb.length(i))
                    assertEquals(i.toByte(), inb.buffer(i)[0])
                    if (ecn) assertEquals(Ecn.Ect0, inb.ecn(i))
                }
                assertEquals(
                    if (gso) 1L else 16L,
                    a.statsForTest().sendSyscalls,
                    "one sendmsg for the run (Linux GSO, Windows USO), one per datagram on Darwin",
                )
                out.close()
                inb.close()
            } finally {
                a.close()
                b.close()
            }
        }

    @Test fun ecnSurvivesLoopback() =
        runBlocking {
            assumeTrue(ready(), "needs the accelerated socket (Linux, macOS, Windows)")
            val a = assertNotNull(KslDatagramIo.open(lo))
            val b = assertNotNull(KslDatagramIo.open(lo))
            try {
                assumeTrue(ecnExpected(a) && ecnExpected(b), "Windows without IP_ECN (before 10 2004 / Server 2022)")
                val out = PacketBatch(3)
                val marks = listOf(Ecn.Ect0, Ecn.Ce, Ecn.NotEct)
                for (i in 0 until 3) {
                    out.buffer(i).copyFrom(byteArrayOf(1, 2, 3), 0, 0, 3)
                    out.setLength(i, 3)
                    out.setAddress(i, b.localAddress)
                    out.setEcn(i, marks[i])
                }
                assertEquals(3, a.send(out))
                val inb = PacketBatch(3)
                withTimeout(5.seconds) { while (inb.count < 3) b.receive(inb) }
                val got = (0 until 3).map { inb.ecn(it) }
                if (windows) {
                    // Windows 11 does not carry a CE the sender asks for over loopback (it arrives Not-ECT); a QUIC sender never
                    // sets CE (RFC 9000 section 13.4.1), routers do, so the granted capability is ECT(0) written and read back
                    assertEquals(listOf(Ecn.Ect0, Ecn.NotEct), listOf(got[0], got[2]))
                    assertTrue(got[1] == Ecn.Ce || got[1] == Ecn.NotEct, "CE sent over Windows loopback arrived as ${got[1]}")
                } else {
                    assertEquals(marks, got)
                }
                a.disableEcnMarking()
                out.clear()
                out.buffer(0).copyFrom(byteArrayOf(9), 0, 0, 1)
                out.setLength(0, 1)
                out.setAddress(0, b.localAddress)
                out.setEcn(0, Ecn.Ect0)
                assertEquals(1, a.send(out))
                inb.clear()
                withTimeout(5.seconds) { while (inb.count < 1) b.receive(inb) }
                assertEquals(
                    Ecn.Ect0,
                    inb.ecn(0),
                    "marks are per datagram: one failed path does not stop the socket marking (runtime review I7)",
                )
                assertTrue(a.capabilities.value.ecnSend)
                out.close()
                inb.close()
            } finally {
                a.close()
                b.close()
            }
        }

    @Test fun peerAddressInstanceReused() =
        runBlocking {
            assumeTrue(ready(), "needs the accelerated socket (Linux, macOS, Windows)")
            val a = assertNotNull(KslDatagramIo.open(lo))
            val b = assertNotNull(KslDatagramIo.open(lo))
            try {
                val out = PacketBatch(1)
                out.buffer(0).copyFrom(byteArrayOf(1), 0, 0, 1)
                out.setLength(0, 1)
                out.setAddress(0, b.localAddress)
                val inb = PacketBatch(4)
                assertEquals(1, a.send(out))
                withTimeout(5.seconds) { while (inb.count < 1) b.receive(inb) }
                val first = inb.address(0)!!
                inb.clear()
                assertEquals(1, a.send(out))
                withTimeout(5.seconds) { while (inb.count < 1) b.receive(inb) }
                assertSame(first, inb.address(0), "the same InetSocketAddress instance for the same peer")
                out.close()
                inb.close()
            } finally {
                a.close()
                b.close()
            }
        }

    @Test fun closeUnblocksReceive() =
        runBlocking {
            assumeTrue(ready(), "needs the accelerated socket (Linux, macOS, Windows)")
            val a = assertNotNull(KslDatagramIo.open(lo))
            val inb = PacketBatch(4)
            val r = async { runCatching { a.receive(inb) } }
            delay(100)
            a.close()
            val outcome = withTimeoutOrNull(3.seconds) { r.await() }
            assertNotNull(outcome, "receive returned after close")
            assertTrue(outcome.isFailure, "a closed transport throws from receive")
            inb.close()
        }

    /** Focus 5: the lossless GSO fallback itself is driven by a C test hook (`udp_gso_eio_falls_back_and_resends`); here a socket that never lost GSO reports no fallback and keeps its capability. */
    @Test fun gsoFallbackCounterStartsAtZero() =
        runBlocking {
            assumeTrue(ready(), "needs the accelerated socket (Linux, macOS, Windows)")
            val a = assertNotNull(KslDatagramIo.open(lo))
            val b = assertNotNull(KslDatagramIo.open(lo))
            try {
                val out = PacketBatch(8)
                for (i in 0 until 8) {
                    out.buffer(i).copyFrom(ByteArray(1200) { i.toByte() }, 0, 0, 1200)
                    out.setLength(i, 1200)
                    out.setAddress(i, b.localAddress)
                }
                repeat(300) { assertEquals(8, a.send(out)) } // past the capability refresh interval
                assertEquals(0L, a.statsForTest().gsoFallbacks)
                if (linux) assertTrue(a.capabilities.value.gsoMaxSegments >= 2, "capabilities refreshed and GSO still on")
                out.close()
            } finally {
                a.close()
                b.close()
            }
        }

    @Test fun realUdpServerClient50MiBAccelerated() =
        runBlocking {
            assumeTrue(ready(), "needs the accelerated socket (Linux, macOS, Windows)")
            val ecnOnHost = hostEcn()
            val server =
                QuicEndpoint.bind(
                    lo,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig.Builder(CoreFixtures.server()).build()
                            ; crypto = KslQuicCrypto
                        }.build(),
                )
            val client = QuicEndpoint.bind(lo, QuicEndpointConfig.Builder().apply { crypto = KslQuicCrypto }.build())
            try {
                withTimeout(180.seconds) {
                    val accepted = async { server.accept() }
                    val c = client.connect(server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    val s = accepted.await()
                    val data = ByteArray(50 shl 20) { (it * 7).toByte() }
                    val sink =
                        async {
                            val st = s.acceptStream()
                            st.input.readExactly(data.size)
                        }
                    val st = c.openBidi()
                    launch {
                        st.output.writeFully(data, 0, data.size)
                        st.output.flushAndClose()
                    }
                    assertContentEquals(data, sink.await())
                    if (ecnOnHost) {
                        assertEquals(EcnState.Capable, c.stats.ecnState, "ECN validated over the accelerated socket")
                        assertEquals(EcnState.Capable, s.stats.ecnState)
                    }
                    assertEquals(1452, c.stats.pathMtu, "PMTUD reached the loopback ceiling")
                    assertEquals(1452, s.stats.pathMtu)
                    c.close()
                    s.close()
                }
            } finally {
                client.close()
                server.close()
            }
        }

    @Test fun oneClientBleachingEcnLeavesOthersCapable() =
        runBlocking {
            // client A's path bleaches ECN, so the server's validation for A fails; B, on the same accelerated server socket, still validates
            assumeTrue(ready(), "needs the accelerated socket (Linux, macOS, Windows)")
            assumeTrue(hostEcn(), "Windows without IP_ECN (before 10 2004 / Server 2022)")
            val server =
                QuicEndpoint.bind(
                    lo,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig.Builder(CoreFixtures.server()).build()
                            ; crypto = KslQuicCrypto
                        }.build(),
                )
            val bleaching =
                QuicEndpoint.bind(
                    lo,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            crypto = KslQuicCrypto
                            io =
                                { local ->
                                    val inner = KslDatagramIo.open(local)!!
                                    object : DatagramIo by inner {
                                        override suspend fun receive(into: PacketBatch): Int {
                                            val from = into.count
                                            val n = inner.receive(into)
                                            for (i in from until
                                                from + n) {
                                                into.setEcn(i, Ecn.NotEct)
                                            }
                                            return n
                                        }
                                    }
                                }
                        }.build(),
                )
            val clean = QuicEndpoint.bind(lo, QuicEndpointConfig.Builder().apply { crypto = KslQuicCrypto }.build())
            try {
                withTimeout(120.seconds) {
                    suspend fun transfer(client: QuicEndpoint): Pair<QuicConnection, QuicConnection> {
                        val accepted = async { server.accept() }
                        val c = client.connect(server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                        val s = accepted.await()
                        val data = ByteArray(2 shl 20) { it.toByte() }
                        val sink = async { s.acceptStream().input.readExactly(data.size) }
                        val st = c.openBidi()
                        st.output.writeFully(data, 0, data.size)
                        st.output.flushAndClose()
                        sink.await()
                        return c to s
                    }
                    val (ca, sa) = transfer(bleaching)
                    assertTrue(
                        sa.stats.ecnState == EcnState.Failed,
                        "the server's validation for the bleaching client failed: ${sa.stats.ecnState}",
                    )
                    val (cb, sb) = transfer(clean)
                    assertEquals(EcnState.Capable, cb.stats.ecnState)
                    assertEquals(EcnState.Capable, sb.stats.ecnState, "the server still marks for the other client")
                    ca.close()
                    sa.close()
                    cb.close()
                    sb.close()
                }
            } finally {
                bleaching.close()
                clean.close()
                server.close()
            }
        }

    @Test fun eightyIdleEndpointsDoNotStarveTheEightyFirst() =
        runBlocking {
            // an idle accelerated socket must not pin a Dispatchers.IO thread (64 by default) for its lifetime
            assumeTrue(ready(), "needs the accelerated socket (Linux, macOS, Windows)")
            val server =
                QuicEndpoint.bind(
                    lo,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig.Builder(CoreFixtures.server()).build()
                            ; crypto = KslQuicCrypto
                        }.build(),
                )
            val clients = List(80) { QuicEndpoint.bind(lo, QuicEndpointConfig.Builder().apply { crypto = KslQuicCrypto }.build()) }
            try {
                withTimeout(30.seconds) {
                    val accepted = async { server.accept() }
                    val c = clients.last().connect(server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    val s = accepted.await()
                    c.close()
                    s.close()
                }
            } finally {
                clients.forEach { it.close() }
                server.close()
            }
        }

    @Test fun openPrefersAcceleratedWhereItExists() =
        runBlocking {
            assumeTrue(ready(), "needs the accelerated socket (Linux, macOS, Windows)")
            val io = DatagramIo.open(lo)
            try {
                assertTrue(io is KslDatagramIo, "accelerated by default")
            } finally {
                io.close()
            }
            val p = DatagramIo.open(lo, IoPreference.Portable)
            try {
                assertTrue(p !is KslDatagramIo)
            } finally {
                p.close()
            }
        }
}
