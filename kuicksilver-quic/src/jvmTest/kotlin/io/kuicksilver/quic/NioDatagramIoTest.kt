// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.toByteArray
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalKuicksilverApi::class)
class NioDatagramIoTest {
    private fun batchOf(
        vararg payloads: ByteArray,
        to: InetSocketAddress,
    ): PacketBatch {
        val b = PacketBatch(payloads.size)
        payloads.forEachIndexed {
            i,
            p,
            ->
            b.buffer(i).copyFrom(p, 0, 0, p.size)
            b.setLength(i, p.size)
            b.setAddress(i, to)
        }
        return b
    }

    // the portable transport on purpose: on Linux the default is the accelerated one (KslDatagramIoTest)
    private suspend fun pair(): Pair<DatagramIo, DatagramIo> =
        DatagramIo.open(InetSocketAddress("127.0.0.1", 0), IoPreference.Portable) to
            DatagramIo.open(InetSocketAddress("127.0.0.1", 0), IoPreference.Portable)

    @Test fun loopbackSendReceive() =
        runBlocking {
            val (a, b) = pair()
            try {
                val out = batchOf(byteArrayOf(1, 2, 3), ByteArray(1200) { 7 }, byteArrayOf(9), to = b.localAddress)
                assertEquals(3, a.send(out))
                val inb = PacketBatch(8)
                var got = 0
                withTimeout(5.seconds) {
                    while (got < 3) {
                        inb.clear()
                        got += b.receive(inb)
                    }
                }
                assertEquals(3, got)
                assertEquals(a.localAddress.port, inb.address(0)!!.port)
                out.close()
                inb.close()
            } finally {
                a.close()
                b.close()
            }
        }

    @Test fun trySendDoesNotSuspend() =
        runBlocking {
            val (a, b) = pair()
            try {
                val out = batchOf(byteArrayOf(4), to = b.localAddress)
                assertEquals(1, a.trySend(out))
                out.close()
            } finally {
                a.close()
                b.close()
            }
        }

    @Test fun portableCapabilities() =
        runBlocking {
            val (a, _) = pair()
            try {
                val c = a.capabilities.value
                // ECT(0) through IP_TOS where the JDK can set it. Windows 11 refuses IP_TOS on a DatagramChannel (SocketException) and
                // the socket then reports no ECN; Windows Server 2025 (the GitHub runner) accepts it. Either way ecnSend matches what
                // IP_TOS holds (nioSetsIpTosEct0); elsewhere it is always on
                if (!onWindows) assertTrue(c.ecnSend, "ecnSend on ${System.getProperty("os.name")}")
                assertFalse(c.ecnReceive)
                assertEquals(1, c.gsoMaxSegments)
                assertFalse(c.gro)
                assertFalse(c.df)
                assertEquals(1, c.batch)
            } finally {
                a.close()
            }
        }

    @Test fun nioSetsIpTosEct0() =
        runBlocking {
            // ADR-0006: the portable socket marks everything it sends ECT(0) through IP_TOS where the platform lets it set the option;
            // it cannot read marks, so ecnReceive stays false. Capability-consistent: ecnSend is reported exactly when IP_TOS holds ECT(0)
            val (a, _) = pair()
            try {
                val c = a.capabilities.value
                assertFalse(c.ecnReceive)
                if (c.ecnSend) {
                    assertEquals(2, (a as io.kuicksilver.quic.NioDatagramIo).ipTosForTest())
                } else {
                    assertTrue(onWindows, "only Windows (11, not Server 2025) refuses IP_TOS on a DatagramChannel")
                    val tos = runCatching { (a as io.kuicksilver.quic.NioDatagramIo).ipTosForTest() }.getOrDefault(0)
                    assertEquals(0, tos and 3, "no ECN codepoint when ecnSend is off")
                }
            } finally {
                a.close()
            }
        }

    /**
     * RFC 9000 section 14 ("UDP datagrams MUST NOT be fragmented at the IP layer. In IPv4, the Don't Fragment (DF) bit MUST be
     * set if possible") and section 14.2.1 (an endpoint "MUST ignore an ICMP message that claims the PMTU has decreased below
     * QUIC's smallest allowed maximum datagram size"): on Linux the portable socket is in probe mode (`IP_PMTUDISC_PROBE`, and
     * `IPV6_PMTUDISC_PROBE` on a dual-stack socket), set through `ksl`, and never in the JDK's `IP_DONTFRAGMENT`, which is
     * `IP_PMTUDISC_DO` there; Windows the same where the system takes PROBE, and never the JDK's option (DO there too).
     * Apple has no probe mode: the JDK's option is set where the JDK has it (19 and later). Its datagrams stay within 1200
     * bytes, so PMTUD stays off (`df` capability false). The forged-ICMP attack itself is `test_udp.c`
     * `udp_fd_df_probe_forged_ptb` (Linux: a raw socket in a user and network namespace of its own); on Windows it cannot be
     * reproduced over loopback, which ignores the cached path MTU (checked on a Windows 11 VM against a real peer instead).
     */
    @Test fun nioSetsDontFragmentWherePossible() =
        runBlocking {
            val (a, b) = pair()
            try {
                a as NioDatagramIo
                val os = (System.getProperty("os.name") ?: "").lowercase()
                val granted = a.dfProbeGranted
                when {
                    os.startsWith("linux") -> {
                        assertTrue(
                            io.kuicksilver.native.KslLoader
                                .isAvailable(),
                            "the Linux test needs ksl",
                        )
                        assertTrue(granted and 1 != 0, "probe mode on the IPv4 side: $granted")
                        assertEquals(3, a.dfModeForTest(4), "IP_MTU_DISCOVER = IP_PMTUDISC_PROBE, not DO")
                        if (granted and 2 != 0) assertEquals(3, a.dfModeForTest(6), "IPV6_MTU_DISCOVER = IPV6_PMTUDISC_PROBE")
                        assertEquals(if (Runtime.version().feature() >= 19) false else null, a.dontFragmentForTest())
                    }

                    os.startsWith("mac") -> {
                        assertEquals(0, granted, "Darwin has no probe mode")
                        assertEquals(if (Runtime.version().feature() >= 19) true else null, a.dontFragmentForTest())
                    }

                    // Windows: probe mode where the system takes it; never the JDK's option (IP_PMTUDISC_DO)
                    os.startsWith("windows") -> {
                        if (granted != 0) assertEquals(3, a.dfModeForTest(4), "IP_MTU_DISCOVER = IP_PMTUDISC_PROBE")
                        assertEquals(if (Runtime.version().feature() >= 19) false else null, a.dontFragmentForTest())
                    }
                }
                assertFalse(a.capabilities.value.df)
                // a 1200-byte datagram still goes out and arrives whole
                val out = batchOf(ByteArray(1200) { 9 }, to = b.localAddress)
                assertEquals(1, a.send(out))
                val inb = PacketBatch(1)
                withTimeout(5.seconds) { while (b.receive(inb) == 0) continue }
                assertEquals(1200, inb.length(0))
                out.close()
                inb.close()
            } finally {
                a.close()
                b.close()
            }
        }

    /**
     * The mode choice per OS and probe outcome: the JDK's `IP_DONTFRAGMENT` (`IP_PMTUDISC_DO` on Linux and Windows) only where
     * probe mode was not granted and the system is neither Linux (Android reports Linux) nor Windows.
     */
    @Test fun jdkDontFragmentOnlyWithoutProbeModeOutsideLinuxAndWindows() {
        val choose = NioDatagramIo.Companion::usesJdkDontFragment
        for (os in listOf("Linux", "Windows 11", "Windows Server 2025")) {
            assertFalse(choose(os, 0), "$os without probe mode (no ksl): the system's default, not DO")
            assertFalse(choose(os, 1), "$os with probe mode")
            assertFalse(choose(os, 3), "$os with probe mode on both halves")
        }
        assertTrue(choose("Mac OS X", 0), "Apple: IP_DONTFRAG, no modes")
        assertFalse(choose("Mac OS X", 1), "probe mode granted wins anywhere")
        assertTrue(choose("FreeBSD", 0), "another system without probe mode")
    }

    @Test fun nioClearsTosAfterValidationFailure() =
        runBlocking {
            val (a, _) = pair()
            try {
                a.disableEcnMarking()
                assertEquals(0, (a as io.kuicksilver.quic.NioDatagramIo).ipTosForTest())
                assertFalse(a.capabilities.value.ecnSend)
            } finally {
                a.close()
            }
        }

    @Test fun closeUnblocksReceive() =
        runBlocking {
            val (a, _) = pair()
            val inb = PacketBatch(4)
            val job =
                async {
                    try {
                        a.receive(inb)
                        "returned"
                    } catch (
                        e: Exception,
                    ) {
                        "failed"
                    }
                }
            a.close()
            assertTrue(withTimeout(1.seconds) { job.await() } == "failed")
            inb.close()
        }

    @Test fun emptyDatagramDoesNotStopReceive() =
        runBlocking {
            val (a, b) = pair()
            try {
                val out = batchOf(ByteArray(0), ByteArray(10) { 3 }, to = b.localAddress)
                assertEquals(2, a.send(out))
                val inb = PacketBatch(4)
                var got = ByteArray(0)
                withTimeout(5.seconds) {
                    while (got.size !=
                        10
                    ) {
                        inb.clear()
                        val n = b.receive(inb)
                        for (i in 0 until n) {
                            if (inb.length(i) ==
                                10
                            ) {
                                got = inb.buffer(i).toByteArray(10)
                            }
                        }
                    }
                }
                assertContentEquals(ByteArray(10) { 3 }, got)
                out.close()
                inb.close()
            } finally {
                a.close()
                b.close()
            }
        }

    @Test fun stableAddressReusesInstance() =
        runBlocking {
            val (a, b) = pair()
            try {
                val out = batchOf(byteArrayOf(1), byteArrayOf(2), to = b.localAddress)
                a.send(out)
                val inb = PacketBatch(1)
                val seen = ArrayList<InetSocketAddress>()
                withTimeout(5.seconds) {
                    while (seen.size < 2) {
                        inb.clear()
                        if (b.receive(inb) == 1) seen += inb.address(0)!!
                    }
                }
                assertSame(seen[0], seen[1])
                out.close()
                inb.close()
            } finally {
                a.close()
                b.close()
            }
        }
}

private val onWindows: Boolean = System.getProperty("os.name").orEmpty().startsWith("Windows")
