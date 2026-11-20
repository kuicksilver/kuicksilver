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
import kotlin.test.assertFailsWith
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
     * QUIC's smallest allowed maximum datagram size"): DF on all traffic, or no QUIC. On Linux every half of the portable socket
     * is in probe mode (`IP_PMTUDISC_PROBE`, and `IPV6_PMTUDISC_PROBE` on a dual-stack socket), set through `ksl`, and the
     * JDK's `IP_DONTFRAGMENT` (DO mode there) is not added; on Windows probe mode where the system takes it, else DO; Apple has
     * no modes: `IPV6_DONTFRAG` through `ksl`, which covers v4-mapped traffic. Datagrams stay within 1200 bytes, so PMTUD stays off (`df` capability
     * false). The forged-ICMP attack itself is `test_udp.c` `udp_fd_df_probe_forged_ptb` (Linux: a raw socket in a user and
     * network namespace of its own); on Windows it cannot be reproduced over loopback, which ignores the cached path MTU
     * (checked on a Windows 11 VM against a real peer instead).
     */
    @Test fun nioSetsDontFragmentWherePossible() =
        runBlocking {
            val (a, b) = pair()
            try {
                a as NioDatagramIo
                val os = (System.getProperty("os.name") ?: "").lowercase()
                val bits = a.dfProbeGranted
                val jdk19 = Runtime.version().feature() >= 19
                when {
                    os.startsWith("linux") -> {
                        assertTrue(
                            io.kuicksilver.native.KslLoader
                                .isAvailable(),
                            "the Linux test needs ksl",
                        )
                        assertTrue(probeComplete(bits), "probe mode on every half: $bits")
                        assertEquals(3, a.dfModeForTest(4), "IP_MTU_DISCOVER = IP_PMTUDISC_PROBE, not DO")
                        if (bits and DF_INET6 != 0) assertEquals(3, a.dfModeForTest(6), "IPV6_MTU_DISCOVER = IPV6_PMTUDISC_PROBE")
                        assertEquals(if (jdk19) false else null, a.dontFragmentForTest(), "the JDK's DO mode not added")
                    }

                    os.startsWith("mac") -> {
                        assertEquals(DF_INET6 or DF_V4_DO or DF_V6_DO, bits, "Darwin: IPV6_DONTFRAG through ksl, no modes")
                        // the JDK reads Darwin's IPV6_DONTFRAG back, which ksl set
                        assertEquals(if (jdk19) true else null, a.dontFragmentForTest())
                    }

                    os.startsWith("windows") -> {
                        assertTrue(dfComplete(bits), "DF on every half, probe or DO: $bits")
                        if (bits and DF_V4 != 0) assertEquals(3, a.dfModeForTest(4), "IP_MTU_DISCOVER = IP_PMTUDISC_PROBE")
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
     * The DF choice from the [dfProbe] bits: the JDK's `IP_DONTFRAGMENT` (DO on Linux and Windows, IP_DONTFRAG on Apple) only
     * where nothing put DF on the half it covers (an AF_INET socket's only half; an AF_INET6 socket's IPv6 half), so DF is
     * always on; probe mode on every half is what meets section 14.2.1.
     */
    @Test fun dfChoicePerProbeOutcome() {
        val jdk = NioDatagramIo.Companion::usesJdkDontFragment
        assertTrue(jdk(-1), "no ksl (or no descriptor): the JDK's option")
        assertTrue(jdk(0), "Apple, or every mode refused: the JDK's option")
        assertFalse(jdk(DF_V4), "AF_INET in probe mode")
        assertFalse(jdk(DF_V4_DO), "AF_INET in DO mode through ksl")
        assertFalse(jdk(DF_INET6 or DF_V4 or DF_V6), "dual-stack, both halves in probe mode")
        assertTrue(jdk(DF_INET6 or DF_V4), "dual-stack, the IPv6 half without DF: the JDK's option covers it")
        assertFalse(jdk(DF_INET6 or DF_V4 or DF_V6_DO), "dual-stack, the IPv6 half in DO mode")
        assertFalse(jdk(DF_INET6 or DF_V6), "the JDK's option would not reach the IPv4 half anyway (it sets IPV6_MTU_DISCOVER)")
        assertTrue(probeComplete(DF_V4) && probeComplete(DF_INET6 or DF_V4 or DF_V6))
        assertFalse(probeComplete(DF_INET6 or DF_V4), "dual-stack with only the V4 bit: not complete")
        assertFalse(probeComplete(DF_V4_DO) || probeComplete(0) || probeComplete(-1))
        assertTrue(dfComplete(DF_V4_DO) && dfComplete(DF_INET6 or DF_V4 or DF_V6_DO))
        assertFalse(dfComplete(DF_INET6 or DF_V4))
    }

    /**
     * EMSGSIZE as the JDK reports it on Linux (strerror under the process's locale: also a localized text, which `ksl` gives),
     * Android and Windows; anything else is not a path MTU refusal.
     */
    @Test fun messageTooLongPerPlatform() {
        fun tooLong(
            m: String?,
            localized: String? = null,
        ) = NioDatagramIo.isMessageTooLong(java.net.SocketException(m), localized)
        assertTrue(tooLong("Message too long"), "Linux, C locale")
        assertTrue(tooLong("sendto failed: EMSGSIZE (Message too long)"), "Android")
        assertTrue(
            tooLong("sendto: The message is larger than the maximum supported by the underlying transport"),
            "Windows (net_util_md.c)",
        )
        assertTrue(tooLong("Nachricht zu lang", localized = "Nachricht zu lang"), "Linux, de_DE: strerror(EMSGSIZE) through ksl")
        assertFalse(tooLong("Nachricht zu lang"), "a localized text without ksl's strerror is not recognized")
        assertFalse(tooLong("Network is unreachable", localized = "Nachricht zu lang"))
        assertFalse(tooLong(null))
        assertFalse(tooLong("", localized = ""), "an empty localized text matches nothing")
        // the system's own text in this process, where ksl is loaded
        val own = localizedEmsgsizeText()
        if (own != null) assertTrue(tooLong(own, localized = own))
    }

    /**
     * A refusal as too large fails the path only when the retry is refused too: a connected socket's one-shot ICMP error (Linux
     * `sk_err`, even in probe mode) passes the retry; DO mode refuses both. Larger datagrams and other errors propagate as they are.
     */
    @Test fun aRefusalFailsThePathOnlyWhenTheRetryIsRefusedToo() {
        val to = InetSocketAddress("127.0.0.1", 9)
        val tooLong = java.net.SocketException("Message too long")
        var calls = 0
        assertEquals(1200, NioDatagramIo.sendRefusalAware(1200, to, null) { if (calls++ == 0) throw tooLong else 1200 })
        assertEquals(2, calls, "one retry after a one-shot refusal")
        calls = 0
        val e =
            assertFails {
                NioDatagramIo.sendRefusalAware(1200, to, null) {
                    calls++
                    throw tooLong
                }
            }
        assertTrue(e is PathMtuRefusedException && e.size == 1200 && e.destination == to, "refused twice: $e")
        // the system's refusal stays the cause, and the text names it: a CONNECT-UDP proxy recognises it as too large
        assertSame(tooLong, e.cause, "the SocketException is kept as the cause")
        assertTrue("Message too long" in e.message!! && "EMSGSIZE" in e.message!!, e.message)
        assertEquals(2, calls)
        calls = 0
        assertSame(
            tooLong,
            assertFails {
                NioDatagramIo.sendRefusalAware(1201, to, null) {
                    calls++
                    throw tooLong
                }
            },
        )
        assertEquals(1, calls, "above QUIC's floor: no retry, a lost datagram")
        val other = java.net.SocketException("Network is unreachable")
        assertSame(other, assertFails { NioDatagramIo.sendRefusalAware(100, to, null) { throw other } })
    }

    /**
     * Which traffic goes without DF (no DF, no QUIC): none, one half of a dual-stack socket (its sends are refused), or all
     * of it (open fails). The JDK's option covers an AF_INET socket, the IPv6 half of a dual-stack one on Linux and Windows,
     * and both halves on Apple (IPV6_DONTFRAG covers v4-mapped traffic there).
     */
    @Test fun noDfFamilyPerCase() {
        val f = NioDatagramIo.Companion::noDfFamily
        // (bits, the JDK's option took, AF_INET, Apple)
        assertEquals(NioDatagramIo.DF_ALL, f(DF_V4, false, true, false), "AF_INET in probe mode")
        assertEquals(NioDatagramIo.DF_ALL, f(DF_INET6 or DF_V4 or DF_V6, false, false, false), "dual-stack, both in probe mode")
        assertEquals(NioDatagramIo.DF_ALL, f(DF_INET6 or DF_V4_DO or DF_V6_DO, false, false, true), "Apple through ksl")
        assertEquals(NioDatagramIo.DF_ALL, f(-1, true, true, false), "no ksl, AF_INET: the JDK's option")
        assertEquals(NioDatagramIo.DF_ALL, f(-1, true, false, true), "no ksl, Apple: IPV6_DONTFRAG covers v4-mapped traffic")
        assertEquals(NioDatagramIo.DF_ALL, f(DF_INET6 or DF_V4, true, false, false), "the JDK's option covers the IPv6 half ksl left")
        assertEquals(4, f(-1, true, false, false), "no ksl, dual-stack on Linux or Windows: the IPv4 half has none")
        assertEquals(4, f(DF_INET6 or DF_V6, false, false, false), "the IPv4 half refused both modes")
        assertEquals(6, f(DF_INET6 or DF_V4, false, false, false), "the IPv6 half refused both modes, no JDK option")
        assertEquals(NioDatagramIo.DF_NONE, f(-1, false, false, false), "no ksl below JDK 19")
        assertEquals(NioDatagramIo.DF_NONE, f(-1, false, true, false))
        assertEquals(NioDatagramIo.DF_NONE, f(DF_INET6, false, false, false), "both halves refused both modes")
        assertTrue(NioDatagramIo.dfUnavailableDetail(-1, false).contains("below 19"))
        assertTrue(NioDatagramIo.dfUnavailableDetail(DF_INET6, false).contains("refused both"))
    }

    /**
     * A failed probe (Android: the descriptor could not be duplicated, out of file descriptors) is no lasting lack of DF: the
     * socket does not open, with `permanent = false`, so a CONNECT-UDP proxy does not remember the family; no means at all
     * (no ksl below JDK 19) is permanent.
     */
    @Test fun aFailedProbeIsNotAPermanentLackOfDf() =
        runBlocking {
            assertFalse(NioDatagramIo.dfLackPermanent(DF_PROBE_FAILED))
            assertTrue(NioDatagramIo.dfLackPermanent(-1) && NioDatagramIo.dfLackPermanent(0) && NioDatagramIo.dfLackPermanent(DF_INET6))
            assertTrue("file descriptors" in NioDatagramIo.dfUnavailableDetail(DF_PROBE_FAILED, false))
            for ((bits, permanent) in listOf(DF_PROBE_FAILED to false, -1 to true)) {
                NioDatagramIo.dfForTest = { bits to false }
                try {
                    val e =
                        assertFailsWith<QuicException.DontFragmentUnavailable> {
                            DatagramIo.open(InetSocketAddress("127.0.0.1", 0), IoPreference.Portable).close()
                        }
                    assertEquals(permanent, e.permanent, "bits $bits")
                } finally {
                    NioDatagramIo.dfForTest = null
                }
            }
        }

    /** No DF on any traffic: the socket does not open, with the typed error. */
    @Test fun negative_aSocketWithoutDfDoesNotOpen() =
        runBlocking {
            NioDatagramIo.dfForTest = { -1 to false } // no ksl, no IP_DONTFRAGMENT (below JDK 19)
            try {
                val e =
                    assertFailsWith<QuicException.DontFragmentUnavailable> {
                        DatagramIo.open(InetSocketAddress("127.0.0.1", 0), IoPreference.Portable).close()
                    }
                assertEquals(null, e.family)
                assertTrue("Don't Fragment" in e.message!!, e.message)
            } finally {
                NioDatagramIo.dfForTest = null
            }
        }

    /**
     * A dual-stack socket whose IPv4 half has no DF skips the slots to IPv4 destinations (reported to the endpoint loop, which
     * fails their path) and still carries the rest of the batch to IPv6.
     */
    @Test fun negative_aDualStackSocketWithoutDfOnItsIpv4HalfRefusesIpv4Sends() =
        runBlocking {
            NioDatagramIo.dfForTest = { inet -> if (inet) 0 to false else (DF_INET6 or DF_V6) to false }
            val a: DatagramIo
            val b: DatagramIo
            try {
                a = DatagramIo.open(InetSocketAddress("::1", 0), IoPreference.Portable)
                b = DatagramIo.open(InetSocketAddress("::1", 0), IoPreference.Portable)
            } finally {
                NioDatagramIo.dfForTest = null
            }
            try {
                assertEquals(4, (a as NioDatagramIo).noDf)
                assertEquals(IpFamily.V4, a.noDfFamily)
                val v4 = InetSocketAddress("127.0.0.1", b.localAddress.port)
                val mapped = InetSocketAddress("::ffff:127.0.0.1", b.localAddress.port)
                // IPv4, IPv6, IPv4-mapped in one batch: the IPv4 slots are skipped, the IPv6 one in between still goes
                val out = PacketBatch(3)
                for ((i, to) in listOf(v4, b.localAddress, mapped).withIndex()) {
                    out.buffer(i).copyFrom(ByteArray(100 + i), 0, 0, 100 + i)
                    out.setLength(i, 100 + i)
                    out.setAddress(i, to)
                }
                assertEquals(3, a.send(out), "the batch is done: the IPv4 slots are skipped, not left for a retry")
                assertEquals(listOf(v4, mapped), a.takeDfRefusals())
                assertEquals(emptyList(), a.takeDfRefusals(), "taken once")
                val inb = PacketBatch(1)
                withTimeout(5.seconds) { while (b.receive(inb) == 0) continue }
                assertEquals(101, inb.length(0), "the IPv6 datagram arrived")
                inb.close()
                out.close()
            } finally {
                a.close()
                b.close()
            }
        }

    /** An IPv4 bind keeps the AF_INET channel when DF took on it, else the dual-stack one, whose IPv4 sends are refused. */
    @Test fun anIpv4BindTakesAfInetOnlyWithDf() =
        runBlocking {
            val v4 = InetSocketAddress("127.0.0.1", 0)
            NioDatagramIo.dfForTest = { inet -> if (inet) -1 to true else -1 to true } // no ksl, the JDK's option takes
            try {
                DatagramIo.open(v4, IoPreference.Portable).use {
                    if ((System.getProperty("os.name") ?: "").lowercase().startsWith("mac")) {
                        // Apple: the JDK's option covers both halves of the dual-stack channel, which stays
                        assertEquals(null, (it as NioDatagramIo).noDfFamily)
                        return@use
                    }
                    // AF_INET: DF on all it can send; IPv6 is refused as without DF (it cannot reach IPv6 at all)
                    assertEquals(IpFamily.V6, (it as NioDatagramIo).noDfFamily)
                    val six = batchOf(ByteArray(10), to = InetSocketAddress("::1", 9))
                    assertEquals(1, it.send(six))
                    assertEquals(listOf(InetSocketAddress("::1", 9)), it.takeDfRefusals())
                }
            } finally {
                NioDatagramIo.dfForTest = null
            }
            NioDatagramIo.dfForTest = { inet -> if (inet) 0 to false else (DF_INET6 or DF_V6) to false } // AF_INET took nothing
            try {
                DatagramIo
                    .open(
                        v4,
                        IoPreference.Portable,
                    ).use { assertEquals(4, (it as NioDatagramIo).noDf, "the dual-stack channel stayed") }
            } finally {
                NioDatagramIo.dfForTest = null
            }
        }

    /**
     * The channel family: an AF_INET channel is tried for an IPv4 bind whose dual-stack channel has no DF on its IPv4 half
     * (the JDK's option sets only the IPv6 half on Linux and Windows), and kept only when DF took on it.
     */
    @Test fun inetChannelOnlyWhereItGetsDf() {
        val tries = NioDatagramIo.Companion::triesInet
        // (bits of the dual-stack channel, local is IPv6, Apple, the JDK has the option)
        assertTrue(tries(-1, false, false, true), "no ksl, IPv4 bind: the JDK's option reaches IPv4 only on AF_INET")
        assertTrue(tries(DF_INET6 or DF_V6, false, false, true), "ksl, IPv4 half refused both modes")
        assertTrue(tries(DF_INET6 or DF_V6_DO, false, false, true))
        assertFalse(tries(DF_INET6 or DF_V4 or DF_V6, false, false, true), "probe mode on both halves")
        assertFalse(tries(DF_INET6 or DF_V4 or DF_V6_DO, false, false, true), "DF on both halves")
        assertFalse(tries(DF_INET6 or DF_V4, false, false, true), "the IPv4 half has DF; the JDK's option covers the IPv6 half")
        assertFalse(tries(-1, true, false, true), "an IPv6 bind stays dual-stack")
        assertFalse(tries(-1, false, true, true), "Apple: its option covers v4-mapped traffic")
        assertFalse(tries(-1, false, false, false), "no JDK option (below JDK 19, Android): AF_INET gains nothing")
        assertFalse(tries(DF_V4, false, false, true), "already AF_INET with DF")
        val keeps = NioDatagramIo.Companion::keepsInet
        assertTrue(keeps(-1, true), "no ksl: the JDK's option took")
        assertTrue(keeps(DF_V4, false), "ksl: probe mode on AF_INET")
        assertTrue(keeps(DF_V4_DO, false), "ksl: DO mode on AF_INET")
        assertFalse(keeps(0, false), "both modes refused and no JDK option: the dual-stack channel stays")
        assertFalse(keeps(-1, false), "the JDK's option did not take")
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
