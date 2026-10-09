// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.native.KslException
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import kotlin.concurrent.thread
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The accelerated UDP socket (ADR-0006) over `ksl_udp_*`: Linux delivers batches with ECN; elsewhere `open` says so. */
class KslUdpSocketTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
    }

    private fun loopback() = KslUdpSocket.encodeAddress(byteArrayOf(127, 0, 0, 1), 0)

    @Test fun openSendReceive() {
        if (!KslUdpSocket.supported) return // Apple, Windows: covered by openOnUnsupportedPlatformThrows
        KslUdpSocket.open(loopback(), KslUdpSocket.ECN or KslUdpSocket.GSO or KslUdpSocket.GRO).use { a ->
            KslUdpSocket.open(loopback(), KslUdpSocket.ECN or KslUdpSocket.GRO).use { b ->
                val n = 8
                val bufs = Array(n) { PacketBuffer.allocate(1500) }
                val lens = IntArray(n) { 1200 }
                val addrs = ByteArray(n * KslUdpSocket.ADDR_LEN) { i -> b.localAddress[i % KslUdpSocket.ADDR_LEN] }
                val ecn = ByteArray(n) { 2 }
                for (i in 0 until n) bufs[i].copyFrom(ByteArray(1200) { i.toByte() }, 0, 0, 1200)
                assertEquals(n, a.send(bufs, lens, addrs, ecn, n))
                val rb = Array(n) { PacketBuffer.allocate(1500) }
                val rl = IntArray(n)
                val ra = ByteArray(n * KslUdpSocket.ADDR_LEN)
                val re = ByteArray(n)
                var got = 0
                while (got <
                    n
                ) {
                    val r = b.receive(rb, rl, ra, re, n, 2000)
                    assertTrue(r > 0, "receive timed out with $got of $n")
                    got += r
                }
                assertEquals(n, got)
                for (i in 0 until n) {
                    assertEquals(1200, rl[i])
                    assertEquals(2, re[i].toInt(), "ECT(0) on slot $i")
                    assertEquals(
                        a.localAddress.toList(),
                        ra.copyOfRange(i * KslUdpSocket.ADDR_LEN, (i + 1) * KslUdpSocket.ADDR_LEN).toList(),
                    )
                }
                val one = ByteArray(1200)
                rb[0].copyTo(one, 0, 0, 1200)
                assertTrue(one.all { it == one[0] })
            }
        }
    }

    @Test fun grantedFlagsOnLinux() {
        if (!KslUdpSocket.supported) return // Apple, Windows: covered by openOnUnsupportedPlatformThrows
        KslUdpSocket.open(loopback(), KslUdpSocket.ECN or KslUdpSocket.GSO or KslUdpSocket.GRO or KslUdpSocket.DF).use { s ->
            val f = s.grantedFlags
            assertTrue(f and KslUdpSocket.ECN != 0, "ECN")
            assertTrue(f and KslUdpSocket.DF != 0, "DF")
            assertTrue(f and KslUdpSocket.GSO != 0, "GSO")
            assertTrue(f and KslUdpSocket.GRO != 0, "GRO")
            assertTrue(s.gsoMaxSegments >= 2)
            assertTrue(s.fd >= 0)
            assertEquals(4, s.localAddress[0].toInt())
            assertTrue(KslUdpSocket.portOf(s.localAddress) > 0)
        }
    }

    @Test fun closeUnblocksReceive() {
        if (!KslUdpSocket.supported) return // Apple, Windows: covered by openOnUnsupportedPlatformThrows
        val s = KslUdpSocket.open(loopback(), 0)
        val bufs = Array(1) { PacketBuffer.allocate(64) }
        var result = -2
        var elapsed = 0L
        val t =
            thread {
                val t0 = System.nanoTime()
                result =
                    s.receive(bufs, IntArray(1), ByteArray(KslUdpSocket.ADDR_LEN), ByteArray(1), 1, 5000)
                elapsed =
                    (System.nanoTime() - t0) / 1_000_000
            }
        Thread.sleep(50)
        s.close()
        t.join(2000)
        assertEquals(0, result, "a woken receive answers 0")
        assertTrue(elapsed < 1000, "woke after $elapsed ms")
        assertTrue(s.isClosed)
        assertEquals(0, s.receive(bufs, IntArray(1), ByteArray(KslUdpSocket.ADDR_LEN), ByteArray(1), 1, 10))
    }

    /** A receive error on a socket nobody shut down throws instead of looking like a timeout (Linux only). */
    @Test fun negative_receiveErrorIsNotATimeout() {
        if (!KslUdpSocket.supported) return // Apple, Windows: no ksl_udp
        KslUdpSocket.open(loopback(), 0).use { s ->
            io.kuicksilver.native.Ksl
                .udpShutdown(s.handle) // the native socket fails underneath a wrapper that was not shut down
            assertFailsWith<KslException.Internal> {
                s.receive(Array(1) { PacketBuffer.allocate(64) }, IntArray(1), ByteArray(KslUdpSocket.ADDR_LEN), ByteArray(1), 1, 10)
            }
        }
    }

    @Test fun openOnUnsupportedPlatformThrows() {
        if (KslUdpSocket.supported) return
        val e = assertFailsWith<KslException.Internal> { KslUdpSocket.open(loopback(), 0) }
        assertEquals(io.kuicksilver.native.KslConst.E_NOT_SUPPORTED, e.packed)
    }
}
