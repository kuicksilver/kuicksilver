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
                // ECT(0) through IP_TOS where the JDK can set it; Windows refuses IP_TOS on a DatagramChannel (SocketException), so
                // there the socket reports no ECN rather than claiming marks it cannot send
                assertEquals(!onWindows, c.ecnSend, "ecnSend on ${System.getProperty("os.name")}")
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
                    assertTrue(onWindows, "only Windows refuses IP_TOS on a DatagramChannel")
                    val tos = runCatching { (a as io.kuicksilver.quic.NioDatagramIo).ipTosForTest() }.getOrDefault(0)
                    assertEquals(0, tos and 3, "no ECN codepoint when ecnSend is off")
                }
            } finally {
                a.close()
            }
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
