// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.time.Duration.Companion.seconds

/**
 * The sockets' side of the drain before an idle close (RFC 9000 section 10.1) on Kotlin/Native, real loopback: the
 * accelerated `ksl` socket and the portable ktor-network one, whose queue is the channel ktor's own receiver fills. Every
 * socket is bound to 127.0.0.1 here and every datagram goes to one of them.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class QueuedReceiveNativeTest {
    private val lo = InetSocketAddress("127.0.0.1", 0)

    private suspend fun send(
        from: DatagramIo,
        to: DatagramIo,
        count: Int,
    ) {
        val out = PacketBatch(count)
        try {
            for (i in 0 until count) {
                out.buffer(i).copyFrom(ByteArray(40 + i) { (it + i).toByte() }, 0, 0, 40 + i)
                out.setLength(i, 40 + i)
                out.setAddress(i, to.localAddress)
            }
            assertEquals(count, from.send(out))
        } finally {
            out.close()
        }
    }

    private fun queuedAndInterrupt(prefer: IoPreference): Unit =
        runBlocking {
            // the portable socket itself: DatagramIo.open refuses it (no DF, no QUIC), the class is still tested
            val a: DatagramIo = if (prefer == IoPreference.Portable) KtorDatagramIo.open(lo) else DatagramIo.open(lo, prefer)
            val b: DatagramIo = if (prefer == IoPreference.Portable) KtorDatagramIo.open(lo) else DatagramIo.open(lo, prefer)
            val inb = PacketBatch(16)
            try {
                val q = assertIs<QueuedReceive>(b)
                send(a, b, 3)
                withTimeout(5.seconds) {
                    // looked at again until all three are there, never waited on
                    while (inb.count < 3) {
                        q.receiveQueued(inb)
                        yield()
                    }
                }
                assertEquals(listOf(40, 41, 42), (0 until 3).map { inb.length(it) })
                inb.clear()
                val r = async(Dispatchers.Default, start = CoroutineStart.UNDISPATCHED) { b.receive(inb) }
                q.interruptReceive()
                assertEquals(0, withTimeout(5.seconds) { r.await() }, "the receive in flight ended without a datagram")
                val next = async(Dispatchers.Default, start = CoroutineStart.UNDISPATCHED) { b.receive(inb) }
                send(a, b, 1)
                assertEquals(1, withTimeout(5.seconds) { next.await() })
            } finally {
                inb.close()
                a.close()
                b.close()
            }
        }

    @Test fun acceleratedQueuedAndInterrupted() = queuedAndInterrupt(IoPreference.Accelerated)

    @Test fun portableQueuedAndInterrupted() = queuedAndInterrupt(IoPreference.Portable)
}
