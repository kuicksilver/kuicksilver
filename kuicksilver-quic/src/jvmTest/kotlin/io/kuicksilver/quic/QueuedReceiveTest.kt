// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.KslUdpSocket
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.time.Duration.Companion.seconds

/**
 * The sockets' side of the drain before an idle close ([QueuedReceive], RFC 9000 section 10.1) on real loopback sockets, the
 * accelerated one (`ksl`: recvmsg on Linux, Android and Darwin, WSARecvMsg on Windows) and the portable JVM channel: what the
 * kernel queued is taken without waiting, and a receive in flight can be ended without a datagram. Every socket here is
 * bound to 127.0.0.1 by the test, and every datagram goes to one of them.
 */
class QueuedReceiveTest {
    private val lo = InetSocketAddress("127.0.0.1", 0)

    private fun accelerated(): Boolean {
        KslLoader.ensureLoaded()
        return KslUdpSocket.supported
    }

    private suspend fun open(accelerated: Boolean): DatagramIo =
        if (accelerated) {
            checkNotNull(KslDatagramIo.open(lo))
        } else {
            DatagramIo.open(lo, IoPreference.Portable)
        }

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

    private fun queuedAreTakenWithoutWaiting(accelerated: Boolean): Unit =
        runBlocking {
            val a = open(accelerated)
            val b = open(accelerated)
            val inb = PacketBatch(16)
            try {
                val q = assertIs<QueuedReceive>(b)
                assertEquals(0, q.receiveQueued(inb), "an empty socket answers at once")
                send(a, b, 3)
                withTimeout(5.seconds) {
                    // loopback delivery is not instant on every system: looked at again until all three are there, never waited on
                    while (inb.count < 3) {
                        q.receiveQueued(inb)
                        yield()
                    }
                }
                assertEquals(3, inb.count)
                assertEquals(listOf(40, 41, 42), (0 until 3).map { inb.length(it) })
                assertEquals(a.localAddress.port, inb.address(0)!!.port)
                assertEquals(3, inb.count, "no more than was sent")
            } finally {
                inb.close()
                a.close()
                b.close()
            }
        }

    private fun interruptEndsAReceiveInFlight(accelerated: Boolean): Unit =
        runBlocking {
            val a = open(accelerated)
            val b = open(accelerated)
            val inb = PacketBatch(16)
            try {
                // undispatched: the receive has started (and cleared any earlier interrupt) by the time async returns
                val r = async(Dispatchers.Default, start = CoroutineStart.UNDISPATCHED) { b.receive(inb) }
                (b as QueuedReceive).interruptReceive()
                assertEquals(0, withTimeout(5.seconds) { r.await() }, "the receive ended without a datagram")
                // the socket goes on: the next receive waits for the next datagram, which the interrupt does not cancel
                val next = async(Dispatchers.Default, start = CoroutineStart.UNDISPATCHED) { b.receive(inb) }
                send(a, b, 1)
                assertEquals(1, withTimeout(5.seconds) { next.await() })
            } finally {
                inb.close()
                a.close()
                b.close()
            }
        }

    @Test fun acceleratedQueuedDatagramsAreTakenWithoutWaiting() {
        assumeTrue(accelerated(), "needs the accelerated socket (Linux, macOS, Windows)")
        queuedAreTakenWithoutWaiting(true)
    }

    @Test fun portableQueuedDatagramsAreTakenWithoutWaiting() = queuedAreTakenWithoutWaiting(false)

    @Test fun acceleratedInterruptEndsAReceiveInFlight() {
        assumeTrue(accelerated(), "needs the accelerated socket (Linux, macOS, Windows)")
        interruptEndsAReceiveInFlight(true)
    }

    @Test fun portableInterruptEndsAReceiveInFlight() = interruptEndsAReceiveInFlight(false)
}
