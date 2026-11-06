// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.DirectReceive
import io.kuicksilver.quic.IoCapabilities
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.TimeMark
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.runBlocking
import java.lang.management.ManagementFactory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration

/** The loop takes a flowing socket's batches on its own thread without allocating per batch: no coroutine frame, no boxed time (P.2). */
class BatchReceiverAllocationTest {
    /** One datagram per receive, never blocking. */
    private class OneEach :
        DatagramIo,
        DirectReceive {
        override val localAddress = InetSocketAddress("10.0.0.1", 1)
        override val capabilities: StateFlow<IoCapabilities> = MutableStateFlow(IoCapabilities.Portable)

        override suspend fun receive(into: PacketBatch): Int = 1

        override fun receiveNow(
            into: PacketBatch,
            waitMs: Int,
        ): Int = 1

        override suspend fun send(batch: PacketBatch): Int = batch.count

        override fun trySend(batch: PacketBatch): Int = batch.count

        override fun close() {}
    }

    @Test fun aFlowingBatchAllocatesNothing() =
        runBlocking {
            val mx = ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean
            val batch = PacketBatch(16)
            var t = 1_000_000_000L
            // a clock that stands still apart from the receiver's own reads: no 1 ms yield falls into the window
            val r = BatchReceiver(OneEach(), { TimeMark(t) }, Duration.ZERO)
            val horizon = BatchReceiver.TimerHorizon { Duration.INFINITE }
            r.receive(batch, horizon) // the blocking receive starts the flow
            // as the loop does: the direct part, and the suspending receive when it says so (a yield every 16 datagrams). Only
            // the direct calls are measured, cold (no JIT warm-up), so escape analysis cannot hide a frame or a box that the
            // loop's large method would allocate
            var direct = 0
            var bytes = 0L
            repeat(400) {
                val before = mx.currentThreadAllocatedBytes
                val n = r.receiveDirect(batch, horizon)
                val after = mx.currentThreadAllocatedBytes
                if (n > 0) {
                    direct++
                    bytes += after - before
                } else {
                    assertEquals(BatchReceiver.NOT_TRIED, n)
                    r.receive(batch, horizon)
                }
            }
            assertTrue(direct >= 350, "$direct direct batches")
            // a frame of the suspending receive and a boxed Duration and TimeMark are 100+ bytes per batch (38 000+ here); the JIT's
            // tiering steps allocate a few hundred bytes now and then, once
            assertTrue(bytes <= 1024, "$direct direct batches allocated $bytes bytes")
            t += 1
        }
}
