// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

import java.lang.management.ManagementFactory
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * The steady-state send and receive paths allocate nothing per packet. Both cores run on this thread, so a
 * window covers the sender's write + poll and the receiver's handleDatagram + read for every datagram moved.
 */
class CoreAllocationTest {
    private val mx = ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean
    private fun allocated(): Long = mx.getThreadAllocatedBytes(Thread.currentThread().threadId())

    private fun measure(reverse: Boolean, datagrams: Boolean = false, quic: io.kuicksilver.quic.QuicConfig = io.kuicksilver.quic.QuicConfig.Default, midway: (CoreLoopback) -> Unit = {}) {
        CoreLoopback(streams = 1, payload = 1200, reverse = reverse, useDatagrams = datagrams, quic = quic).use { loop ->
            assertTrue(loop.handshake(), "handshake")
            var packets = 0L
            while (packets < 10_000) packets += loop.step()                     // warm-up: windows grow, JIT settles
            packets = 0; val before = allocated()
            val trace = System.getenv("KUICKSILVER_ALLOC_TRACE") != null; var last = before; var steps = 0; val sb = StringBuilder()
            if (trace) System.err.println("window start ${java.time.Instant.now()}")
            var midwayDone = false
            while (packets < 100_000) {
                packets += loop.step(); steps++
                if (!midwayDone && packets >= 50_000) { midwayDone = true; midway(loop) }
                if (trace) { val a = allocated(); if (a != last) { sb.append("step ").append(steps).append(" pkts ").append(packets).append(" +").append(a - last).append(" B received ").append(loop.bytesReceived).append('\n'); last = a } }
            }
            val bytes = allocated() - before
            println("allocation gate (${if (reverse) "server→client" else "client→server"}${if (datagrams) ", datagrams" else ""}): $bytes bytes over $packets packets in $steps steps, ${loop.bytesReceived shr 20} MiB received")
            if (trace) System.err.println("window end ${java.time.Instant.now()}\nallocating steps:\n$sb")
            // 12 KiB per 100 000 packets: the steady state allocates nothing; what remains is the sent-packet pool growing and the connection ID rotation
            // every 10 000 packets (a fresh ID, its reset token and the RETIRE_CONNECTION_ID bookkeeping, about 500 bytes each; RFC 9000 section 5.1)
            assertTrue(bytes <= 12_288, "allocated $bytes bytes over $packets packets (${bytes.toDouble() / packets} bytes/packet); " +
                "find the sites with JFR: -XX:StartFlightRecording and the jdk.ObjectAllocationSample event")
            assertTrue(loop.bytesReceived > 0, "data flowed")
        }
    }

    @Test fun steadyStateSendPathAllocatesZero() = measure(reverse = false)       // client writes, server reads
    @Test fun steadyStateReceivePathAllocatesZero() = measure(reverse = true)     // server writes, client reads
    /** A key update in the middle of the window (RFC 9001 section 6): the next keys were precomputed, the switch itself allocates nothing per packet. */
    @Test fun steadyStateWithKeyUpdateAllocatesZero() = measure(reverse = false, midway = { assertTrue(it.initiateKeyUpdate(), "key update allowed after the handshake and an acknowledged packet") })
    /** DATAGRAM frames through [io.kuicksilver.quic.DatagramSender] and `readDatagram` (RFC 9221) instead of streams. */
    @Test fun steadyStateDatagramsAllocatesZero() = measure(reverse = false, datagrams = true)
    /** CUBIC with HyStart++ (RFC 9438) stated explicitly, the default controller of `QuicConfig`. */
    @Test fun steadyStateCubicAllocatesZero() = measure(reverse = false, quic = io.kuicksilver.quic.quicConfig { congestionController = { io.kuicksilver.quic.Cubic() } })
}
