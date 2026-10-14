// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.PacketBatch
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * A poll ends after one send quantum (RFC 9002 section 7.7, ten datagrams); with window and data left, the connection must
 * ask to be polled again when the pacer allows the next datagram. It did not: the next datagrams waited for the next packet
 * from the peer, so an upload ran at about one quantum per ACK, half the window in flight (20 datagrams in a 40-datagram
 * window in the simulator's 40 ms scenario), and the controller, seeing an application-limited sender, never grew it.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class SendContinuationTest {
    @Test fun quantumLimitedPollArmsTheNextSend() {
        val p = CorePair()
        val batch = PacketBatch(64)
        try {
            assertTrue(p.handshake())
            val c = p.client
            val id = c.openStream(true)
            var written = 0L
            // grow the window well above one quantum
            p.runUntil(limit = 3.seconds, tick = 10.milliseconds) {
                written += c.writeStream(id, ByteArray(16384), 0, 16384, false)
                c.stats.cwnd >= 40 * 1200
            }
            assertTrue(c.stats.cwnd >= 40 * 1200, "cwnd ${c.stats.cwnd}")
            p.runUntil(limit = 2.seconds, tick = 10.milliseconds) { c.stats.bytesInFlight == 0L }
            c.writeStream(id, ByteArray(200_000), 0, 200_000, false)
            val n = c.poll(batch, p.now)
            var bytes = 0L
            for (i in 0 until n) bytes += batch.length(i)
            assertTrue(bytes >= 9 * 1200 && c.stats.bytesInFlight < c.stats.cwnd, "one quantum out ($bytes bytes), window left")
            val next = c.nextTimeout()
            assertTrue(
                next != null && next - p.now <= c.stats.smoothedRtt / 4,
                "next send at ${next?.let { it - p.now }}, srtt ${c.stats.smoothedRtt}",
            )
        } finally {
            batch.close()
            p.close()
        }
    }
}
