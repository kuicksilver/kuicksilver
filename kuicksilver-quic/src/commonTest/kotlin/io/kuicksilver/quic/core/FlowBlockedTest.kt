// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.TestFrame
import io.kuicksilver.quic.nullOneRttFrames
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * An upload whose window updates travel a lossy return path (RFC 9000 section 4.1): when the last MAX_DATA / MAX_STREAM_DATA
 * before the sender runs dry is lost, the sender has nothing in flight and the receiver's only copy waits behind its PTO
 * backoff. DATA_BLOCKED / STREAM_DATA_BLOCKED, answered at once and repeated when lost, and PTO probes that carry the update,
 * keep the transfer moving.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class FlowBlockedTest {
    /** Uploads [size] bytes while 75 % of the server's ack-eliciting datagrams are lost; returns the longest time without progress. */
    private fun longestStall(
        seed: Long,
        size: Int,
    ): Pair<Boolean, Duration> {
        val p = CorePair(seed = seed)
        try {
            assertTrue(p.handshake())
            p.runUntil(200.milliseconds) { false }
            val rnd = Random(seed * 7 + 3)
            // ACK-only datagrams pass, so the sender's congestion window keeps growing: what is lost is what needs acknowledging,
            // the window updates among it
            p.filterToClient = { _, b ->
                val eliciting = nullOneRttFrames(b)?.any { it !is TestFrame.Ack && it !is TestFrame.Padding } ?: true
                !eliciting || rnd.nextDouble() >= 0.75
            }
            val id = p.client.openStream(bidi = true, StreamPriority.Default)
            val data = ByteArray(65536)
            val buf = ByteArray(65536)
            var written = 0L
            var read = 0L
            var lastProgress = p.now
            var stall = Duration.ZERO
            val done =
                p.runUntil(60.seconds) {
                    while (written < size) {
                        val n = p.client.writeStream(id, data, 0, minOf(data.size.toLong(), size - written).toInt(), false)
                        if (n <= 0) break
                        written += n
                    }
                    while (true) {
                        val n = p.server!!.readStream(id, buf, 0, buf.size)
                        if (n <= 0) break
                        read += n
                        if (p.now - lastProgress > stall) stall = p.now - lastProgress
                        lastProgress = p.now
                    }
                    read >= size
                }
            if (p.now - lastProgress > stall) stall = p.now - lastProgress
            return done to stall
        } finally {
            p.close()
        }
    }

    @Test fun lostWindowUpdatesDoNotStallAnUpload() {
        val stalls = (1L..8L).map { seed -> seed to longestStall(seed, 8 shl 20) }
        for ((seed, r) in stalls) {
            assertTrue(r.first && r.second < 2.seconds, "seed $seed: delivered ${r.first}, longest stall ${r.second}; all: $stalls")
        }
    }

    @Test fun negative_dataBlockedFloodIsRateLimited() {
        // a peer repeating stale DATA_BLOCKED frames gets one MAX_DATA per RTT, and spends a glitch token for every other one
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.runUntil(300.milliseconds) { false }
            var maxData = 0
            p.filterToClient = { _, b ->
                maxData += nullOneRttFrames(b)?.count { it is TestFrame.MaxData } ?: 0
                true
            }
            p.client.testInjectDataBlocked = 1100
            assertTrue(p.runUntil(limit = 1.seconds) { p.closedReason(p.serverEvents) != null }, "the server closes within the second")
            val r = assertIs<QuicException.ConnectionLost.TransportClosed>(p.closedReason(p.serverEvents))
            assertEquals(0x0aL, r.code)
            assertEquals(Initiator.Local, r.initiator)
            assertTrue(maxData <= 3, "MAX_DATA answers: $maxData")
        } finally {
            p.close()
        }
    }
}
