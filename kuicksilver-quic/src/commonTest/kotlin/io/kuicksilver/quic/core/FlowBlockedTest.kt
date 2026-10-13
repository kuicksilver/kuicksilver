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
import kotlin.math.ceil
import kotlin.math.ln
import kotlin.math.pow
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
    private companion object {
        /** Share of the server's ack-eliciting datagrams the return path loses. */
        const val LOSS = 0.75
    }

    private class Upload(
        val delivered: Boolean,
        val longestStall: Duration,
        /** The longest stall in units of the largest PTO seen during it, the unit the repeat timer schedules in. */
        val longestStallPtos: Double,
        val episodes: Int,
    )

    /**
     * Uploads [size] bytes while a [LOSS] share of the server's ack-eliciting datagrams is lost; returns the longest time without
     * progress and the number of flow-control limits the client reported being blocked at (episodes).
     */
    private fun upload(
        seed: Long,
        size: Int,
    ): Upload {
        val p = CorePair(seed = seed)
        try {
            assertTrue(p.handshake())
            p.runUntil(200.milliseconds) { false }
            val rnd = Random(seed * 7 + 3)
            // ACK-only datagrams pass, so the sender's congestion window keeps growing: what is lost is what needs acknowledging,
            // the window updates among it
            p.filterToClient = { _, b ->
                val eliciting = nullOneRttFrames(b)?.any { it !is TestFrame.Ack && it !is TestFrame.Padding } ?: true
                !eliciting || rnd.nextDouble() >= LOSS
            }
            val id = p.client.openStream(bidi = true, StreamPriority.Default)
            val data = ByteArray(65536)
            val buf = ByteArray(65536)
            var written = 0L
            var read = 0L
            var lastProgress = p.now
            var stall = Duration.ZERO
            var stallPtos = 0.0
            var pto = Duration.ZERO // largest PTO since the last progress

            fun progress() {
                val d = p.now - lastProgress
                if (d > stall) stall = d
                (d / pto).let { if (it > stallPtos) stallPtos = it }
                lastProgress = p.now
                pto = Duration.ZERO
            }
            val done =
                p.runUntil(60.seconds) {
                    p.client.pto().let { if (it > pto) pto = it }
                    while (written < size) {
                        val n = p.client.writeStream(id, data, 0, minOf(data.size.toLong(), size - written).toInt(), false)
                        if (n <= 0) break
                        written += n
                    }
                    while (true) {
                        val n = p.server!!.readStream(id, buf, 0, buf.size)
                        if (n <= 0) break
                        read += n
                        progress()
                    }
                    read >= size
                }
            progress()
            return Upload(done, stall, stallPtos, p.client.streams.blockedEpoch)
        } finally {
            p.close()
        }
    }

    /**
     * What the repeat schedule guarantees, in PTOs. A blocked client reports its limit at once and repeats it 1, 2 and 4 PTOs later,
     * then every 8 PTOs ([onBlockedRepeatTimer]); the server answers each report (they come more than an RTT apart, so the
     * one-answer-per-RTT limit never drops one) and each answer gets through with probability 1 - [LOSS], independently. Report n
     * (n >= 4) goes out (8n - 17) PTOs after the first, so an episode stalls longer than (8m - 15) PTOs (2 for delivery and the read)
     * only when m answers in a row are lost: probability [LOSS]^m. The server's own retransmissions only shorten a stall. Seed 12:
     * 22 answers lost in a row, the 23rd report went through after 167 PTOs (6.07 s at 36 ms).
     */
    private fun ptosAfter(m: Int): Int = 8 * maxOf(m, 4) - 15

    /** The smallest m with [LOSS]^m <= [p]. */
    private fun attemptsFor(p: Double): Int = ceil(ln(p) / ln(LOSS)).toInt()

    @Test fun lostWindowUpdatesDoNotStallAnUpload() {
        val runs = (1L..40L).map { seed -> seed to upload(seed, 8 shl 20) }
        val all = runs.joinToString { (s, u) -> "$s: ${u.longestStall} = ${u.longestStallPtos.toInt()} PTO (${u.episodes} episodes)" }
        assertTrue(runs.all { it.second.delivered }, "every upload completes: $all")
        val episodes = runs.sumOf { it.second.episodes }
        val kMax = runs.maxOf { it.second.episodes }
        // every stall: a union bound over all episodes of the 40 seeds, exceeded by chance with probability <= 1 %
        val x = ptosAfter(attemptsFor(0.01 / episodes))
        // the median of the per-seed longest stalls: one seed (k <= kMax episodes) exceeds y with probability
        // 1 - (1 - LOSS^m)^k <= 0.3, and 20 of 40 seeds doing so has probability < 1 % (binomial)
        val y = ptosAfter(attemptsFor(1 - 0.7.pow(1.0 / kMax)))
        val stalls = runs.map { it.second.longestStallPtos }.sorted()
        assertTrue(stalls.last() < x, "longest stall ${stalls.last()} PTO < $x PTO ($episodes episodes): $all")
        assertTrue(stalls[stalls.size / 2] < y, "median longest stall ${stalls[stalls.size / 2]} PTO < $y PTO (k <= $kMax): $all")
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
