// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.Bbr
import io.kuicksilver.quic.Cubic
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.quicConfig
import kotlin.math.roundToLong
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * BBR (draft-ietf-ccwg-bbr) against CUBIC on a simulated 50 Mbit/s, 40 ms bottleneck (virtual time): goodput under random
 * loss, utilisation and queueing delay on a clean link, sharing between BBR flows and with a CUBIC flow. The numbers go to the
 * test's standard output; the assertions hold what the design promises, with margin.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class BbrSimulationTest {
    private val rate = 50_000_000L
    private val oneWay = 20.milliseconds
    private val bdpBytes = rate / 8 * 40 / 1000 // 250 000

    private fun two(d: Double): Double = (d * 100).roundToLong() / 100.0

    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
    }

    private fun bbr(seed: Int): QuicConfig = quicConfig { congestionController = { Bbr(random = Random(seed)) } }

    private fun cubic(): QuicConfig = quicConfig { congestionController = { Cubic() } }

    private fun link(
        loss: Double = 0.0,
        buffer: Long = bdpBytes,
    ) = LinkParams(delay = oneWay, bandwidthBitsPerSecond = rate, lossRate = loss, queueLimitBytes = buffer)

    private class Single(
        val goodput: Long,
        val meanQueue: Duration,
        val maxQueue: Duration,
        val lost: Long,
    ) {
        override fun toString() = "${goodput / 1000} kbit/s, queue mean $meanQueue max $maxQueue, lost $lost"
    }

    private fun single(
        quic: QuicConfig,
        data: LinkParams,
        seed: Long = 11,
        warmup: Duration = 3.seconds,
        window: Duration = 12.seconds,
    ): Single {
        val net = SharedBottleneck(seed = seed, data = data)
        val f = net.addFlow(quic)
        net.run(warmup)
        net.mark()
        net.run(window)
        return Single(net.goodputBits(f, window), net.timeMeanQueueDelay, net.maxQueueDelay, f.lost)
    }

    @Test fun onALossyLinkBbrKeepsItsRateWhereCubicCollapses() {
        val data = link(loss = 0.01)
        for (seed in 11L..13L) {
            val b = single(bbr(seed.toInt()), data, seed)
            val c = single(cubic(), data, seed)
            println(
                "1 % loss, 50 Mbit/s, 40 ms, 1 BDP buffer, seed $seed: BBR $b; CUBIC $c; ratio ${two(b.goodput.toDouble() / c.goodput)}",
            )
            // BBRv3 keeps about the loss rate plus the pacing margin per lossy round between probes: at least 70 % of the link
            assertTrue(b.goodput >= rate * 7 / 10, "BBR ${b.goodput} of $rate with 1 % loss")
            assertTrue(b.goodput >= 2 * c.goodput, "BBR ${b.goodput} vs CUBIC ${c.goodput}")
        }
    }

    @Test fun onACleanLinkBbrFillsThePipeWithAShortQueue() {
        val data = link(buffer = 4 * bdpBytes) // a deep buffer: a loss-based flow fills it, BBR should not
        val b = single(bbr(2), data)
        val c = single(cubic(), data)
        println("clean, 50 Mbit/s, 40 ms, 4 BDP buffer: BBR $b; CUBIC $c")
        assertTrue(b.goodput >= rate * 9 / 10, "BBR utilisation ${b.goodput} of $rate")
        assertTrue(b.meanQueue <= 20.milliseconds, "BBR mean queueing delay ${b.meanQueue} (base RTT 40 ms)")
        // ProbeBW_UP queues at most a quarter BDP over the 2 x BDP window: never the 160 ms the buffer holds, and nothing lost
        assertTrue(b.maxQueue <= 60.milliseconds, "BBR max queueing delay ${b.maxQueue}")
        assertTrue(b.lost == 0L, "BBR lost ${b.lost} packets on a clean link with a 4 BDP buffer")
    }

    @Test fun twoBbrFlowsShareTheBottleneck() {
        // pre-declared: the late flow starts at 2 s, the share is judged over 20-40 s, for 3 seeds; the 5 s shares before it show
        // the convergence
        val ratios = ArrayList<Double>()
        for (seed in 12L..14L) {
            val net = SharedBottleneck(seed = seed, data = link())
            val a = net.addFlow(bbr(seed.toInt() * 2 + 1))
            val b = net.addFlow(bbr(seed.toInt() * 2 + 2), startAfter = 2.seconds)
            val trend = StringBuilder()
            repeat(4) {
                net.mark()
                net.run(5.seconds)
                trend.append(" ${two(net.goodputBits(b, 5.seconds).toDouble() / net.goodputBits(a, 5.seconds))}")
            }
            net.mark()
            val window = 20.seconds
            net.run(window)
            val ga = net.goodputBits(a, window)
            val gb = net.goodputBits(b, window)
            val ratio = minOf(ga, gb).toDouble() / maxOf(ga, gb)
            ratios += ratio
            println(
                "two BBR flows, seed $seed, 20-40 s: ${ga / 1000} + ${gb / 1000} kbit/s (ratio ${two(ratio)}), " +
                    "queue mean ${net.timeMeanQueueDelay}, tail drops ${net.tailDrops}; late/early per 5 s from 0 s:$trend",
            )
            assertTrue(ga + gb >= rate * 85 / 100, "together ${ga + gb} of $rate")
            assertTrue(ratio >= 0.4, "share ratio $ratio, seed $seed")
        }
        assertTrue(ratios.average() >= 0.5, "mean share ratio ${ratios.average()}")
    }

    @Test fun bbrNextToCubicKeepsBothFlowsAlive() {
        for (seed in 13L..15L) {
            val net = SharedBottleneck(seed = seed, data = link())
            val c = net.addFlow(cubic())
            val b = net.addFlow(bbr(seed.toInt() + 5), startAfter = 2.seconds)
            net.run(12.seconds)
            net.mark()
            val window = 20.seconds
            net.run(window)
            val gc = net.goodputBits(c, window)
            val gb = net.goodputBits(b, window)
            val share = gb.toDouble() / (gb + gc)
            println(
                "BBR with CUBIC, 1 BDP buffer, seed $seed: BBR ${gb / 1000} kbit/s (${two(share * 100)} %), CUBIC ${gc / 1000} kbit/s, " +
                    "queue mean ${net.timeMeanQueueDelay}",
            )
            // documented in guide/quic.md: with one BDP of buffer BBR takes the larger part, but neither flow starves
            assertTrue(share in 0.2..0.85, "BBR share $share next to CUBIC, seed $seed")
            assertTrue(gb + gc >= rate * 85 / 100, "together ${gb + gc} of $rate")
        }
    }
}
