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
        warmup: Duration = 3.seconds,
        window: Duration = 12.seconds,
    ): Single {
        val net = SharedBottleneck(seed = 11, data = data)
        val f = net.addFlow(quic)
        net.run(warmup)
        net.mark()
        net.run(window)
        return Single(net.goodputBits(f, window), net.meanQueueDelay, net.maxQueueDelay, f.lost)
    }

    @Test fun onALossyLinkBbrKeepsItsRateWhereCubicCollapses() {
        val data = link(loss = 0.01)
        val b = single(bbr(1), data)
        val c = single(cubic(), data)
        println("1 % loss, 50 Mbit/s, 40 ms, 1 BDP buffer: BBR $b; CUBIC $c; ratio ${two(b.goodput.toDouble() / c.goodput)}")
        assertTrue(b.goodput >= 2 * c.goodput, "BBR ${b.goodput} vs CUBIC ${c.goodput}")
    }

    @Test fun onACleanLinkBbrFillsThePipeWithAShortQueue() {
        val data = link(buffer = 4 * bdpBytes) // a deep buffer: a loss-based flow fills it, BBR should not
        val b = single(bbr(2), data)
        val c = single(cubic(), data)
        println("clean, 50 Mbit/s, 40 ms, 4 BDP buffer: BBR $b; CUBIC $c")
        assertTrue(b.goodput >= rate * 9 / 10, "BBR utilisation ${b.goodput} of $rate")
        assertTrue(b.meanQueue <= 20.milliseconds, "BBR mean queueing delay ${b.meanQueue} (base RTT 40 ms)")
    }

    @Test fun twoBbrFlowsShareTheBottleneck() {
        val net = SharedBottleneck(seed = 12, data = link())
        val a = net.addFlow(bbr(3))
        val b = net.addFlow(bbr(4), startAfter = 2.seconds)
        net.run(20.seconds) // BBRv3 converges over several probe cycles (2-3 s each): the late flow climbs from about 30 % to 40 %
        val early = net.goodputBits(a, 20.seconds) to net.goodputBits(b, 20.seconds)
        net.mark()
        val window = 20.seconds
        net.run(window)
        val ga = net.goodputBits(a, window)
        val gb = net.goodputBits(b, window)
        val ratio = minOf(ga, gb).toDouble() / maxOf(ga, gb)
        println(
            "two BBR flows, 20-40 s: ${ga / 1000} + ${gb / 1000} kbit/s (ratio ${two(ratio)}), queue mean ${net.meanQueueDelay}, " +
                "tail drops ${net.tailDrops}; 0-20 s: ${early.first / 1000} + ${early.second / 1000} kbit/s",
        )
        assertTrue(ga + gb >= rate * 85 / 100, "together ${ga + gb} of $rate")
        assertTrue(ratio >= 0.5, "share ratio $ratio")
    }

    @Test fun bbrNextToCubicKeepsBothFlowsAlive() {
        val net = SharedBottleneck(seed = 13, data = link())
        val c = net.addFlow(cubic())
        val b = net.addFlow(bbr(5), startAfter = 2.seconds)
        net.run(12.seconds)
        net.mark()
        val window = 20.seconds
        net.run(window)
        val gc = net.goodputBits(c, window)
        val gb = net.goodputBits(b, window)
        println(
            "BBR with CUBIC, 1 BDP buffer: BBR ${gb / 1000} kbit/s (${gb * 100 / (gb + gc)} %), CUBIC ${gc / 1000} kbit/s, " +
                "queue mean ${net.meanQueueDelay}",
        )
        assertTrue(gb >= rate / 20 && gc >= rate / 20, "a flow starved: BBR $gb CUBIC $gc")
    }
}
