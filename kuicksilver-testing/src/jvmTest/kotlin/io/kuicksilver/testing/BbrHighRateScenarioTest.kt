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
 * BBR and CUBIC at 1 Gbit/s on the simulator (virtual time): an idle gap longer than the one that overflowed the pacer's
 * token arithmetic at 10 Gbit/s (7.4 s; here 8 s), and a 0.2 ms LAN where BBR is paced although the RTT is below 1 ms.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class BbrHighRateScenarioTest {
    private val rate = 1_000_000_000L

    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
    }

    private fun configs(): List<Pair<String, QuicConfig>> =
        listOf(
            "BBR" to quicConfig { congestionController = { Bbr(random = Random(41)) } },
            "CUBIC" to quicConfig { congestionController = { Cubic() } },
        )

    @Test fun aLongIdleGapAtOneGigabit() {
        for ((name, q) in configs()) {
            val oneWay = 5.milliseconds
            val net = SharedBottleneck(41, LinkParams(delay = oneWay, bandwidthBitsPerSecond = rate, queueLimitBytes = rate / 8 / 100))
            val f = net.addFlow(q)
            net.run(3.seconds)
            f.paused = true
            net.run(8.seconds) // the 4 MB send buffer drains in ~35 ms, then nothing moves for the rest of the gap
            f.paused = false
            var stall = Duration.ZERO
            var still = Duration.ZERO
            net.mark()
            repeat(20) {
                val before = f.read
                net.run(100.milliseconds)
                if (f.read == before) still += 100.milliseconds else still = Duration.ZERO
                if (still > stall) stall = still
            }
            val g = net.goodputBits(f, 2.seconds)
            println(
                "| 1 Gbit/s, 10 ms, after an 8 s idle gap | $name ${mbit(
                    g,
                )} over 2 s, longest stall $stall, queue ${ms(net.timeMeanQueueDelay)} |",
            )
            assertTrue(stall == Duration.ZERO, "$name stalled $stall after the idle gap")
            assertTrue(g >= rate / 2, "$name after the idle gap: $g")
        }
    }

    @Test fun lanAtPointTwoMilliseconds() {
        for ((name, q) in configs()) {
            val net = SharedBottleneck(42, LinkParams(delay = 0.1.milliseconds, bandwidthBitsPerSecond = rate, queueLimitBytes = 25_000))
            val f = net.addFlow(q)
            net.run(1.seconds)
            net.mark()
            net.run(2.seconds)
            val g = net.goodputBits(f, 2.seconds)
            println(
                "| 1 Gbit/s, RTT 0.2 ms, 25 kB buffer | $name ${mbit(
                    g,
                )}, queue ${ms(net.timeMeanQueueDelay)} / ${ms(net.maxQueueDelay)}, lost ${f.lost} |",
            )
            assertTrue(g >= rate * 6 / 10, "$name on a 0.2 ms LAN: $g")
        }
    }

    private companion object {
        fun mbit(bits: Long): String = "${(bits / 1e4).roundToLong() / 100.0} Mbit/s"

        fun ms(d: Duration): String = "${(d.inWholeMicroseconds / 10.0).roundToLong() / 100.0} ms"
    }
}
