// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.Bbr
import io.kuicksilver.quic.Cubic
import io.kuicksilver.quic.IoCapabilities
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
 * BBR against CUBIC under harsh conditions on a simulated bottleneck (virtual time, 3 seeds each): reordering, ACK aggregation,
 * thinned ACKs, a link rate step, deep and shallow buffers, satellite and LAN RTTs, a 2 s blackhole, 10 % loss, an on/off flow,
 * a step-marking ECN AQM, a PMTU black hole mid-flow. Every run prints one table row (goodput, time-averaged and maximum
 * queueing delay, packets the sender declared lost, the longest stall); the assertions hold only robust properties: no stall,
 * no collapse, a bounded queue in a deep buffer, recovery after the blackhole.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class BbrHarshScenarioTest {
    private val rate = 50_000_000L
    private val oneWay = 20.milliseconds
    private val bdpBytes = rate / 8 * 40 / 1000 // 250 000
    private val seeds = listOf(21L, 22L, 23L)

    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
    }

    private fun bbr(seed: Long): QuicConfig = quicConfig { congestionController = { Bbr(random = Random(seed)) } }

    private fun cubic(): QuicConfig = quicConfig { congestionController = { Cubic() } }

    private fun QuicConfig.withWindows(): QuicConfig {
        val cc = congestionController
        return quicConfig {
            congestionController = cc
            initialStreamWindow = 64_000_000
            initialConnectionWindow = 64_000_000
            maxStreamWindow = 64_000_000
            maxConnectionWindow = 64_000_000
        }
    }

    private class Run(
        val goodput: Long,
        val meanQueue: Duration,
        val maxQueue: Duration,
        val lost: Long,
        val stall: Duration,
        val extra: Map<String, Double> = emptyMap(),
    )

    /** Mean over the seeds, and the worst value, of one measure. */
    private class Summary(
        val runs: List<Run>,
    ) {
        val goodput: Long get() = runs.sumOf { it.goodput } / runs.size
        val minGoodput: Long get() = runs.minOf { it.goodput }
        val meanQueue: Duration get() = runs.map { it.meanQueue }.reduce { a, b -> a + b } / runs.size
        val maxQueue: Duration get() = runs.maxOf { it.maxQueue }
        val lost: Long get() = runs.sumOf { it.lost } / runs.size
        val stall: Duration get() = runs.maxOf { it.stall }

        fun extra(k: String): Double = runs.sumOf { it.extra[k] ?: 0.0 } / runs.size

        fun extraMax(k: String): Double = runs.maxOf { it.extra[k] ?: 0.0 }

        override fun toString(): String =
            "${mbit(goodput)} (min ${mbit(minGoodput)}) | ${ms(meanQueue)} / ${ms(maxQueue)} | $lost | ${ms(stall)}"
    }

    /**
     * One flow over [data] / [acks]: [warmup], then a measurement [window] in slices of [slice]; [during] runs before every slice
     * with the time since the start of the window (to change the link mid-run).
     */
    private fun single(
        quic: QuicConfig,
        seed: Long,
        data: LinkParams,
        acks: LinkParams = LinkParams(delay = data.delay),
        caps: IoCapabilities? = null,
        warmup: Duration = 3.seconds,
        window: Duration = 12.seconds,
        slice: Duration = 100.milliseconds,
        setup: (SharedBottleneck) -> Unit = {},
        during: (SharedBottleneck, SharedBottleneck.Flow, Duration) -> Unit = { _, _, _ -> },
        extra: (SharedBottleneck, SharedBottleneck.Flow) -> Map<String, Double> = { _, _ -> emptyMap() },
    ): Run {
        val net = SharedBottleneck(seed = seed, data = data, acks = acks, caps = caps)
        setup(net)
        val f = net.addFlow(quic)
        net.run(warmup)
        net.mark()
        var t = Duration.ZERO
        var stall = Duration.ZERO
        var still = Duration.ZERO
        while (t < window) {
            during(net, f, t)
            val before = f.read
            net.run(slice)
            t += slice
            if (f.read == before && !f.paused) still += slice else still = Duration.ZERO
            if (still > stall) stall = still
        }
        return Run(net.goodputBits(f, window), net.timeMeanQueueDelay, net.maxQueueDelay, f.lost, stall, extra(net, f))
    }

    private fun compare(
        name: String,
        run: (QuicConfig, Long) -> Run,
    ): Pair<Summary, Summary> {
        val b = Summary(seeds.map { run(bbr(it), it) })
        val c = Summary(seeds.map { run(cubic(), it) })
        println("| $name | $b | $c |")
        return b to c
    }

    private fun link(
        buffer: Long = bdpBytes,
        loss: Double = 0.0,
        delay: Duration = oneWay,
        rate: Long = this.rate,
        reorder: Double = 0.0,
    ) = LinkParams(delay = delay, bandwidthBitsPerSecond = rate, lossRate = loss, queueLimitBytes = buffer, reorderRate = reorder)

    @Test fun reorderingDeeperThanThePacketThreshold() {
        // 1 % of the datagrams 8 ms late (40 packets at 50 Mbit/s): declared lost, then acknowledged; BBR undoes the spurious episodes
        val (b, _) =
            compare("reordering 1 % by 8 ms") { q, s ->
                single(q, s, link(reorder = 0.01), setup = { it.c2s.reorderDelay = 8.milliseconds })
            }
        assertTrue(b.minGoodput >= rate * 7 / 10, "BBR with reordering: $b")
        assertTrue(b.stall < 1.seconds)
    }

    @Test fun ackAggregationLikeWifi() {
        val (b, _) =
            compare("ACK aggregation, 8 ms batches") { q, s -> single(q, s, link(), setup = { it.s2c.aggregation = 8.milliseconds }) }
        assertTrue(b.minGoodput >= rate * 8 / 10, "BBR with aggregated ACKs: $b")
        assertTrue(b.stall < 1.seconds)
    }

    @Test fun thinnedAcks() {
        // 3 of 4 ACK datagrams lost: every ACK frame that gets through acknowledges about 8 packets (stretch ACKs). The flow-control
        // windows are large: with the defaults a lost MAX_STREAM_DATA stalls both controllers for ~10 s behind the server's PTO
        // backoff (a flow-control finding, not congestion control)
        val (b, _) =
            compare("ACK thinning 75 %") { q, s ->
                single(q.withWindows(), s, link(), acks = LinkParams(delay = oneWay, lossRate = 0.75))
            }
        assertTrue(b.minGoodput >= rate * 6 / 10, "BBR with thinned ACKs: $b")
        assertTrue(b.stall < 1.seconds)
    }

    @Test fun linkRateStepDownAndUp() {
        // 50 -> 5 Mbit/s at 3 s into the window, back to 50 at 11 s; the old max_bw must age out (two ProbeBW cycles) and the new one
        // be found again
        val (b, c) =
            compare("rate step 50 -> 5 -> 50 Mbit/s") { q, s ->
                var lowFrom = 0L
                var lowTo = 0L
                var highFrom = 0L
                var lowQueue = Duration.ZERO
                var lowQueueAt = Duration.ZERO
                single(
                    q,
                    s,
                    link(),
                    window = 20.seconds,
                    during = { net, f, t ->
                        when (t) {
                            3.seconds -> {
                                net.c2s.bandwidth = 5_000_000L
                            }

                            6.seconds -> {
                                lowFrom = f.read
                                lowQueueAt = Duration.ZERO
                            }

                            11.seconds -> {
                                lowTo = f.read
                                net.c2s.bandwidth = rate
                            }

                            14.seconds -> {
                                highFrom = f.read
                            }
                        }
                        if (t >= 6.seconds && t < 11.seconds) {
                            val q2 = net.c2s.busyUntil - net.now
                            if (q2 > lowQueue) lowQueue = q2
                            lowQueueAt += 100.milliseconds
                        }
                    },
                    extra = { _, f ->
                        mapOf(
                            "low" to (lowTo - lowFrom) * 8.0 / 5,
                            "high" to (f.read - highFrom) * 8.0 / 6,
                            "lowQueueMs" to lowQueue.inWholeMicroseconds / 1000.0,
                        )
                    },
                )
            }
        println(
            "|   rate step detail | BBR at 5 Mbit/s ${mbit(b.extra("low").toLong())}, after the rise ${mbit(b.extra("high").toLong())}, " +
                "max queue at 5 Mbit/s ${b.extraMax("lowQueueMs")} ms | CUBIC ${mbit(c.extra("low").toLong())}, " +
                "${mbit(c.extra("high").toLong())}, ${c.extraMax("lowQueueMs")} ms |",
        )
        assertTrue(b.extra("low") >= 5_000_000 * 0.6, "BBR at 5 Mbit/s: ${b.extra("low")}")
        assertTrue(b.extra("high") >= rate * 0.7, "BBR after the rise: ${b.extra("high")}")
        assertTrue(b.stall < 1.seconds)
    }

    @Test fun deepBufferStaysShort() {
        val (b, c) = compare("deep buffer 8 BDP") { q, s -> single(q, s, link(buffer = 8 * bdpBytes)) }
        assertTrue(b.minGoodput >= rate * 85 / 100, "BBR utilisation in a deep buffer: $b")
        assertTrue(b.meanQueue <= 40.milliseconds, "BBR keeps a deep buffer short (base RTT 40 ms): $b")
        assertTrue(b.meanQueue * 3 < c.meanQueue, "CUBIC fills it: $c")
    }

    @Test fun shallowBuffer() {
        val (b, _) = compare("shallow buffer 0.25 BDP") { q, s -> single(q, s, link(buffer = bdpBytes / 4)) }
        assertTrue(b.minGoodput >= rate * 7 / 10, "BBR in a shallow buffer: $b")
        assertTrue(b.stall < 1.seconds)
    }

    @Test fun satelliteRtt() {
        // 300 ms RTT, 1 BDP buffer (1.9 MB)
        val (b, _) =
            compare("satellite RTT 300 ms") { q, s ->
                single(q, s, link(buffer = rate / 8 * 300 / 1000, delay = 150.milliseconds), warmup = 8.seconds, window = 20.seconds)
            }
        assertTrue(b.minGoodput >= rate * 7 / 10, "BBR at 300 ms: $b")
        assertTrue(b.stall < 2.seconds)
    }

    @Test fun lanRtt() {
        // 1 ms RTT, 1 BDP buffer (6 kB, five datagrams)
        val (b, _) =
            compare("LAN RTT 1 ms") { q, s -> single(q, s, link(buffer = maxOf(rate / 8 / 1000, 6000L), delay = 500.microseconds())) }
        assertTrue(b.minGoodput >= rate * 7 / 10, "BBR at 1 ms: $b")
        assertTrue(b.stall < 1.seconds)
    }

    @Test fun blackholeOfTwoSeconds() {
        // both directions dropped for 2 s from 2 s into the window: PTOs back off; once a probe passes the flow must recover
        val (b, c) =
            compare("2 s blackhole") { q, s ->
                var recovered = -1.0
                var window = 0L
                single(
                    q,
                    s,
                    link(),
                    window = 14.seconds,
                    during = { net, f, t ->
                        if (t == 2.seconds) {
                            net.c2s.blackhole = true
                            net.s2c.blackhole = true
                        }
                        if (t == 4.seconds) {
                            net.c2s.blackhole = false
                            net.s2c.blackhole = false
                        }
                        if (t >= 4.seconds && recovered < 0) {
                            // half the link over the last 200 ms
                            if (t > 4.seconds &&
                                (f.read - window) * 8 * 5 >= rate / 2
                            ) {
                                recovered = (t - 4.seconds).inWholeMilliseconds / 1000.0
                            }
                            if ((t - 4.seconds).inWholeMilliseconds % 200 == 0L) window = f.read
                        }
                    },
                    extra = { _, _ -> mapOf("recovery" to recovered) },
                )
            }
        println(
            "|   blackhole detail | BBR back to half the link ${b.extraMax(
                "recovery",
            )} s after (worst seed) | CUBIC ${c.extraMax("recovery")} s |",
        )
        assertTrue(
            b.runs.all { (it.extra["recovery"] ?: -1.0) in 0.0..4.0 },
            "BBR recovery after the blackhole: ${b.runs.map { it.extra }}",
        )
    }

    @Test fun tenPercentLoss() {
        // BBRv3 treats loss above 2 % as congestion: the short-term model backs off every lossy round and the flow runs near its
        // 4-datagram floor (4 x 1200 B per 40 ms is 0.96 Mbit/s); it must not fall below that or stall
        val (b, c) = compare("10 % random loss") { q, s -> single(q, s, link(loss = 0.1)) }
        assertTrue(b.minGoodput >= 1_000_000L, "BBR collapsed at 10 % loss: $b")
        assertTrue(b.goodput > c.goodput, "BBR $b vs CUBIC $c")
        assertTrue(b.stall < 1.seconds)
    }

    @Test fun onOffFlowRestartsWithoutABurst() {
        // 1 s on, 2 s off, repeated (the send buffer drains for ~0.6 s, then the flow is idle): in its first RTT after a quiet
        // period the flow sends at its pacing rate, not a line-rate burst of its window. A bandwidth probe may follow at once (the
        // probe timer ran out while idle); its queue is the probe's, bounded by the 2.25 BDP window, not a burst
        val (b, _) =
            compare("on/off 1 s / 2 s, deep buffer") { q, s ->
                var restartQueue = Duration.ZERO
                single(
                    q,
                    s,
                    link(buffer = 8 * bdpBytes),
                    window = 12.seconds,
                    slice = 10.milliseconds,
                    during = { net, f, t ->
                        val phase = t.inWholeMilliseconds % 3000
                        f.paused = phase >= 1000
                        if (t >= 3.seconds && phase in 0..50) {
                            val qd = net.c2s.busyUntil - net.now
                            if (qd > restartQueue) restartQueue = qd
                        }
                    },
                    extra = { _, _ -> mapOf("restartQueueMs" to restartQueue.inWholeMicroseconds / 1000.0) },
                )
            }
        println(
            "|   on/off detail | BBR max queue in the first 50 ms after a restart ${b.extraMax(
                "restartQueueMs",
            )} ms (overall ${ms(b.maxQueue)}) |",
        )
        assertTrue(b.extraMax("restartQueueMs") <= 10.0, "a restart queued ${b.extraMax("restartQueueMs")} ms in its first RTT")
        assertTrue(b.maxQueue <= 60.milliseconds, "BBR's queue stays within its 2.25 BDP probing window: $b")
    }

    @Test fun ecnStepMarkingAqm() {
        // CE above 5 ms of queue (an L4S-style step): BBR treats CE as loss and keeps the queue near the threshold
        val caps = IoCapabilities(ecnSend = true, ecnReceive = true, gsoMaxSegments = 1, gro = false, df = false, batch = 1)
        val (b, _) =
            compare("ECN step marking at 5 ms, 8 BDP buffer") { q, s ->
                single(q, s, link(buffer = 8 * bdpBytes), caps = caps, setup = { it.c2s.ceMarkAbove = 5.milliseconds })
            }
        assertTrue(b.minGoodput >= rate * 6 / 10, "BBR with an ECN AQM: $b")
        assertTrue(b.meanQueue <= 40.milliseconds, "$b")
    }

    @Test fun pmtuBlackHoleMidFlow() {
        // DF sockets: PMTUD raises the datagram size to 1452 early; at 3 s into the window the path drops everything above 1300 bytes
        val caps = IoCapabilities(ecnSend = false, ecnReceive = false, gsoMaxSegments = 1, gro = false, df = true, batch = 1)
        val (b, _) =
            compare("PMTU black hole (1452 -> 1300) mid-flow") { q, s ->
                single(q, s, link(), caps = caps, during = { net, _, t -> if (t == 3.seconds) net.c2s.mtu = 1300 })
            }
        assertTrue(b.minGoodput >= rate / 2, "BBR across a PMTU black hole: $b")
        assertTrue(b.stall < 3.seconds, "$b")
    }

    @Test fun deepBufferSharedWithCubic() {
        val net = SharedBottleneck(seed = 31, data = link(buffer = 8 * bdpBytes))
        val c = net.addFlow(cubic())
        val b = net.addFlow(bbr(31), startAfter = 2.seconds)
        net.run(12.seconds)
        net.mark()
        net.run(20.seconds)
        val gc = net.goodputBits(c, 20.seconds)
        val gb = net.goodputBits(b, 20.seconds)
        println("| BBR + CUBIC, 8 BDP buffer | BBR ${mbit(gb)} | CUBIC ${mbit(gc)}, queue ${ms(net.timeMeanQueueDelay)} |")
        assertTrue(gb >= rate / 20 && gc >= rate / 20, "a flow starved: BBR $gb CUBIC $gc")
        assertTrue(gb + gc >= rate * 85 / 100)
    }

    @Test fun rttUnfairnessBetweenTwoBbrFlows() {
        // the same bottleneck, base RTTs 40 ms and 100 ms
        val net = SharedBottleneck(seed = 32, data = link())
        val short = net.addFlow(bbr(32))
        val long = net.addFlow(bbr(33))
        net.c2s.extraDelayByTag = { if (it == long.index) 30.milliseconds else Duration.ZERO }
        net.s2c.extraDelayByTag = net.c2s.extraDelayByTag
        net.run(15.seconds)
        net.mark()
        net.run(20.seconds)
        val gs = net.goodputBits(short, 20.seconds)
        val gl = net.goodputBits(long, 20.seconds)
        println("| two BBR flows, RTT 40 ms vs 100 ms | ${mbit(gs)} | ${mbit(gl)} (ratio ${two(gl.toDouble() / gs)}) |")
        assertTrue(gs >= rate / 20 && gl >= rate / 20, "a flow starved: $gs $gl")
        assertTrue(gs + gl >= rate * 85 / 100)
    }

    private fun Int.microseconds(): Duration = (this / 1000.0).milliseconds

    private companion object {
        fun mbit(bits: Long): String = "${two(bits / 1e6)} Mbit/s"

        fun ms(d: Duration): String = "${two(d.inWholeMicroseconds / 1000.0)} ms"

        fun two(d: Double): Double = (d * 100).roundToLong() / 100.0
    }
}
