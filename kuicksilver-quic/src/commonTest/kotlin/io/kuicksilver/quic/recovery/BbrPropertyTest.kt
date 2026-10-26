// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.double
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.arbitrary.long
import io.kotest.property.checkAll
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.Bbr
import kotlinx.coroutines.test.runTest
import kotlin.math.pow
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.nanoseconds

/**
 * Property tests of [Bbr] (draft-ietf-ccwg-bbr): random ACK, loss, CE, timeout, idle, MTU and spurious-loss streams keep every
 * invariant [BbrDriver.check] states (window at least 4 datagrams, a positive pacing rate, no negative or overflowing model
 * value, only legal state transitions); and a clean bottleneck anywhere from 10 to 100 Gbit/s and 100 us to 2 s of RTT is
 * measured without overflow.
 */
@OptIn(ExperimentalKuicksilverApi::class, io.kotest.common.ExperimentalKotest::class)
class BbrPropertyTest {
    @Test fun arbitraryEventStreamsKeepTheInvariants() =
        runTest {
            checkAll(PropTestConfig(iterations = 300), Arb.long(), Arb.int(1200..65_527), Arb.list(Arb.int(), 100..1500)) {
                seed,
                mss,
                words,
                ->
                val d = BbrDriver(seed, mss)
                var i = 0
                val arg = { if (i < words.size) words[i++] else 0 }
                while (i < words.size) d.step(arg(), arg)
            }
        }

    @Test fun mostlySendAndAckStreamsReachEveryState() =
        runTest {
            // a stream biased to a working flow (send, time, ack) must pass the probing states too, so the invariants see them
            val seen = HashSet<Bbr.State>()
            checkAll(PropTestConfig(iterations = 60), Arb.long()) { seed ->
                val r = Random(seed)
                val d = BbrDriver(seed, 1200)
                repeat(6000) {
                    val op =
                        when (r.nextInt(20)) {
                            in 0..6 -> 0
                            in 7..12 -> 1
                            in 13..16 -> 2
                            17 -> 5
                            18 -> 7
                            else -> r.nextInt(10)
                        }
                    var k = 0
                    // time moves in steps of up to 2 ms (scale 1: microseconds), other arguments are arbitrary
                    d.step(op) { if (op == 2) (if (k++ == 0) 1 else r.nextInt(2000)) else r.nextInt() }
                    seen += d.cc.state
                }
            }
            // Drain can pass within one ACK (Startup -> Drain -> ProbeBW_DOWN), so only states that persist are required
            assertTrue(seen.containsAll(listOf(Bbr.State.Startup, Bbr.State.ProbeBwDown, Bbr.State.ProbeBwUp)), "states seen $seen")
        }

    @Test fun aCleanBottleneckFrom10To100GbitAnd100usTo2sIsMeasuredWithoutOverflow() =
        runTest {
            checkAll(PropTestConfig(iterations = 12), Arb.double(10.0..100.0), Arb.double(-4.0..0.31)) { gbit, rttExp ->
                scale((gbit * 1e9 / 8).toLong(), (10.0.pow(rttExp) * 1e9).toLong())
            }
            for (g in listOf(10.0, 100.0)) for (rtt in listOf(100_000L, 2_000_000_000L)) scale((g * 1e9 / 8).toLong(), rtt)
        }

    /** [rate] bytes per second, [rttNanos]: "datagrams" of a 200th of the BDP (a numeric stress, not a real datagram size). */
    private fun scale(
        rate: Long,
        rttNanos: Long,
    ) {
        val bdp = (rate.toDouble() * rttNanos / 1e9).toLong()
        val size = (bdp / 200).coerceIn(1200L, 1L shl 30).toInt()
        val b = Bottleneck(Bbr(size, Random(1)), rate, rttNanos.nanoseconds, mss = size)
        b.run((rttNanos * 40).nanoseconds)
        val cc = b.cc
        val ctx = "rate $rate B/s, RTT $rttNanos ns, datagram $size: max_bw ${cc.maxBw}, cwnd ${cc.cwnd}, states ${b.states.map {
            it.second
        }.distinct()}"
        println(ctx)
        assertTrue(cc.maxBw in (rate * 0.8).toLong()..(rate * 1.3).toLong(), ctx)
        assertTrue(cc.minRttNanos in rttNanos..rttNanos * 2, "min_rtt ${cc.minRttNanos}; $ctx")
        assertTrue(cc.cwnd in cc.minPipeCwnd..Long.MAX_VALUE / 4, ctx)
        val pacing = cc.pacingRate(rttNanos.nanoseconds)
        assertTrue(pacing in (rate * 0.5).toLong()..(rate * 4L), "pacing $pacing; $ctx")
        assertTrue(b.delivered >= bdp * 10, "delivered ${b.delivered} of ${bdp * 40}; $ctx")
    }
}
