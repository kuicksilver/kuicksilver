// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.Cubic
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.quicConfig
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * CUBIC (RFC 9438) with HyStart++ (RFC 9406) through the whole stack on a simulated bottleneck under virtual time: one bulk
 * upload, the client's controller watched between steps.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class CubicScenarioTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
    }

    /**
     * RFC 9406 section 4.3: "An implementation SHOULD use HyStart++ only for the initial slow start (when the ssthresh is at its
     * initial value of arbitrarily high per [RFC5681]) and fall back to using standard slow start for the remainder of the
     * connection lifetime." 50 Mbit/s, 40 ms, a one-BDP buffer: the initial slow start ends; the upload pauses until nothing is in
     * flight, then resumes into a 6 s blackhole in both directions, which ends in persistent congestion (RFC 9002 section 7.6.2:
     * the window back to 2 datagrams, ssthresh where the loss set it); from the collapse the data direction's delay rises by 3 ms
     * every 10 ms for a second (a route change into a filling queue). The slow start back to that ssthresh is plain slow start:
     * HyStart++ ran in it with the round state of the initial one, entered Conservative Slow Start and ended slow start far below
     * the ssthresh the loss had set (290 542 -> 88 800 bytes with seed 31).
     */
    @Test fun noHystartInTheSlowStartAfterPersistentCongestion() {
        for (seed in 31L..33L) {
            val ccs = ArrayList<Cubic>()
            val quic = quicConfig { congestionController = { Cubic().also { ccs += it } } }
            val net =
                SharedBottleneck(
                    seed = seed,
                    data = LinkParams(delay = 20.milliseconds, bandwidthBitsPerSecond = 50_000_000L, queueLimitBytes = 250_000L),
                )
            val flow = net.addFlow(quic)
            net.run(3.seconds)
            val cc = ccs.first() // the client's: it connects before the server sees its Initial
            assertTrue(cc.ssthresh < Long.MAX_VALUE, "seed $seed: the initial slow start ended (cwnd ${cc.cwnd})")
            flow.paused = true
            net.run(1.seconds) // nothing in flight: what the blackhole takes is all the sender sends from now on
            net.c2s.blackhole = true
            net.s2c.blackhole = true
            flow.paused = false
            net.run(6.seconds) // the PTO backs off to seconds: the first probe after the blackhole comes some seconds later
            net.c2s.blackhole = false
            net.s2c.blackhole = false
            val restored = net.now
            val before = cc.cwnd
            var collapsedAt: TimeMark? = null
            while (collapsedAt == null && net.now - restored < 20.seconds) {
                net.run(1.milliseconds)
                // the ACK that declares it also acknowledges the probe that got through: 2 datagrams plus what that ACK delivered
                if (cc.cwnd < before / 4) collapsedAt = net.now
            }
            val from = collapsedAt ?: net.now
            val ssthresh = cc.ssthresh
            net.c2s.extraDelayByTag = { _ -> (net.now - from).coerceAtMost(1.seconds) * 0.3 }
            val lostAtCollapse = flow.lost
            var css = false
            var lowered = false
            repeat(1000) {
                net.run(5.milliseconds)
                if (cc.inConservativeSlowStart) css = true
                if (flow.lost == lostAtCollapse && cc.ssthresh < ssthresh) lowered = true // no loss since, yet a lower ssthresh
            }
            println(
                "seed $seed: collapsed ${collapsedAt?.let { it - restored }} after the blackhole, ssthresh $ssthresh -> ${cc.ssthresh}, " +
                    "cwnd ${cc.cwnd}, losses since ${flow.lost - lostAtCollapse}",
            )
            assertTrue(collapsedAt != null, "seed $seed: persistent congestion collapsed the window")
            assertTrue(!css, "seed $seed: Conservative Slow Start in the slow start after persistent congestion")
            assertTrue(!lowered, "seed $seed: slow start ended below the ssthresh the loss set ($ssthresh -> ${cc.ssthresh})")
        }
    }
}
