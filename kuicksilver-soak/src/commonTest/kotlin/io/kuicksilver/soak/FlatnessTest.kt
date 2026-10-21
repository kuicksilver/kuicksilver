// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.TimeSource

/** The soak's statistic: flat noisy series pass, slow steady leaks fail even under noise larger than the leak. */
class FlatnessTest {
    private val t = DoubleArray(96) { it * 15.0 } // 24 minutes at 15 s

    @Test fun exactLineSlope() {
        assertEquals(2.0, Flatness.theilSen(doubleArrayOf(0.0, 1.0, 2.0, 3.0), doubleArrayOf(1.0, 3.0, 5.0, 7.0)), 1e-9)
    }

    @Test fun noisyLevelIsFlat() {
        val r = Random(7)
        val v = DoubleArray(t.size) { 12.0 + r.nextInt(-6, 7) } // in-flight connections: 6..18
        assertTrue(Flatness(5.0, 0.25).judge("quic.connections", t, v).flat)
    }

    @Test fun gcSawToothAndOutliersAreFlat() {
        val v = DoubleArray(t.size) { 200_000.0 + (it % 7) * 3_000.0 + if (it % 23 == 0) 60_000.0 else 0.0 }
        assertTrue(Flatness(16 * 1024.0, 0.10).judge("jvm.heapAfterGcKiB", t, v).flat)
    }

    @Test fun slowLeakUnderNoiseIsCaught() {
        val r = Random(11)
        // one connection leaked every ~20 s (+72 over the window) under ±6 of noise
        val v = DoubleArray(t.size) { 12.0 + it * 0.75 + r.nextInt(-6, 7) }
        val verdict = Flatness(5.0, 0.25).judge("quic.connections", t, v)
        assertFalse(verdict.flat, verdict.toString())
        assertEquals(72.0, verdict.projectedGrowth, 6.0)
    }

    @Test fun memoryGrowthIsCaughtOnlyAboveTheBound() {
        // bound: max(32 MiB, 10% of the ~540 MiB median) = ~54 MiB over the window
        val grow = DoubleArray(t.size) { 500_000.0 + it * 800.0 } // +74 MiB over 24 min
        assertFalse(Flatness(32 * 1024.0, 0.10).judge("proc.rssKiB", t, grow).flat)
        val small = DoubleArray(t.size) { 500_000.0 + it * 100.0 } // +9 MiB
        assertTrue(Flatness(32 * 1024.0, 0.10).judge("proc.rssKiB", t, small).flat)
    }

    @Test fun shrinkingIsFlat() {
        val v = DoubleArray(t.size) { 1000.0 - it }
        assertTrue(Flatness(5.0, 0.25).judge("x", t, v).flat)
    }

    @Test fun tooFewSamplesAreNotJudged() {
        assertTrue(Flatness(0.0, 0.0).judge("x", doubleArrayOf(0.0, 1.0), doubleArrayOf(0.0, 100.0)).flat)
    }

    @Test fun matchesTheQuadraticEstimatorOnSmallInputs() {
        val r = Random(3)
        val cases =
            listOf(
                doubleArrayOf(0.0, 1.0, 2.0) to doubleArrayOf(5.0, 5.0, 5.0), // constant
                doubleArrayOf(0.0, 0.0, 0.0, 0.0) to doubleArrayOf(1.0, 2.0, 3.0, 4.0), // every pair at the same time
                doubleArrayOf(0.0, 0.0, 15.0, 15.0, 30.0, 45.0) to doubleArrayOf(1.0, 3.0, 3.0, 3.0, 7.0, 2.0), // ties in t and v
                doubleArrayOf(0.0, 15.0, 30.0, 45.0) to doubleArrayOf(1.0, 2.0, 2.0, 1.0), // an even number of slopes
                t to DoubleArray(t.size) { 40.0 + it * 0.3 + r.nextInt(-5, 6) }, // known slope (0.02/s) under noise
                t to DoubleArray(t.size) { (r.nextInt(0, 4) * 1000).toDouble() }, // heavy ties in v
                // the most samples still judged exactly: 2,048 (2,096,128 pairs)
                DoubleArray(2048) { it * 15.0 } to DoubleArray(2048) { 1e6 - it * 2.0 + r.nextInt(-500, 501) },
            )
        for ((ts, vs) in cases) assertEquals(quadraticTheilSen(ts, vs), Flatness.theilSen(ts, vs), 0.0, "n=${ts.size}")
    }

    @Test fun beyondTheExactLimitTheEstimateStaysWithinAPercentileOfTheExactMedian() {
        val r = Random(5)
        val n = 3000 // 4.5 M pairs
        val ts = DoubleArray(n) { it * 15.0 }
        val vs = DoubleArray(n) { 300_000.0 + it * 0.5 + r.nextInt(-20_000, 20_001) + if (it % 17 == 0) 90_000.0 else 0.0 }
        val sorted = quadraticSlopes(ts, vs).also { it.sort() }
        val est = Flatness.theilSen(ts, vs)
        assertTrue(est >= sorted[(sorted.size * 0.49).toInt()] && est <= sorted[(sorted.size * 0.51).toInt()], "estimate $est")
    }

    @Test fun aSevenDayWindowIsJudgedInBoundedTime() {
        // 72 h at 15 s after a fifth of warm-up has ~13.8k samples (95 M pairs), 7 days ~32k; the quadratic estimator ran
        // out of the 1 GiB test heap on the first
        val r = Random(9)
        val n = 32_000
        val ts = DoubleArray(n) { it * 15.0 }
        val vs = DoubleArray(n) { 12.0 + it * 0.001 + r.nextInt(-6, 7) } // +32 over the window under ±6
        val mark = TimeSource.Monotonic.markNow()
        val verdict = Flatness(5.0, 0.25).judge("quic.connections", ts, vs)
        val took = mark.elapsedNow()
        println("n=$n judged in $took: $verdict")
        assertEquals(32.0, verdict.projectedGrowth, 1.0)
        assertFalse(verdict.flat)
        assertTrue(took.inWholeSeconds < 10, "took $took")
    }

    @Test fun pairSlopesAreBoundedWhateverTheLength() {
        val exact = DoubleArray(2048) { it * 15.0 }
        assertEquals(2048 * 2047 / 2, Flatness.pairSlopes(exact, exact).size) // all pairs
        val week = DoubleArray(40_320) { it * 15.0 } // 7 days at 15 s, warm-up included
        assertEquals(Flatness.MAX_PAIRS, Flatness.pairSlopes(week, week).size)
        // all at one time: no slope at all, and the sampler gives up instead of spinning
        assertEquals(0.0, Flatness.theilSen(DoubleArray(5000), DoubleArray(5000) { it.toDouble() }))
    }

    @Test fun returnToBaselineHonoursTolerance() {
        val r = Soak.returned(mapOf("ksl.ssl" to 3, "proc.fds" to 40), mapOf("ksl.ssl" to 4, "proc.fds" to 43))
        assertFalse(r.first { it.metric == "ksl.ssl" }.ok)
        assertTrue(r.first { it.metric == "proc.fds" }.ok)
    }

    /** The definition: every pair with distinct times, in index order. */
    private fun quadraticSlopes(
        ts: DoubleArray,
        vs: DoubleArray,
    ): DoubleArray {
        val out = DoubleArray(ts.size * (ts.size - 1) / 2)
        var k = 0
        for (i in ts.indices) for (j in i + 1 until ts.size) if (ts[j] != ts[i]) out[k++] = (vs[j] - vs[i]) / (ts[j] - ts[i])
        return out.copyOf(k)
    }

    private fun quadraticTheilSen(
        ts: DoubleArray,
        vs: DoubleArray,
    ): Double = quadraticSlopes(ts, vs).let { if (it.isEmpty()) 0.0 else Flatness.median(it) }
}
