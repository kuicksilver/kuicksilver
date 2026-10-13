// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

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

    @Test fun returnToBaselineHonoursTolerance() {
        val r = Soak.returned(mapOf("ksl.ssl" to 3, "proc.fds" to 40), mapOf("ksl.ssl" to 4, "proc.fds" to 43))
        assertFalse(r.first { it.metric == "ksl.ssl" }.ok)
        assertTrue(r.first { it.metric == "proc.fds" }.ok)
    }
}
