// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

import kotlin.math.abs
import kotlin.math.max

/**
 * The flatness verdict for one sampled resource.
 *
 * Statistic: the Theil–Sen slope (the median of the slopes between every pair of post-warm-up samples) times the length
 * of that window, i.e. the growth the trend line predicts across the window. Why this one:
 * - a leak is a sustained trend; a load test's samples are a level plus noise — in-flight connections, GC saw-teeth,
 *   allocator steps — and the median of pairwise slopes ignores up to ~29% outlying samples (its breakdown point), so a
 *   GC that happens to land on one sample, or a burst of in-flight handshakes, does not move it, where a least-squares
 *   slope or a first-vs-last difference would;
 * - it needs no distribution assumption and is exact for a perfect line, so a slow, steady leak of one object per few
 *   hundred iterations shows up as a positive slope even when the noise is larger than the leak at any single sample.
 *
 * Bound: the projected growth must stay within `max(absolute, relative × median level)`; the absolute floor absorbs
 * quantisation of small counts (a level of 3 ± 2 in-flight connections), the relative part absorbs allocator and JIT
 * drift of large levels (RSS). Countable resources are also checked for an exact return to their idle baseline after
 * the load stops (see [Soak]), which a slow leak cannot pass.
 */
public class Flatness(
    public val absolute: Double,
    public val relative: Double,
) {
    /** The outcome for one series. */
    public class Verdict(
        public val metric: String,
        public val samples: Int,
        public val median: Double,
        public val slopePerHour: Double,
        public val projectedGrowth: Double,
        public val bound: Double,
    ) {
        public val flat: Boolean get() = projectedGrowth <= bound

        override fun toString(): String {
            val growth = "growth over window ${fmt(projectedGrowth)} (bound ${fmt(bound)})"
            return "$metric: median ${fmt(median)}, slope ${fmt(slopePerHour)}/h, $growth " +
                if (flat) "flat" else "GROWING"
        }
    }

    /** [t] in seconds, [v] the samples; at least three points (fewer is reported flat with zero growth). */
    public fun judge(
        metric: String,
        t: DoubleArray,
        v: DoubleArray,
    ): Verdict {
        require(t.size == v.size)
        val med = median(v)
        val bound = max(absolute, relative * abs(med))
        if (t.size < 3) return Verdict(metric, t.size, med, 0.0, 0.0, bound)
        val slope = theilSen(t, v)
        val window = t.last() - t.first()
        return Verdict(metric, t.size, med, slope * 3600.0, slope * window, bound)
    }

    public companion object {
        /** The median of pairwise slopes (pairs with equal time are skipped). O(n²) pairs: a 2-hour run at 15 s has 480 samples, ~115k pairs. */
        public fun theilSen(
            t: DoubleArray,
            v: DoubleArray,
        ): Double {
            val slopes = ArrayList<Double>(t.size * (t.size - 1) / 2)
            for (i in t.indices) for (j in i + 1 until t.size) if (t[j] != t[i]) slopes += (v[j] - v[i]) / (t[j] - t[i])
            return if (slopes.isEmpty()) 0.0 else median(slopes.toDoubleArray())
        }

        public fun median(v: DoubleArray): Double {
            if (v.isEmpty()) return 0.0
            val s = v.sortedArray()
            val m = s.size / 2
            return if (s.size % 2 == 1) s[m] else (s[m - 1] + s[m]) / 2
        }

        private fun fmt(d: Double): String {
            val r = kotlin.math.round(d * 100) / 100
            return r.toString()
        }
    }
}
