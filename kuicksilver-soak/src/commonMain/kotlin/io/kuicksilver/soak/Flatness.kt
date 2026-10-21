// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min
import kotlin.random.Random

/**
 * The flatness verdict for one sampled resource.
 *
 * Statistic: the Theil–Sen slope (the median of the slopes between every pair of post-warm-up samples; a fixed-seed
 * sample of [MAX_PAIRS] pairs beyond 2,048 samples, see [theilSen]) times the length of that window, i.e. the growth the
 * trend line predicts across the window. Why this one:
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
        /**
         * At most this many pairwise slopes are held (16 MiB of doubles): up to 2,048 samples (8.5 h after warm-up at 15 s)
         * every pair is used, beyond that a sample of pairs; see [theilSen].
         */
        internal const val MAX_PAIRS: Int = 1 shl 21

        /** Seed of the pair sample: the same series always gets the same verdict. */
        private const val PAIR_SEED: Long = 0x5EED_7E11_5E9L

        /**
         * The Theil–Sen slope: the median of the slopes between pairs of points (pairs with equal time are skipped).
         *
         * Up to [MAX_PAIRS] pairs (n ≤ 2,048) it is exact, the median of every pair. Beyond that the n(n−1)/2 pairs no longer
         * fit — a 72-hour soak at the default 15 s has ~13,800 samples after warm-up, ~95 M pairs — and it is the median of
         * [MAX_PAIRS] pairs drawn uniformly, with replacement, from a fixed seed, so a series always gets the same verdict.
         * The rank of that median among all pairwise slopes has a standard deviation of about 1/(2√[MAX_PAIRS]), 0.035
         * percentile, far finer than the bound the growth is compared with, and the robustness to outlying samples is the
         * same. Memory is O([MAX_PAIRS]) and time O(n + [MAX_PAIRS]) for a run of any length. The exact O(n log n)
         * slope-selection algorithms (Cole–Salowe–Steiger–Szemerédi, Matoušek, Dillencourt–Mount–Netanyahu) were not
         * chosen: much more code for no difference in the verdict.
         */
        public fun theilSen(
            t: DoubleArray,
            v: DoubleArray,
        ): Double {
            val slopes = pairSlopes(t, v)
            if (slopes.isEmpty()) return 0.0
            val m = slopes.size / 2
            val upper = select(slopes, m)
            if (slopes.size % 2 == 1) return upper
            var lower = slopes[0] // after select, slopes[0 until m] are the m smallest
            for (i in 1 until m) if (slopes[i] > lower) lower = slopes[i]
            return (lower + upper) / 2
        }

        /** The slopes [theilSen] takes the median of: every pair up to [MAX_PAIRS] pairs, else [MAX_PAIRS] sampled pairs. */
        internal fun pairSlopes(
            t: DoubleArray,
            v: DoubleArray,
        ): DoubleArray {
            require(t.size == v.size)
            val n = t.size
            if (n < 2) return DoubleArray(0)
            val pairs = n.toLong() * (n - 1) / 2
            if (pairs <= MAX_PAIRS) {
                val out = DoubleArray(pairs.toInt())
                var k = 0
                for (i in 0 until n) for (j in i + 1 until n) if (t[j] != t[i]) out[k++] = (v[j] - v[i]) / (t[j] - t[i])
                return if (k == out.size) out else out.copyOf(k)
            }
            // uniform over unordered pairs: an ordered pair i ≠ j, then the earlier index first as in the exact case
            val r = Random(PAIR_SEED)
            val out = DoubleArray(MAX_PAIRS)
            var k = 0
            var attempts = 0L
            while (k < out.size && attempts < 8L * MAX_PAIRS) { // the cap only bites when most pairs share a time
                attempts++
                val a = r.nextInt(n)
                var b = r.nextInt(n - 1)
                if (b >= a) b++
                val i = min(a, b)
                val j = max(a, b)
                if (t[j] != t[i]) out[k++] = (v[j] - v[i]) / (t[j] - t[i])
            }
            return if (k == out.size) out else out.copyOf(k)
        }

        /** The [k]-th smallest of [a] (0-based), reordering [a] so that `a[0 until k]` hold smaller or equal values (Hoare). */
        private fun select(
            a: DoubleArray,
            k: Int,
        ): Double {
            var lo = 0
            var hi = a.size - 1
            while (lo < hi) {
                val pivot = a[(lo + hi) ushr 1]
                var i = lo
                var j = hi
                while (i <= j) {
                    while (a[i] < pivot) i++
                    while (a[j] > pivot) j--
                    if (i <= j) {
                        val x = a[i]
                        a[i] = a[j]
                        a[j] = x
                        i++
                        j--
                    }
                }
                when {
                    k <= j -> hi = j
                    k >= i -> lo = i
                    else -> return a[k]
                }
            }
            return a[k]
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
