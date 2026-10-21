// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/** The report of a long run: every series judged and written, read column by column without rebuilding maps. */
class SoakResultTest {
    @Test fun aSevenDayRunIsJudgedAndWritten() {
        val metrics = List(50) { "m$it" }
        val n = 40_320 // 7 days at 15 s
        val samples =
            List(n) { i ->
                val row = metrics.withIndex().associate { (j, k) -> k to (1000L + j + (i * 7 + j) % 13) }
                Sample(i * 15.0, if (i < n / 2) row else row + ("late" to 7L)) // a metric that appears halfway: a new key table
            }
        val result = SoakResult(SoakConfig(7.days), emptyMap(), samples, emptyMap(), emptyList(), 0.seconds, emptyMap())
        val mark = TimeSource.Monotonic.markNow()
        val verdicts = result.verdicts
        val csv = result.csv().lines()
        println("$n samples x ${metrics.size + 1} metrics: verdicts and CSV in ${mark.elapsedNow()}")
        assertEquals(metrics + "late", verdicts.map { it.metric })
        assertTrue(verdicts.all { it.flat }, verdicts.filter { !it.flat }.toString())
        assertEquals(n - n / 5, verdicts.first { it.metric == "m0" }.samples)
        assertEquals(n / 2, verdicts.first { it.metric == "late" }.samples)
        assertEquals(n + 2, csv.size) // header, rows, the empty string after the last newline
        assertEquals("t_s," + metrics.joinToString(",") + ",late", csv[0])
        assertEquals("0," + metrics.indices.joinToString(",") { "${1000 + it + it % 13}" } + ",", csv[1])
        assertTrue(csv[n].endsWith(",7"), csv[n])
    }
}
