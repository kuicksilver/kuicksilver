// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.writeString
import kotlin.time.Duration

/** The run's data and its verdict; [write] puts `<label>.csv` (every sample) and `<label>.md` (the summary) into the report directory. */
internal class SoakResult(
    val config: SoakConfig,
    val baseline: Map<String, Long>,
    val samples: List<Sample>,
    val end: Map<String, Long>,
    val returned: List<Returned>,
    val quietTook: Duration,
    val stats: Map<Scenario, ScenarioStats>,
) {
    val iterations: Long get() = stats.values.sumOf { it.iterations }
    val failures: Long get() = stats.values.sumOf { it.failed }

    /** Samples after the warm-up: the flatness window. */
    val window: List<Sample> get() = samples.filter { it.t >= config.warmup.inWholeMilliseconds / 1000.0 }

    val verdicts: List<Flatness.Verdict> by lazy {
        val w = window
        val keys = samples.flatMap { it.values.keys }.distinct().filter { it !in UNJUDGED }
        keys.map { k ->
            val pts = w.filter { k in it.values }
            boundFor(k).judge(k, pts.map { it.t }.toDoubleArray(), pts.map { it.values.getValue(k).toDouble() }.toDoubleArray())
        }
    }

    val failureRateOk: Boolean get() = iterations > 0 && failures * 1000 <= iterations * 5

    val passed: Boolean get() = window.size >= 3 && verdicts.all { it.flat } && returned.all { it.ok } && failureRateOk

    fun summary(): String =
        buildString {
            appendLine("# Soak `${config.label}`: ${if (passed) "PASS" else "FAIL"}")
            appendLine()
            appendLine(
                "Duration ${config.duration}, ${config.clients} clients, rate ceiling ${config.rate}/s, " +
                    "sample every ${config.sampleEvery}, warm-up ${config.warmup}; ${samples.size} samples, ${window.size} after warm-up.",
            )
            appendLine()
            appendLine("Iterations $iterations, unexpected failures $failures (${pct(failures, iterations)}; limit 0.5%).")
            appendLine()
            appendLine("| Scenario | Iterations | Outcomes | Unexpected |")
            appendLine("|---|---:|---|---:|")
            for ((s, st) in stats) {
                appendLine(
                    "| $s | ${st.iterations} | ${st.outcomes.entries.joinToString(", ") { "${it.key} ${it.value}" }} | ${st.failed} |",
                )
            }
            val fails = stats.flatMap { (s, st) -> st.failures.map { Triple(s, it.key, it.value) } }.sortedByDescending { it.third }
            if (fails.isNotEmpty()) {
                appendLine()
                appendLine("Unexpected failures (top 15):")
                appendLine()
                for ((s, msg, n) in fails.take(15)) appendLine("- $s × $n: `${msg.replace('`', '\'')}`")
            }
            appendLine()
            appendLine("## Flatness after warm-up (Theil–Sen growth over the window)")
            appendLine()
            appendLine("| Metric | Baseline | Median | Slope / h | Growth | Bound | Verdict |")
            appendLine("|---|---:|---:|---:|---:|---:|---|")
            for (v in verdicts) {
                appendLine(
                    "| ${v.metric} | ${baseline[v.metric] ?: ""} | ${num(
                        v.median,
                    )} | ${num(v.slopePerHour)} | ${num(v.projectedGrowth)} | ${num(v.bound)} | " +
                        "${if (v.flat) "flat" else "**GROWING**"} |",
                )
            }
            appendLine()
            appendLine("## Return to the idle baseline (quiet period ${quietTook.inWholeSeconds} s)")
            appendLine()
            appendLine("| Metric | Baseline | End | Tolerance | Verdict |")
            appendLine("|---|---:|---:|---:|---|")
            for (r in returned) {
                appendLine(
                    "| ${r.metric} | ${r.baseline} | ${r.end} | ${r.tolerance} | ${if (r.ok) "ok" else "**LEAK**"} |",
                )
            }
        }

    fun csv(): String =
        buildString {
            val keys = samples.flatMap { it.values.keys }.distinct()
            appendLine((listOf("t_s") + keys).joinToString(","))
            for (s in samples) appendLine((listOf(num(s.t)) + keys.map { s.values[it]?.toString() ?: "" }).joinToString(","))
        }

    /** Writes the report files; returns the Markdown path, or null without a report directory. */
    fun write(): String? {
        val dir = config.reportDir ?: return null
        SystemFileSystem.createDirectories(Path(dir))
        val md = "$dir/${config.label}.md"
        SystemFileSystem.sink(Path("$dir/${config.label}.csv")).buffered().use { it.writeString(csv()) }
        SystemFileSystem.sink(Path(md)).buffered().use { it.writeString(summary()) }
        return md
    }

    companion object {
        /** Series that grow by design. */
        val UNJUDGED: Set<String> = setOf("soak.iterations")

        /** The bound per kind of series (see [Flatness]): memory in KiB, descriptors, threads, buffers, then counts. */
        fun boundFor(metric: String): Flatness =
            when {
                metric == "proc.rssKiB" -> Flatness(absolute = 32 * 1024.0, relative = 0.10)
                metric.endsWith("heapAfterGcKiB") -> Flatness(absolute = 16 * 1024.0, relative = 0.10)
                metric == "jvm.directKiB" -> Flatness(absolute = 4 * 1024.0, relative = 0.10)
                metric == "jvm.directBuffers" -> Flatness(absolute = 64.0, relative = 0.10)
                metric == "proc.fds" -> Flatness(absolute = 8.0, relative = 0.10)
                metric == "jvm.threads" -> Flatness(absolute = 8.0, relative = 0.10)
                else -> Flatness(absolute = 5.0, relative = 0.25)
            }

        private fun pct(
            a: Long,
            b: Long,
        ): String = if (b == 0L) "n/a" else num(a * 100.0 / b) + "%"

        fun num(d: Double): String {
            val r = kotlin.math.round(d * 100) / 100
            return if (r == kotlin.math.floor(r)) r.toLong().toString() else r.toString()
        }
    }
}

/** Writes [text] to [dir]/[name], creating [dir]. */
internal fun writeText(
    dir: String,
    name: String,
    text: String,
) {
    SystemFileSystem.createDirectories(Path(dir))
    SystemFileSystem.sink(Path("$dir/$name")).buffered().use { it.writeString(text) }
}
