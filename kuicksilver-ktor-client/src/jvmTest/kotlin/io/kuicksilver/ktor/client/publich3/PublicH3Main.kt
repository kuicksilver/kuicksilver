// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:JvmName("PublicH3Main")

package io.kuicksilver.ktor.client.publich3

import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.system.exitProcess
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.TimeSource

/** The checks [target] takes part in: every target the universal ones, ECH where its HTTPS record publishes a configuration. */
internal fun checksOf(target: Target): List<Check> = Check.entries.filter { it != Check.Ech || target.ech }

/** The summary's cell for [j]: the verdict as a word, `FAIL` in capitals so it stands out. */
private fun cell(j: Judged?): String =
    when (j?.verdict) {
        null -> "-"
        Verdict.Pass -> "pass"
        Verdict.NotApplicable -> "n/a"
        Verdict.Warn -> "warn"
        Verdict.Fail -> "FAIL"
    }

/**
 * [s] as plain text for the summary, the annotations and the log: a reason can quote a server (a close's reason phrase, a
 * trace line, an exception message), so control characters and Markdown or HTML syntax become spaces, a bare URL is broken
 * (`https:// host`, `www. host`) so that GitHub's Markdown does not turn it into a link, and it is cut to 300 characters.
 */
internal fun plain(s: String): String =
    s
        .take(300)
        .map { if (it < ' ' || it == '\u007f' || it in "<>[]`*_") ' ' else it }
        .joinToString("")
        .replace("://", ":// ")
        .replace(Regex("(?i)\\bwww\\."), "www. ")

/**
 * The job summary (Markdown): one row per target and one column per check, then every judgement with its reason, the UDP
 * control (the versions each target's Version Negotiation listed, [control]), then the policy in one line. [results] maps
 * a target's name to its checks' judgements, in [TARGETS] order.
 */
internal fun summaryMarkdown(
    results: Map<String, Map<Check, Judged>>,
    control: Map<String, List<Int>?> = emptyMap(),
): String =
    buildString {
        val worst = results.values.flatMap { it.values }.maxOfOrNull { it.verdict } ?: Verdict.Pass
        appendLine(
            "## Public HTTP/3 servers: ${if (worst == Verdict.Fail) {
                "FAIL"
            } else if (worst == Verdict.Warn) {
                "warnings"
            } else {
                "pass"
            }}",
        )
        appendLine()
        appendLine("| Target | Stack | " + Check.entries.joinToString(" | ") { it.label } + " |")
        appendLine("|---|---|" + Check.entries.joinToString("") { "---|" })
        for ((name, checks) in results) {
            val stack = TARGETS.firstOrNull { it.name == name }?.stack ?: ""
            appendLine("| $name | $stack | " + Check.entries.joinToString(" | ") { cell(checks[it]) } + " |")
        }
        appendLine()
        for ((name, checks) in results) {
            for ((c, j) in checks) appendLine("- **$name, ${c.label}**: ${cell(j)}. ${plain(j.reason).replace("|", "\\|")}")
        }
        if (control.isNotEmpty()) {
            appendLine()
            val open = control.count { it.value != null }
            appendLine(
                "UDP control (a Version Negotiation probe to port 443, without our QUIC stack): $open of ${control.size} targets " +
                    "answered" + if (open == 0) "; the runner's network blocks QUIC, so no QUIC verdict is escalated." else ".",
            )
            for ((name, v) in control) appendLine("- $name: ${v?.joinToString(", ") { versionName(it) } ?: "no answer"}")
        }
        appendLine()
        appendLine(
            "warn: the server changed or was unreachable (not our client; no red build). FAIL: our client is wrong (twice in a " +
                "row, or the check passed on no reachable target). Policy: docs/how-we-verify.md, \"Public HTTP/3 servers\".",
        )
    }

private fun jsonString(s: String): String =
    buildString {
        append('"')
        for (ch in s) {
            when {
                ch == '"' -> append("\\\"")
                ch == '\\' -> append("\\\\")
                ch < ' ' -> append("\\u%04x".format(ch.code))
                else -> append(ch)
            }
        }
        append('"')
    }

/** The machine-readable results: `[{"target", "check", "verdict", "reason"}]`, for the workflow's annotations. */
internal fun resultsJson(results: Map<String, Map<Check, Judged>>): String =
    results
        .flatMap { (name, checks) ->
            checks.map { (c, j) ->
                "{\"target\":${jsonString(name)},\"check\":${jsonString(c.label)},\"verdict\":${jsonString(j.verdict.name)}," +
                    "\"reason\":${jsonString(plain(j.reason))}}"
            }
        }.joinToString(",\n", "[\n", "\n]\n")

/** How long the checks may run in all: the run then writes what it has, well before the job's own timeout. */
internal val RUN_DEADLINE: Duration = 40.minutes

/** The judgement of a check the run's deadline left out: a warning that [escalate] skips (offline: it never ran). */
internal val NOT_RUN = Judged(Verdict.Warn, "not run: the run's ${RUN_DEADLINE.inWholeMinutes}-minute deadline had passed", offline = true)

/** Escalates [raw], writes the summary and the results to [out], and returns the escalated results. */
private fun write(
    out: Path,
    raw: Map<String, Map<Check, Judged>>,
    control: Map<String, List<Int>?>,
): Map<String, Map<Check, Judged>> {
    val results = escalate(raw, quicPathOpen = control.values.any { it != null })
    Files.writeString(out.resolve("summary.md"), summaryMarkdown(results, control))
    Files.writeString(out.resolve("results.json"), resultsJson(results))
    return results
}

/**
 * The public HTTP/3 check (`.github/workflows/public-h3.yml`; docs/how-we-verify.md, "Public HTTP/3 servers"): every
 * check of [checksOf] against every target of [TARGETS], one at a time, a second attempt for a check that did not pass,
 * then [escalate], unless the UDP control ([versionNegotiationFrom]) got no answer from any target. Writes `summary.md`,
 * `results.json` (after every target too, so a run cut short leaves what it had) and the qlog traces of what went wrong
 * (`qlog/`) to `args[0]`, and exits 1 when a verdict is Fail, 0 otherwise (warnings included). Checks still to run when
 * [RUN_DEADLINE] has passed are [NOT_RUN].
 *
 * Run with `./gradlew --max-workers=2 :kuicksilver-ktor-client:publicH3Check`, only on a machine whose network may be
 * used for it and where UDP to port 443 and the public DNS work (GitHub's runners).
 */
fun main(args: Array<String>) {
    val out: Path = Paths.get(args.firstOrNull() ?: "build/public-h3")
    Files.createDirectories(out)
    KslLoader.ensureLoaded()
    // the control first: does UDP to port 443 get an answer at all, without our QUIC stack?
    val control = TARGETS.associate { it.name to versionNegotiationFrom(it.host) }
    println(
        "public-h3: UDP control: " +
            control.entries.joinToString { (n, v) -> "$n ${v?.joinToString("/") { versionName(it) } ?: "no answer"}" },
    )
    val probe = PublicH3Probe(out)
    val raw = LinkedHashMap<String, Map<Check, Judged>>()
    val start = TimeSource.Monotonic.markNow()
    runBlocking {
        for (t in TARGETS) {
            val checks = LinkedHashMap<Check, Judged>()
            for (c in checksOf(t)) {
                if (start.elapsedNow() > RUN_DEADLINE) {
                    checks[c] = NOT_RUN
                    continue
                }
                val first = probe.attempt(t, c, 1)
                val second = if (first.verdict == Verdict.Warn || first.verdict == Verdict.Fail) probe.attempt(t, c, 2) else null
                checks[c] = combine(first, second)
                println("public-h3: ${t.name} ${c.label}: ${checks.getValue(c).verdict} (${plain(checks.getValue(c).reason)})")
            }
            raw[t.name] = checks
            write(out, raw, control)
        }
    }
    val results = write(out, raw, control)
    print(Files.readString(out.resolve("summary.md")))
    exitProcess(if (results.values.any { checks -> checks.values.any { it.verdict == Verdict.Fail } }) 1 else 0)
}
