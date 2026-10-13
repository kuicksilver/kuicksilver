// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * The soak run itself; does nothing unless `-Pkuicksilver.soak.minutes=<m>` (environment `KSL_SOAK_MINUTES`) is set, so a
 * plain `check` never runs it. See CONTRIBUTING.md, "Soak and churn".
 */
class SoakTest {
    /** `-Pkuicksilver.soak.attribute=N`: every scenario alone N times, with the change of each countable resource (leak attribution). */
    @Test fun attribute() {
        val n = ProcessResources.env("KSL_SOAK_ATTRIBUTE")?.toIntOrNull() ?: return
        val only = Scenario.fromEnvironment()
        val result = runBlocking { Soak(SoakConfig(kotlin.time.Duration.ZERO)).attribute(n, only) }
        val text = result.entries.joinToString("\n") { (s, d) -> "$s: " + d.filterValues { it != 0L } }
        println(text)
        ProcessResources.env("KSL_SOAK_DEFAULT_REPORT")?.let { dir -> writeText(dir, "attribution.txt", text) }
        val leaking = result.filterValues { d -> d.any { (k, v) -> k in Soak.COUNTABLE && v > Soak.COUNTABLE.getValue(k) } }
        assertTrue(leaking.isEmpty(), "scenarios leaving resources behind: $leaking")
    }

    @Test fun soak() {
        val config = SoakConfig.fromEnvironment() ?: return
        val result = runBlocking { Soak(config).run() }
        val path = result.write()
        println(result.summary())
        if (path != null) println("[soak ${config.label}] report: $path")
        assertTrue(result.passed, "soak ${config.label} failed; report: ${path ?: "(none)"}\n" + result.summary())
    }
}
