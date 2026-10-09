// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

import java.io.File

public actual fun simRuns(default: Int): Int =
    System.getProperty("kuicksilver.sim.runs")?.toIntOrNull() ?: System.getenv("KSL_SIM_RUNS")?.toIntOrNull() ?: default

public actual fun recordFailure(
    test: String,
    seed: Long,
    params: LinkParams,
) {
    val f = File("build/sim-failures/$test.txt")
    f.parentFile.mkdirs()
    f.appendText("seed=$seed $params\n")
}

public actual fun simForceViolation(): Boolean =
    System.getProperty("kuicksilver.sim.forceViolation") == "true" || System.getenv("KSL_SIM_FORCE_VIOLATION") == "true"
