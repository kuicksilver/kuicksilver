// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import platform.posix.getenv

@OptIn(ExperimentalForeignApi::class)
public actual fun simRuns(default: Int): Int = getenv("KSL_SIM_RUNS")?.toKString()?.toIntOrNull() ?: default

public actual fun recordFailure(
    test: String,
    seed: Long,
    params: LinkParams,
) {
    println("sim failure: $test seed=$seed $params")
}

@OptIn(ExperimentalForeignApi::class)
public actual fun simForceViolation(): Boolean = getenv("KSL_SIM_FORCE_VIOLATION")?.toKString() == "true"
