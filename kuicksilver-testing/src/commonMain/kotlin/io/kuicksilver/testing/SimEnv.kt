// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

/** `KSL_SIM_RUNS` from the environment, or [default]. */
public expect fun simRuns(default: Int): Int

/** Appends the failing seed and parameters to `build/sim-failures/<test>.txt` so a run can be replayed. */
public expect fun recordFailure(
    test: String,
    seed: Long,
    params: LinkParams,
)

/** `KSL_SIM_FORCE_VIOLATION` (or the JVM property `kuicksilver.sim.forceViolation`): makes every invariant check fail — the CI's proof that the simulator step can go red. */
public expect fun simForceViolation(): Boolean
