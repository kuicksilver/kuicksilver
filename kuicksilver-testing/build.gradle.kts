// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// Deterministic network simulator and scenario helpers for the QUIC core (not published).
plugins {
    id("kuicksilver.kmp")
}
kotlin {
    sourceSets {
        commonMain.dependencies {
            api(project(":kuicksilver-quic"))
        }
    }
}

// Monte-Carlo size: -Pkuicksilver.sim.runs=N (the test also honours KSL_SIM_RUNS when the environment reaches the test JVM).
tasks.withType<Test>().configureEach {
    providers.gradleProperty("kuicksilver.sim.runs").orNull?.let { systemProperty("kuicksilver.sim.runs", it); environment("KSL_SIM_RUNS", it) }
    // -Pkuicksilver.sim.forceViolation=true makes every invariant fail: the CI checks that the simulator step can go red
    providers.gradleProperty("kuicksilver.sim.forceViolation").orNull?.let { systemProperty("kuicksilver.sim.forceViolation", it); environment("KSL_SIM_FORCE_VIOLATION", it) }
}
