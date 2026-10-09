// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// Throughput benchmark and the steady-state allocation gate for the QUIC core (not published; JVM and Linux x64 only).
plugins {
    id("org.jetbrains.kotlin.multiplatform")
    id("org.jetbrains.kotlin.plugin.allopen")
    id("org.jetbrains.kotlinx.benchmark")
}
kotlin {
    jvmToolchain(21)
    jvm()
    linuxX64()
    sourceSets {
        commonMain.dependencies {
            implementation(project(":kuicksilver-quic"))
            implementation(libs.kotlinx.benchmark.runtime)
        }
        jvmTest.dependencies { implementation(kotlin("test-junit5")) }
    }
}
allOpen { annotation("org.openjdk.jmh.annotations.State") }
benchmark {
    // the benchmark plugin refuses a native target it cannot run on this host (a Linux arm64 container running the JVM suites); the JVM gate is what matters there
    val linuxArmHost = System.getProperty("os.name").lowercase().contains("linux") && System.getProperty("os.arch").lowercase() in setOf("aarch64", "arm64")
    targets { register("jvm"); if (!linuxArmHost) register("linuxX64") }
    configurations {
        named("main") { warmups = 3; iterations = 5; iterationTime = 2; iterationTimeUnit = "s"; mode = "thrpt"; outputTimeUnit = "s"; advanced("jvmForks", "1") }
    }
}
tasks.named<Test>("jvmTest") {
    useJUnitPlatform(); maxHeapSize = "1g"
    // -Pkuicksilver.jfr=<file> records the allocation gate with JFR (inspect with `jfr view allocation-by-site <file>`)
    providers.gradleProperty("kuicksilver.jfr").orNull?.let { jvmArgs("-XX:StartFlightRecording=filename=$it,settings=profile") }
    // -Pkuicksilver.jfrExact=<file> records every allocation (TLABs off) so rare sites show up; pair it with allocTrace for the window bounds
    providers.gradleProperty("kuicksilver.jfrExact").orNull?.let { jvmArgs("-XX:-UseTLAB", "-XX:StartFlightRecording=filename=$it,jdk.ObjectAllocationOutsideTLAB#enabled=true,jdk.ObjectAllocationOutsideTLAB#stackTrace=true,jdk.ObjectAllocationSample#enabled=false") }
    // -Pkuicksilver.allocTrace prints every step of the gate window that allocated, with the byte count
    if (providers.gradleProperty("kuicksilver.allocTrace").isPresent) { environment("KUICKSILVER_ALLOC_TRACE", "1"); testLogging.showStandardStreams = true }
}
tasks.withType<Test>().configureEach { providers.gradleProperty("kuicksilver.native.path").orNull?.let { systemProperty("kuicksilver.native.path", it) } }
