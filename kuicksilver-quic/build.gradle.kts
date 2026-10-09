// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

plugins {
    id("kuicksilver.kmp")
    id("kuicksilver.publish")
}
kotlin {
    sourceSets {
        commonMain.dependencies {
            api(project(":kuicksilver-tls"))
            api(libs.ktor.network)
        }
        jvmTest.dependencies {
            implementation(kotlin("test-junit5"))
            implementation(libs.jazzer.junit)
        }
    }
}
// 1 GiB: MultiLoopTest runs 100 concurrent 1 MiB echoes on Linux (Gradle's 512 MiB default overflowed there)
tasks.named<Test>("jvmTest") { useJUnitPlatform(); maxHeapSize = "1g" }

// Architecture checks (ADR-0004 sans-IO rule; only `PacketBuffer` and annotations may be imported from kuicksilver-native); see tools/check.
val checkQuicArchitecture by tasks.registering {
    group = "verification"; description = "Runs the sans-IO and import rules for the QUIC core"
    val scripts = listOf(rootProject.file("tools/check/sans-io.sh"), rootProject.file("tools/check/quic-imports.sh")).map { it.path }
    val module = project.name; val workDir = rootProject.projectDir
    doLast {
        for (script in scripts) {
            val p = ProcessBuilder("bash", script, module).directory(workDir).redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText(); val rc = p.waitFor(); println(out.trim())
            if (rc != 0) throw GradleException("architecture check failed: $script")
        }
    }
}
tasks.named("check") { dependsOn(checkQuicArchitecture) }
