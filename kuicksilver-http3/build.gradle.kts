// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// HTTP/3 (RFC 9114), QPACK (RFC 9204), priorities (RFC 9218), Extended CONNECT (RFC 9220) and HTTP datagrams (RFC 9297) over kuicksilver-quic.
plugins {
    id("kuicksilver.kmp")
    id("kuicksilver.publish")
}
kotlin {
    sourceSets {
        commonMain.dependencies {
            api(project(":kuicksilver-quic"))
        }
        jvmTest.dependencies {
            implementation(kotlin("test-junit5"))
            implementation(libs.jazzer.junit)
        }
    }
}
tasks.named<Test>("jvmTest") { useJUnitPlatform() }

// Sans-IO rule (ADR-0004) for the HTTP/3 and QPACK codecs; see tools/check/sans-io.sh.
val checkHttp3Architecture by tasks.registering {
    group = "verification"; description = "Runs the sans-IO rule for the HTTP/3 frame, QPACK and message codecs"
    val script = rootProject.file("tools/check/sans-io.sh").path
    val module = project.name; val workDir = rootProject.projectDir
    doLast {
        val p = ProcessBuilder("bash", script, module, "http3", "frame", "qpack", "message").directory(workDir).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText(); val rc = p.waitFor(); println(out.trim())
        if (rc != 0) throw GradleException("architecture check failed: $script")
    }
}
tasks.named("check") { dependsOn(checkHttp3Architecture) }
