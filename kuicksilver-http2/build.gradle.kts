// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// HTTP/2 (RFC 9113) and HPACK (RFC 7541): a sans-IO frame codec, header compression and connection state (ADR-0017).
// No QUIC and no TLS: kuicksilver-native only for the API annotations; the Ktor engines bring the socket and TLS.
plugins {
    id("kuicksilver.kmp")
    id("kuicksilver.publish")
}
kotlin {
    sourceSets {
        commonMain.dependencies {
            api(project(":kuicksilver-native"))
        }
        jvmTest.dependencies {
            implementation(kotlin("test-junit5"))
            implementation(libs.jazzer.junit)
        }
    }
}
tasks.named<Test>("jvmTest") { useJUnitPlatform() }

// Sans-IO rule (ADR-0004) for the frame codec, HPACK, the connection core and the message rules; see tools/check/sans-io.sh.
val checkHttp2Architecture = tasks.register("checkHttp2Architecture") {
    group = "verification"; description = "Runs the sans-IO rule for the HTTP/2 frame codec, HPACK, the connection core and the message rules"
    val script = rootProject.file("tools/check/sans-io.sh").path
    val module = project.name; val workDir = rootProject.projectDir
    doLast {
        val p = ProcessBuilder("bash", script, module, "http2", "frame", "hpack", "core", "message").directory(workDir).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText(); val rc = p.waitFor(); println(out.trim())
        if (rc != 0) throw GradleException("architecture check failed: $script")
    }
}
tasks.named("check") { dependsOn(checkHttp2Architecture) }
