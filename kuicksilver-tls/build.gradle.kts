// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

plugins {
    id("kuicksilver.kmp")
    id("kuicksilver.publish")
}
kotlin {
    sourceSets {
        commonMain.dependencies {
            api(project(":kuicksilver-native"))
            api(libs.kotlinx.coroutines.core)
            api(libs.kotlinx.io.core)
            api(libs.ktor.io)
        }
    }
}

// negative_keylogDisabledInRelease: the variable is set, and nothing may honour it (OpenSSL is built with no-sslkeylog)
tasks.withType<Test>().configureEach { environment("SSLKEYLOGFILE", layout.buildDirectory.file("must-not-exist-keylog.txt").get().asFile.path) }
