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
    }
}

