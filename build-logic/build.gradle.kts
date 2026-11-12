// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

plugins { `kotlin-dsl` }
dependencies {
    implementation(libs.kotlin.gradle.plugin)
    implementation(libs.android.gradle.plugin)
    implementation(libs.dokka.gradle.plugin)
    implementation(libs.kotlinter.gradle.plugin)
    implementation(libs.maven.publish.gradle.plugin)
    implementation(libs.kotlinx.benchmark.gradle.plugin)
    implementation(libs.kotlin.allopen.gradle.plugin)
    implementation(libs.kover.gradle.plugin)
    // Version floors on the plugin class path (it is the root build's too): AGP 9.3 asks for releases with known
    // vulnerabilities (OSV), each floor is the first fixed release. Tool code only, never in a published module; the
    // floors of the plugins' own configurations (lint, Swift export) are in ../settings.gradle.kts.
    constraints {
        // GHSA-3677-xxcr-wjqv: com.android.tools.build:bundletool 1.18.3 asks for 0.9.5
        implementation("org.bitbucket.b_c:jose4j:0.9.6") { because("first release without the known vulnerabilities") }
        // GHSA-2363-cqg2-863c: com.android.tools.build.jetifier:jetifier-processor 1.0.0-beta10 asks for 2.0.6
        implementation("org.jdom:jdom2:2.0.6.1") { because("first release without the known vulnerabilities") }
    }
}
