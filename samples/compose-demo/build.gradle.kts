// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// Kotlin and AGP as in this repository's gradle/libs.versions.toml; Compose Multiplatform is the demo's own (the library
// does not use it): 1.12.2, the release whose Gradle plugin pairs it with Material 3 1.9.0 (ComposeBuildConfig).

// The floors of ../../build-logic/build.gradle.kts on this build's plugin class path: AGP 9.3 asks for releases with known
// vulnerabilities (OSV), each floor is the first fixed release. Tool code only, never in the app.
buildscript {
    dependencies {
        constraints {
            // GHSA-3677-xxcr-wjqv: com.android.tools.build:bundletool 1.18.3 asks for 0.9.5
            classpath("org.bitbucket.b_c:jose4j:0.9.6") { because("first release without the known vulnerabilities") }
            // GHSA-2363-cqg2-863c: com.android.tools.build.jetifier:jetifier-processor 1.0.0-beta10 asks for 2.0.6
            classpath("org.jdom:jdom2:2.0.6.1") { because("first release without the known vulnerabilities") }
        }
    }
}

plugins {
    kotlin("multiplatform") version "2.4.20" apply false
    kotlin("jvm") version "2.4.20" apply false
    kotlin("plugin.compose") version "2.4.20" apply false
    id("org.jetbrains.compose") version "1.12.2" apply false
    id("com.android.application") version "9.3.3" apply false
    id("com.android.kotlin.multiplatform.library") version "9.3.3" apply false
}

// the Kuicksilver version under test, read by every module; the composite build substitutes it unless
// -Pkuicksilver.fromMavenLocal=true
extra["kuicksilver"] = providers.gradleProperty("kuicksilver.version").getOrElse("0.3.0-SNAPSHOT")
