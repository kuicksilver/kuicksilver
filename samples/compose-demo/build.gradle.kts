// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// Kotlin and AGP as in this repository's gradle/libs.versions.toml; Compose Multiplatform is the demo's own (the library
// does not use it): 1.12.2, the release whose Gradle plugin pairs it with Material 3 1.9.0 (ComposeBuildConfig).
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
