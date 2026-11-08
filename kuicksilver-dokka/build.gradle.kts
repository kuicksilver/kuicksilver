// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// A Dokka plugin for the API reference (not published): it leaves the declarations annotated with @InternalKuicksilverApi
// out of the documentation. The kmp convention plugin adds it to every module's Dokka run (dokkaPlugin).
plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jmailen.kotlinter")
}
kotlin {
    jvmToolchain(21)
    compilerOptions {
        allWarningsAsErrors.set(providers.gradleProperty("kuicksilver.warningsAsErrors").map { it.toBoolean() }.orElse(true))
    }
}
dependencies {
    compileOnly(libs.dokka.core)
    compileOnly(libs.dokka.base)
}
