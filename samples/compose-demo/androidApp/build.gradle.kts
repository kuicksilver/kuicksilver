// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The Android application around :composeApp (AGP 9 keeps the application out of the multiplatform module). Kotlin is
// AGP's built-in support; the Compose compiler is Kotlin's plugin.
plugins {
    id("com.android.application")
    kotlin("plugin.compose")
}

android {
    namespace = "io.kuicksilver.sample.compose.android"
    compileSdk = 37
    defaultConfig {
        applicationId = "io.kuicksilver.sample.compose"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    packaging { resources.excludes += setOf("META-INF/AL2.0", "META-INF/LGPL2.1", "META-INF/*.kotlin_module", "META-INF/INDEX.LIST") }
}

kotlin {
    jvmToolchain(21)
    compilerOptions {
        allWarningsAsErrors.set(true)
        optIn.add("io.kuicksilver.annotations.ExperimentalKuicksilverApi")
    }
}

dependencies {
    implementation(project(":composeApp"))
    implementation("androidx.activity:activity-compose:1.12.4")
    androidTestImplementation(kotlin("test-junit"))
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
