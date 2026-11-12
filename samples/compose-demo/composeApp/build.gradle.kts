// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

plugins {
    kotlin("multiplatform")
    kotlin("plugin.compose")
    id("org.jetbrains.compose")
    id("com.android.kotlin.multiplatform.library")
}

val kuicksilver = rootProject.extra["kuicksilver"] as String
val ktorVersion = "3.6.1"   // as gradle/libs.versions.toml of the repository
val composeVersion = "1.12.2"     // Compose Multiplatform (root build.gradle.kts)
val material3Version = "1.9.0"    // what Compose Multiplatform 1.12.2 pairs with (its ComposeBuildConfig)

kotlin {
    jvmToolchain(21)
    compilerOptions {
        allWarningsAsErrors.set(true)
        optIn.add("io.kuicksilver.annotations.ExperimentalKuicksilverApi")
    }

    // AGP 9: the Android side of a multiplatform module is a library; the application is :androidApp
    android {
        namespace = "io.kuicksilver.sample.compose.shared"
        compileSdk = 37
        minSdk = 24
        withHostTestBuilder {}
    }

    // one static framework for the iOS app (see docs/guide/ios.md: never two Kotlin/Native frameworks in one app)
    listOf(iosArm64(), iosSimulatorArm64()).forEach { target ->
        target.binaries.framework {
            baseName = "ComposeApp"
            isStatic = true
        }
    }

    sourceSets {
        commonMain.dependencies {
            api("io.kuicksilver:kuicksilver-ktor-client:$kuicksilver")   // in the API: Lane, kuicksilverClient
            api("io.ktor:ktor-client-core:$ktorVersion")
            implementation("org.jetbrains.compose.runtime:runtime:$composeVersion")
            implementation("org.jetbrains.compose.foundation:foundation:$composeVersion")
            implementation("org.jetbrains.compose.ui:ui:$composeVersion")
            implementation("org.jetbrains.compose.material3:material3:$material3Version")
        }
        androidMain.dependencies {
            // the TCP reference engine on Android
            implementation("io.ktor:ktor-client-okhttp:$ktorVersion")
        }
        iosMain.dependencies {
            // the TCP reference engines on iOS: CIO (Ktor's own HTTP/1.1, plain HTTP only on Kotlin/Native) and Darwin (URLSession)
            implementation("io.ktor:ktor-client-cio:$ktorVersion")
            implementation("io.ktor:ktor-client-darwin:$ktorVersion")
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation("io.ktor:ktor-client-mock:$ktorVersion")
            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
        }
    }
}
