// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

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
        jvmTest.dependencies {
            implementation(kotlin("test-junit5"))
            implementation(libs.jazzer.junit)
        }
    }
}

// JUnit 5 for the Jazzer fuzz targets (src/jvmTest/.../fuzz); kotlin.test maps onto it
tasks.named<Test>("jvmTest") { useJUnitPlatform() }

// negative_keylogDisabledInRelease: the variable is set, and nothing may honour it (OpenSSL is built with no-sslkeylog)
tasks.withType<Test>().configureEach { environment("SSLKEYLOGFILE", layout.buildDirectory.file("must-not-exist-keylog.txt").get().asFile.path) }

// The native test hooks (kuicksilver-native/src/testhooks): loaded by jvmTest (RecordLimitAlertJvmTest), linked into the macosArm64
// tests (RecordLimitAlertMacosTest); never part of a published library.
val testHooks = rootProject.projectDir.resolve("kuicksilver-native/build/test-hooks")
tasks.named<Test>("jvmTest") {
    dependsOn(":kuicksilver-native:buildTestHooksJni")
    val ext = if (System.getProperty("os.name").lowercase().contains("mac")) "dylib" else "so"
    systemProperty("ksl.testhooks.lib", testHooks.resolve("jni/libksl_test_hooks.$ext").path)
}
kotlin {
    targets.withType<KotlinNativeTarget>().matching { it.name == "macosArm64" }.configureEach {
        compilations.getByName("test").cinterops.create("kslTestHooks") {
            definitionFile.set(file("src/nativeInterop/cinterop/kslTestHooks.def"))
            includeDirs(rootProject.projectDir.resolve("kuicksilver-native/src/testhooks"))
            extraOpts("-libraryPath", testHooks.resolve("macos-arm64").path)
        }
    }
}
tasks.matching { it.name == "cinteropTestKslTestHooksMacosArm64" }.configureEach { dependsOn(":kuicksilver-native:buildTestHooksMacosArm64") }
