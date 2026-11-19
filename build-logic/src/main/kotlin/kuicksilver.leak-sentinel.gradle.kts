// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The leak sentinel (docs/process.md, "The leak sentinel"), applied through kuicksilver.kmp: every module's tests run
// under it on every platform. Its sources live once, in kuicksilver-testing/sentinel, and are copied into each module's
// test source sets (common, JVM, Kotlin/Native, Android device); tools/check/sentinel.allow becomes a generated
// LeakAllowlist object, so the same list reaches the JVM, a device and a native executable. The JVM finds the JUnit
// extension through META-INF/services (with autodetection on), a native test executable starts in leakSentinelTestMain,
// a device runs its test classes through LeakSentinelRunnerBuilder.

import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.TestExecutable

val sentinelRoot: File = rootProject.file("kuicksilver-testing/sentinel")
val allowFile: File = rootProject.file("tools/check/sentinel.allow")
val generated = layout.buildDirectory.dir("generated/leak-sentinel")

val leakSentinelSources =
    tasks.register<Sync>("leakSentinelSources") {
        description = "Copies the leak sentinel's sources and writes the allow list as Kotlin"
        from(sentinelRoot)
        into(generated)
        val allow = allowFile
        inputs.file(allow).withPathSensitivity(PathSensitivity.RELATIVE).withPropertyName("allowList")
        doLast { writeLeakAllowlist(allow, destinationDir.resolve("allow/io/kuicksilver/testing/sentinel/LeakAllowlist.kt")) }
    }

fun sentinelDir(sub: String) = files(generated.map { it.dir(sub) }).builtBy(leakSentinelSources)

extensions.configure<KotlinMultiplatformExtension> {
    // by name and lazily: the targets, and with them most of these source sets, are declared after this plugin is applied
    val dirs = mapOf("commonTest" to listOf("common", "allow"), "jvmTest" to listOf("jvm"), "nativeTest" to listOf("native"), "androidDeviceTest" to listOf("android"))
    sourceSets.matching { it.name in dirs }.configureEach { for (d in dirs.getValue(name)) kotlin.srcDir(sentinelDir(d)) }
    sourceSets.matching { it.name == "jvmTest" }.configureEach {
        resources.srcDir(sentinelDir("jvm-resources"))
        dependencies { implementation(kotlin("test-junit5")) }
    }
    targets.withType<KotlinNativeTarget>().configureEach {
        binaries.withType<TestExecutable>().configureEach {
            freeCompilerArgs += listOf("-e", "io.kuicksilver.testing.sentinel.leakSentinelTestMain")
        }
    }
}

tasks.withType<Test>().matching { it.name == "jvmTest" }.configureEach {
    useJUnitPlatform()
    systemProperty("junit.jupiter.extensions.autodetection.enabled", "true")
    // KUICKSILVER_LEAK_SITES=1 (each object keeps the stack that opened it) and KUICKSILVER_LEAK_WAIT_MS reach the test JVM
    // from the environment; they are inputs, so a run with them is not taken from a run without
    inputs.property("leakSites", providers.environmentVariable("KUICKSILVER_LEAK_SITES").orElse(""))
    inputs.property("leakWait", providers.environmentVariable("KUICKSILVER_LEAK_WAIT_MS").orElse(""))
}

// the same two variables for a Kotlin/Native test executable, which gets only what its task passes on
tasks.withType<org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeTest>().configureEach {
    for (name in listOf("KUICKSILVER_LEAK_SITES", "KUICKSILVER_LEAK_WAIT_MS")) {
        providers.environmentVariable(name).orNull?.let { environment(name, it) }
    }
}
