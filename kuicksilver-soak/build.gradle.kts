// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// Soak and churn harness (not published, not part of `check`'s work): a real-UDP Ktor server (HTTP/1.1 + HTTP/3) and a raw QUIC
// server under a weighted mix of client scenarios, with resource sampling and a flatness verdict (CONTRIBUTING.md, "Soak").
//   ./gradlew --max-workers=2 :kuicksilver-soak:jvmTest -Pkuicksilver.soak.minutes=30
//   ./gradlew --max-workers=2 :kuicksilver-soak:macosArm64Test -Pkuicksilver.soak.minutes=30
// Without kuicksilver.soak.minutes the JVM tests run only the statistics unit tests and the native test binaries are not built.
import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeTest

plugins {
    id("org.jetbrains.kotlin.multiplatform")
    id("org.jmailen.kotlinter")
}
kotlin {
    jvmToolchain(21)
    jvm()
    linuxX64(); linuxArm64(); macosArm64()
    applyDefaultHierarchyTemplate()
    sourceSets {
        all { languageSettings.optIn("io.kuicksilver.annotations.InternalKuicksilverApi"); languageSettings.optIn("io.kuicksilver.annotations.ExperimentalKuicksilverApi") }
        commonMain.dependencies {
            implementation(project(":kuicksilver-ktor-client"))
            implementation(project(":kuicksilver-ktor-server"))
            implementation(libs.kotlinx.io.core)
        }
        commonTest.dependencies { implementation(kotlin("test")) }
        jvmTest.dependencies { implementation(kotlin("test-junit5")) }
    }
}
val soak = mapOf(
    "minutes" to "KSL_SOAK_MINUTES", "clients" to "KSL_SOAK_CLIENTS", "rate" to "KSL_SOAK_RATE", "sampleSeconds" to "KSL_SOAK_SAMPLE_SECONDS",
    "warmupMinutes" to "KSL_SOAK_WARMUP_MINUTES", "attribute" to "KSL_SOAK_ATTRIBUTE", "scenarios" to "KSL_SOAK_SCENARIOS", "report" to "KSL_SOAK_REPORT", "label" to "KSL_SOAK_LABEL", "qlog" to "KSL_SOAK_QLOG",
)
val soakRequested = providers.gradleProperty("kuicksilver.soak.minutes").isPresent || providers.gradleProperty("kuicksilver.soak.attribute").isPresent
tasks.named<Test>("jvmTest") {
    useJUnitPlatform(); maxHeapSize = "1g"
    if (soakRequested) { outputs.upToDateWhen { false }; testLogging.showStandardStreams = true }
}
tasks.withType<Test>().configureEach {
    soak.forEach { (k, env) -> providers.gradleProperty("kuicksilver.soak.$k").orNull?.let { environment(env, it) } }
    environment("KSL_SOAK_DEFAULT_REPORT", layout.buildDirectory.dir("soak").get().asFile.path)
}
tasks.withType<KotlinNativeTest>().configureEach {
    enabled = soakRequested
    outputs.upToDateWhen { false }
    soak.forEach { (k, env) -> providers.gradleProperty("kuicksilver.soak.$k").orNull?.let { environment(env, it) } }
    environment("KSL_SOAK_DEFAULT_REPORT", layout.buildDirectory.dir("soak").get().asFile.path)
}
// the native test executables link the whole stack: built only for a soak run (or explicitly, for a container run)
tasks.matching { it.name.startsWith("link") && it.name.contains("Test") }.configureEach { onlyIf { soakRequested || gradle.startParameter.taskNames.any { n -> n.endsWith(name) } } }
// -Pkuicksilver.soak.allocator=std links the native test binaries with the malloc-based allocator: `kn.heapAfterGcKiB` is then
// the exact size of the live objects instead of the default allocator's pages (CONTRIBUTING.md, "Soak and churn")
providers.gradleProperty("kuicksilver.soak.allocator").orNull?.let { a ->
    kotlin.targets.withType<org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget>().configureEach { binaries.all { freeCompilerArgs += "-Xallocator=$a" } }
}
