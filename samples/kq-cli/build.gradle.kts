// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

plugins {
    kotlin("multiplatform") version "2.4.20"
}

val kuicksilver = providers.gradleProperty("kuicksilver.version").getOrElse("0.3.0-SNAPSHOT")   // the version under test; the composite build substitutes it unless -Pkuicksilver.fromMavenLocal=true

kotlin {
    jvmToolchain(21)
    // the JVM target runs the tests on every host and `jvmRun` is the same command line on the JVM; the native targets
    // build the `kq` executable (build/bin/<target>/releaseExecutable/kq.kexe, kq.exe on Windows)
    jvm {
        mainRun { mainClass.set("io.kuicksilver.sample.kq.MainKt") }
    }
    val natives: List<KotlinNativeTarget> = listOf(macosArm64(), linuxX64(), linuxArm64(), mingwX64())
    natives.forEach { target ->
        target.binaries.executable {
            baseName = "kq"
            entryPoint = "io.kuicksilver.sample.kq.main"
        }
    }

    sourceSets {
        all { languageSettings.optIn("io.kuicksilver.annotations.ExperimentalKuicksilverApi") }
        commonMain.dependencies {
            implementation("io.kuicksilver:kuicksilver-ktor-client:$kuicksilver")
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation("io.kuicksilver:kuicksilver-ktor-server:$kuicksilver")   // the in-process server the tests talk to
        }
    }
}

// Swift export, which this sample does not use, asks for opentelemetry-api 1.41.0 (GHSA-ccrj-gw8r-854m,
// GHSA-rcgg-9c38-7xpx). The repository's dependency verification covers this build, so it takes the first fixed release.
// The Kotlin plugin creates the configuration late, hence matching().
configurations.matching { it.name == "swiftExportClasspath" }.configureEach {
    dependencyConstraints.add(project.dependencies.constraints.create("io.opentelemetry:opentelemetry-api:1.67.0"))
}

// A test JVM out of heap exits at once and leaves a heap dump in build/test-heap-dumps, as the repository's modules do (the
// kuicksilver.test-jvm plugin of its build-logic, which this build of its own cannot apply): never a JVM that hangs a CI job.
tasks.withType<Test>().configureEach {
    val dumps = layout.buildDirectory.dir("test-heap-dumps").get().asFile
    val dumpPath = workingDir.toPath().relativize(dumps.toPath()).toString().replace(File.separatorChar, '/')
    jvmArgs("-XX:+ExitOnOutOfMemoryError", "-XX:+HeapDumpOnOutOfMemoryError", "-XX:HeapDumpPath=$dumpPath")
    doFirst { dumps.mkdirs() }
}

// A local server to point kq at by hand: HTTP/1.1, HTTP/2 and HTTP/3 on one port with the test certificates of
// src/commonTest (DevServer.kt, a test-only class: the certificates never reach the kq executable). It writes the CA to
// build/dev-ca.pem for `kq --cacert`. `./gradlew -p samples/kq-cli devServer --args=4433`
tasks.register<JavaExec>("devServer") {
    group = "application"
    description = "Runs a local Kuicksilver server for kq (port in --args, default 4433)."
    val test = kotlin.jvm().compilations.getByName("test")
    classpath = files(test.output.allOutputs, test.runtimeDependencyFiles)
    mainClass.set("io.kuicksilver.sample.kq.DevServerKt")
    workingDir = layout.buildDirectory.get().asFile
    doFirst { workingDir.mkdirs() }
}
