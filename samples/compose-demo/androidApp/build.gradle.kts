// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import java.util.Properties
import java.util.concurrent.TimeUnit

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

// ---- The release gate's emulator check (README, "Tests"): `migrationDemoDeviceTest` starts the demo server on the host's
// 127.0.0.1 (ports chosen by the system), installs the app and its tests, and runs MigrationDemoAndroidTest with the HTTPS
// port, so the downloads cross the emulator's own network to 10.0.2.2, as :kuicksilver-ktor-client:androidMigrationDeviceTest
// does. Set ANDROID_SERIAL to pick the emulator; the test switches its default network off and on again.

/** The demo server for one build: started by the first task that needs it, stopped when the build ends. */
abstract class DemoServerService : BuildService<DemoServerService.Params>, AutoCloseable {
    interface Params : BuildServiceParameters {
        /** The server's installDist lib directory. */
        val libDir: DirectoryProperty
        val java: RegularFileProperty
        val workDir: DirectoryProperty
    }

    private var process: Process? = null
    private var port = 0

    /** Starts the server once and answers its HTTPS port; fails when it does not listen within a minute. */
    @Synchronized fun start(): Int {
        if (process?.isAlive == true) return port
        val dir = parameters.workDir.get().asFile.apply { mkdirs() }
        val portFile = File(dir, "https-port").apply { delete() }
        val log = File(dir, "server.log")
        val p =
            ProcessBuilder(
                parameters.java.get().asFile.path, "-cp", File(parameters.libDir.get().asFile, "*").path,
                "io.kuicksilver.sample.compose.server.DemoServerKt",
                "--host", "127.0.0.1", "--https-port", "0", "--http-port", "0", "--port-file", portFile.path,
            ).redirectErrorStream(true).redirectOutput(log).start()
        process = p
        val deadline = System.nanoTime() + 60_000_000_000L
        while (!portFile.exists()) {
            if (!p.isAlive) throw GradleException("the demo server exited (${p.exitValue()}); see $log")
            if (System.nanoTime() > deadline) { stop(); throw GradleException("the demo server did not listen within 60 s; see $log") }
            Thread.sleep(100)
        }
        port = portFile.readText().trim().toInt()
        return port
    }

    /** Stops the server (its own process only, by handle) and waits for it. */
    @Synchronized fun stop() {
        process?.let { p -> p.destroy(); if (!p.waitFor(10, TimeUnit.SECONDS)) p.destroyForcibly().waitFor() }
        process = null
    }

    override fun close() = stop()
}

val demoServer = gradle.sharedServices.registerIfAbsent("kuicksilverComposeDemoServer", DemoServerService::class) {
    parameters.libDir.set(project(":server").layout.buildDirectory.dir("install/server/lib"))
    parameters.java.set(javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) }.map { it.executablePath })
    parameters.workDir.set(layout.buildDirectory.dir("demo-server"))
}

val androidSdkDir: String? =
    rootProject.file("local.properties").takeIf { it.isFile }
        ?.let { f -> Properties().apply { f.inputStream().use { load(it) } }.getProperty("sdk.dir") }
        ?: System.getenv("ANDROID_HOME")

tasks.register("migrationDemoDeviceTest") {
    group = "verification"
    description = "Runs MigrationDemoAndroidTest on a connected emulator (ANDROID_SERIAL) against the demo server on the host (10.0.2.2)"
    usesService(demoServer)
    dependsOn(":server:installDist", "installDebug", "installDebugAndroidTest")
    outputs.upToDateWhen { false } // the server and the device are outside Gradle's inputs: always run
    val adb = androidSdkDir?.let { "$it/platform-tools/adb" } ?: "adb"
    val log = layout.buildDirectory.file("demo-server/instrument.log")
    doLast {
        val port = demoServer.get().start()
        try {
            val p =
                ProcessBuilder(
                    adb, "shell", "am", "instrument", "-w", "-r",
                    "-e", "class", "io.kuicksilver.sample.compose.android.MigrationDemoAndroidTest",
                    "-e", "demoServerPort", port.toString(),
                    "io.kuicksilver.sample.compose.test/androidx.test.runner.AndroidJUnitRunner",
                ).redirectErrorStream(true).redirectOutput(log.get().asFile).start()
            // bounded: a device that hangs (an instrumentation that never reports) must not hold the gate
            if (!p.waitFor(10, TimeUnit.MINUTES)) {
                p.destroyForcibly().waitFor()
                throw GradleException("MigrationDemoAndroidTest did not finish within 10 minutes; see ${log.get().asFile}")
            }
            val out = log.get().asFile.readText()
            logger.lifecycle(out)
            // -r reports each test's status: -3 is ignored, -4 an assumption failure (a skip); the gate wants the one test run
            if (Regex("""INSTRUMENTATION_STATUS_CODE: -[34]\b""").containsMatchIn(out)) {
                throw GradleException("MigrationDemoAndroidTest was skipped on the device; see ${log.get().asFile}")
            }
            // a run with failures prints "FAILURES!!!"; one that crashed prints neither line
            if (!out.contains("OK (1 test)")) {
                throw GradleException("MigrationDemoAndroidTest failed on the device; see ${log.get().asFile}")
            }
        } finally {
            demoServer.get().stop()
        }
    }
}
