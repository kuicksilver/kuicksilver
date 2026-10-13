// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// Ktor client engine: HttpClient(Kuicksilver) — HTTP/3 and HTTP/1.1 over TLS 1.3, Alt-Svc discovery (docs/guide/ktor.md).
import java.util.concurrent.TimeUnit

plugins {
    id("kuicksilver.kmp")
    id("kuicksilver.publish")
}
kotlin {
    sourceSets {
        commonMain.dependencies {
            api(project(":kuicksilver-http3"))
            api(project(":kuicksilver-ktor-network"))
            api(libs.ktor.client.core)
            implementation(libs.ktor.http.cio)
            implementation(libs.ktor.websockets)
        }
        commonTest.dependencies {
            implementation(project(":kuicksilver-ktor-server"))   // the peer of the engine tests (test scope is outside the layer rule)
            implementation(libs.ktor.server.websockets)
            implementation(libs.ktor.server.sse)
        }
        jvmTest.dependencies {
            implementation(kotlin("test-junit5"))
        }
    }
}
tasks.named<Test>("jvmTest") { useJUnitPlatform() }

// ---- Simulator host-interop harness (docs/guide/quic.md, "iOS"): `iosHostInteropTest` starts a host peer (HostPeerMain, jvmTest)
// before the simulator tests and stops it after; its control port reaches the simulator process as KSL_PEER_PORT, since simctl
// hands every SIMCTL_CHILD_* variable to the app without the prefix. A plain iosSimulatorArm64Test runs HostInteropTest without
// the variable, and those tests pass without doing anything.

/** The host peer process for one build: started by the first task that needs it, destroyed when the build ends. */
abstract class HostPeer : BuildService<HostPeer.Params>, AutoCloseable {
    interface Params : BuildServiceParameters {
        val classpath: ConfigurableFileCollection
        val java: RegularFileProperty
        val workDir: DirectoryProperty
    }

    private var process: Process? = null
    private var port = 0

    /** Starts the peer once and answers its control port; fails when it does not listen within a minute. */
    @Synchronized fun start(): Int {
        if (process?.isAlive == true) return port
        val dir = parameters.workDir.get().asFile.apply { mkdirs() }
        val portFile = File(dir, "control-port").apply { delete() }
        val log = File(dir, "host-peer.log")
        val p =
            ProcessBuilder(
                parameters.java.get().asFile.path, "-cp", parameters.classpath.asPath,
                "io.kuicksilver.ktor.client.HostPeerMain", portFile.path,
            ).redirectErrorStream(true).redirectOutput(log).start()
        process = p
        val deadline = System.nanoTime() + 60_000_000_000L
        while (!portFile.exists()) {
            if (!p.isAlive) throw GradleException("the host peer exited (${p.exitValue()}); see $log")
            if (System.nanoTime() > deadline) { stop(); throw GradleException("the host peer did not listen within 60 s; see $log") }
            Thread.sleep(100)
        }
        port = portFile.readText().trim().toInt()
        return port
    }

    /** Stops the peer (its own process only, by handle) and waits for it. */
    @Synchronized fun stop() {
        process?.let { p -> p.destroy(); if (!p.waitFor(10, TimeUnit.SECONDS)) p.destroyForcibly().waitFor() }
        process = null
    }

    override fun close() = stop()
}

val hostPeer = gradle.sharedServices.registerIfAbsent("kuicksilverHostPeer", HostPeer::class) {
    val jvmTest = kotlin.jvm().compilations.getByName("test")
    parameters.classpath.from(jvmTest.output.allOutputs, jvmTest.runtimeDependencyFiles)
    parameters.java.set(javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) }.map { it.executablePath })
    parameters.workDir.set(layout.buildDirectory.dir("host-peer"))
}

kotlin.iosSimulatorArm64 {
    testRuns.create("hostInterop") { setExecutionSourceFrom(binaries.getTest("DEBUG")) }
}

val hostInteropRun = tasks.named<org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeSimulatorTest>("iosSimulatorArm64HostInteropTest") {
    group = "verification"
    description = "Runs HostInteropTest on the iOS simulator against a host peer (Ktor h3/h1 and raw QUIC on 127.0.0.1 and ::1, both directions)"
    usesService(hostPeer)
    dependsOn("jvmTestClasses")
    filter.includeTestsMatching("*HostInteropTest*")
    outputs.upToDateWhen { false } // the peer is outside Gradle's inputs: always run
    // the value is read when the simulator process starts (a value set in doFirst arrives too late): the peer starts then
    environment("SIMCTL_CHILD_KSL_PEER_PORT", object { override fun toString() = hostPeer.get().start().toString().also { logger.lifecycle("host peer listens, control port $it") } }, false)
    doLast { hostPeer.get().stop() }
}
tasks.register("iosHostInteropTest") {
    group = "verification"
    description = "The simulator host-interop tests with the host peer running (alias of iosSimulatorArm64HostInteropTest)"
    dependsOn(hostInteropRun)
}
