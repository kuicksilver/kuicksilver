// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// Throughput benchmark and the steady-state allocation gate for the QUIC core (not published; JVM, Linux x64 and, to profile
// Kotlin/Native on a Mac with `sample` or Instruments, macOS arm64).
plugins {
    id("org.jetbrains.kotlin.multiplatform")
    id("org.jetbrains.kotlin.plugin.allopen")
    id("org.jetbrains.kotlinx.benchmark")
}
kotlin {
    jvmToolchain(21)
    // the expect/actual classes are Beta (KT-61573): Kotlin's documented acknowledgement, as in the kmp convention plugin
    compilerOptions { freeCompilerArgs.add("-Xexpect-actual-classes") }
    jvm()
    // the memory benchmark (MemoryBench) as an executable: `./gradlew :kuicksilver-bench:runMemoryReleaseExecutableMacosArm64`
    val memoryArgs = providers.gradleProperty("kuicksilver.memory.args").orNull?.split(' ')?.filter { it.isNotEmpty() } ?: emptyList()
    val memory: org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget.() -> Unit = {
        binaries.executable("memory", listOf(org.jetbrains.kotlin.gradle.plugin.mpp.NativeBuildType.RELEASE)) {
            entryPoint = "io.kuicksilver.bench.memoryMain"
            // -Pkuicksilver.memory.allocator=std: the malloc-based allocator, whose heap figure is the exact size of the live
            // objects instead of the default allocator's pages (malloc then counts the Kotlin objects too)
            providers.gradleProperty("kuicksilver.memory.allocator").orNull?.let { freeCompilerArgs += "-Xallocator=$it" }
            runTaskProvider?.configure { args(memoryArgs) }
        }
    }
    linuxX64(memory)
    macosArm64 { memory(); compilations.getByName("main").cinterops.create("mallocstats") }
    sourceSets {
        all { languageSettings.optIn("io.kuicksilver.annotations.ExperimentalKuicksilverApi") }   // internal tooling: uses the library's experimental API directly
        commonMain.dependencies {
            implementation(project(":kuicksilver-quic"))
            implementation(project(":kuicksilver-testing"))   // MemoryNetwork for EndpointHandshakeBenchmark
            implementation(project(":kuicksilver-http3"))     // idle HTTP/3 connections in MemoryBench
            implementation(libs.kotlinx.benchmark.runtime)
        }
        jvmTest.dependencies { implementation(kotlin("test-junit5")) }
    }
}
allOpen { annotation("org.openjdk.jmh.annotations.State") }
benchmark {
    // the benchmark plugin refuses a native target it cannot run on this host (a Linux arm64 container running the JVM suites); the JVM gate is what matters there
    val linuxArmHost = System.getProperty("os.name").lowercase().contains("linux") && System.getProperty("os.arch").lowercase() in setOf("aarch64", "arm64")
    targets { register("jvm"); if (!linuxArmHost) register("linuxX64"); if (System.getProperty("os.name").lowercase().contains("mac")) register("macosArm64") }
    configurations {
        named("main") { warmups = 3; iterations = 5; iterationTime = 2; iterationTimeUnit = "s"; mode = "thrpt"; outputTimeUnit = "s"; advanced("jvmForks", "1") }
        // the QUIC core alone (in-memory loopback, Null and ksl crypto): `./gradlew :kuicksilver-bench:jvmCoreBenchmark` / `macosArm64CoreBenchmark`
        register("core") { include("CoreThroughputBenchmark"); warmups = 3; iterations = 5; iterationTime = 2; iterationTimeUnit = "s"; mode = "thrpt"; outputTimeUnit = "s"; advanced("jvmForks", "1") }
        // whole connections (handshake and close) through the core with ksl crypto: `./gradlew :kuicksilver-bench:jvmHandshakeBenchmark` / `macosArm64HandshakeBenchmark`
        // whole endpoints over loopback UDP, the accelerated socket and CUBIC (Null crypto): `./gradlew :kuicksilver-bench:jvmUdpBenchmark`
        register("udp") { include("UdpThroughputBenchmark"); param("io", "accelerated"); param("cc", "cubic"); warmups = 3; iterations = 5; iterationTime = 2; iterationTimeUnit = "s"; mode = "thrpt"; outputTimeUnit = "s"; advanced("jvmForks", "1") }
        register("handshake") { include("HandshakeBenchmark"); include("EndpointHandshakeBenchmark"); warmups = 3; iterations = 5; iterationTime = 2; iterationTimeUnit = "s"; mode = "thrpt"; outputTimeUnit = "s"; advanced("jvmForks", "1") }
    }
}
tasks.named<Test>("jvmTest") {
    useJUnitPlatform(); maxHeapSize = "1g"
    // IdleFootprintTest walks a connection reflectively, java.base collections included
    jvmArgs("--add-opens=java.base/java.util=ALL-UNNAMED", "--add-opens=java.base/java.util.concurrent=ALL-UNNAMED",
        "--add-opens=java.base/java.util.concurrent.atomic=ALL-UNNAMED", "--add-opens=java.base/java.lang=ALL-UNNAMED")
    // -Pkuicksilver.jfr=<file> records the allocation gate with JFR (inspect with `jfr view allocation-by-site <file>`)
    providers.gradleProperty("kuicksilver.jfr").orNull?.let { jvmArgs("-XX:StartFlightRecording=filename=$it,settings=profile") }
    // -Pkuicksilver.jfrExact=<file> records every allocation (TLABs off) so rare sites show up; pair it with allocTrace for the window bounds
    providers.gradleProperty("kuicksilver.jfrExact").orNull?.let { jvmArgs("-XX:-UseTLAB", "-XX:StartFlightRecording=filename=$it,jdk.ObjectAllocationOutsideTLAB#enabled=true,jdk.ObjectAllocationOutsideTLAB#stackTrace=true,jdk.ObjectAllocationSample#enabled=false") }
    // -Pkuicksilver.allocTrace prints every step of the gate window that allocated, with the byte count
    if (providers.gradleProperty("kuicksilver.allocTrace").isPresent) { environment("KUICKSILVER_ALLOC_TRACE", "1"); testLogging.showStandardStreams = true }
}
// the memory benchmark on the JVM (MemoryBench): `./gradlew :kuicksilver-bench:jvmMemory -Pkuicksilver.memory.args="1000 256"`
tasks.register<JavaExec>("jvmMemory") {
    group = "benchmark"; description = "Idle footprint, memory per idle connection and allocation per GB (MemoryBench), JVM"
    val jvm = kotlin.jvm().compilations.getByName("main")
    classpath(jvm.output.allOutputs, jvm.runtimeDependencyFiles)
    mainClass.set("io.kuicksilver.bench.MemoryMainKt")
    javaLauncher.set(javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) })
    // the heap as a server would size it by default, capped; RSS per connection is only indicative here (the heap grows with
    // garbage and the C heap is not visible: the Native run reports OpenSSL's share). The inventory reads java.base reflectively
    jvmArgs("-Xmx1g", "--add-opens=java.base/java.util=ALL-UNNAMED", "--add-opens=java.base/java.util.concurrent=ALL-UNNAMED",
        "--add-opens=java.base/java.util.concurrent.atomic=ALL-UNNAMED", "--add-opens=java.base/java.lang=ALL-UNNAMED")
    // extra JVM flags, e.g. a JFR recording: -Pkuicksilver.memory.jvmArgs="-XX:StartFlightRecording=filename=/tmp/m.jfr,settings=profile"
    providers.gradleProperty("kuicksilver.memory.jvmArgs").orNull?.split(' ')?.filter { it.isNotEmpty() }?.let { jvmArgs(it) }
    args(providers.gradleProperty("kuicksilver.memory.args").orNull?.split(' ')?.filter { it.isNotEmpty() } ?: emptyList<String>())
    providers.gradleProperty("kuicksilver.native.path").orNull?.let { systemProperty("kuicksilver.native.path", it) }
}
tasks.withType<Test>().configureEach { providers.gradleProperty("kuicksilver.native.path").orNull?.let { systemProperty("kuicksilver.native.path", it) } }
