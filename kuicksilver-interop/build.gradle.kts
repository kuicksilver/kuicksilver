// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// QUIC Interop Runner endpoint (not published): hq-interop server and client over kuicksilver-quic, as a JVM distribution
// (tools/interop/Dockerfile) and as Linux executables (tools/interop/Dockerfile.native).
plugins {
    id("org.jetbrains.kotlin.multiplatform")
}
kotlin {
    jvmToolchain(21)
    jvm()
    linuxX64 { binaries.executable { entryPoint = "io.kuicksilver.interop.main"; baseName = "kuicksilver-interop" } }
    linuxArm64 { binaries.executable { entryPoint = "io.kuicksilver.interop.main"; baseName = "kuicksilver-interop" } }
    sourceSets {
        commonMain.dependencies { implementation(project(":kuicksilver-quic")); implementation(project(":kuicksilver-http3")) }
        commonTest.dependencies { implementation(kotlin("test")) }
    }
}
tasks.withType<Test>().configureEach { providers.gradleProperty("kuicksilver.native.path").orNull?.let { systemProperty("kuicksilver.native.path", it) } }

// The JVM distribution for the interop image: every runtime jar under build/install/kuicksilver-interop/lib, run with java -cp over that directory (see tools/interop/run_endpoint.sh).
tasks.register<Sync>("installJvmDist") {
    group = "distribution"
    from(tasks.named("jvmJar")); from(configurations["jvmRuntimeClasspath"])
    into(layout.buildDirectory.dir("install/kuicksilver-interop/lib"))
}
// The Linux executables for the native image, laid out by Docker's TARGETARCH: build/install/kuicksilver-interop-native/{amd64,arm64}/kuicksilver-interop.
tasks.register("installNativeDist") {
    group = "distribution"
    dependsOn("linkReleaseExecutableLinuxX64", "linkReleaseExecutableLinuxArm64")
    val out = layout.buildDirectory.dir("install/kuicksilver-interop-native"); val bins = layout.buildDirectory.dir("bin")
    inputs.files(bins.map { it.file("linuxX64/releaseExecutable/kuicksilver-interop.kexe") }, bins.map { it.file("linuxArm64/releaseExecutable/kuicksilver-interop.kexe") })   // without inputs Gradle would call a stale copy up to date
    outputs.dir(out)
    doLast {
        for ((arch, target) in listOf("amd64" to "linuxX64", "arm64" to "linuxArm64")) {
            val src = bins.get().file("$target/releaseExecutable/kuicksilver-interop.kexe").asFile
            val dst = out.get().file("$arch/kuicksilver-interop").asFile; dst.parentFile.mkdirs(); src.copyTo(dst, overwrite = true); dst.setExecutable(true)
        }
    }
}
