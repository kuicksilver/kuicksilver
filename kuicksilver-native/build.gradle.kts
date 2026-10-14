// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

plugins {
    id("kuicksilver.kmp")
    id("kuicksilver.publish")
}
apply(from = "openssl.gradle.kts")
apply(from = "jni.gradle.kts")

kotlin {
    val knTargets = mapOf("macosArm64" to "macos-arm64", "iosArm64" to "ios-arm64", "iosSimulatorArm64" to "ios-sim-arm64", "linuxX64" to "linux-x64-kn", "linuxArm64" to "linux-arm64-kn", "mingwX64" to "mingw-x64")
    targets.withType<KotlinNativeTarget>().configureEach {
        val t = knTargets.getValue(name); val lib = rootProject.projectDir.resolve("build/openssl-prefixed/$t")
        val archive = "buildKslA" + name.replaceFirstChar(Char::uppercase)
        compilations.getByName("main").cinterops.create("ksl") {
            definitionFile.set(file("src/nativeInterop/cinterop/ksl.def"))
            includeDirs(file("src/c"), lib.resolve("include"))
            extraOpts("-libraryPath", lib.resolve("lib").absolutePath)
        }
        tasks.matching { it.name == "cinteropKsl" + name.replaceFirstChar(Char::uppercase) }.configureEach { dependsOn(archive) }
    }
    sourceSets {
        jvmMain { resources.srcDir(layout.buildDirectory.dir("jni/resources")) }
    }
}
tasks.matching { it.name == "jvmProcessResources" }.configureEach { dependsOn("buildJniHost") }
// Provenance of the bundled native library: the pinned OpenSSL release and its tarball hash, the ksl ABI and the source revision.
tasks.matching { it.name == "jvmJar" }.configureEach {
    val toml = rootProject.file("gradle/openssl.toml").readText()
    val openSslVersion = Regex("^version = \"(.*)\"", RegexOption.MULTILINE).find(toml)?.groupValues?.get(1) ?: "unknown"
    val openSslSha = Regex("^sha256 = \"(.*)\"", RegexOption.MULTILINE).find(toml)?.groupValues?.get(1) ?: "unknown"
    val abi = Regex("#define KSL_ABI_VERSION (\\d+)u").find(file("src/c/ksl.h").readText())?.groupValues?.get(1) ?: "unknown"
    // the source revision without a git binary (CI containers have none): .git/HEAD, following a symbolic ref or a worktree's gitdir
    fun gitRevision(): String = runCatching {
        var dir = rootProject.file(".git"); if (dir.isFile) dir = File(dir.readText().removePrefix("gitdir:").trim()).let { if (it.isAbsolute) it else rootProject.file(it.path) }
        val head = dir.resolve("HEAD").readText().trim()
        val sha = if (head.startsWith("ref:")) { val ref = head.removePrefix("ref:").trim(); val common = dir.resolve("commondir").takeIf { it.isFile }?.let { dir.resolve(it.readText().trim()) } ?: dir
            (common.resolve(ref).takeIf { it.isFile }?.readText()?.trim() ?: common.resolve("packed-refs").takeIf { it.isFile }?.readLines()?.firstOrNull { it.endsWith(" $ref") }?.substringBefore(' ') ?: "") } else head
        sha.take(7).ifEmpty { "unknown" }
    }.getOrDefault("unknown")
    (this as Jar).manifest.attributes("OpenSSL-Version" to openSslVersion, "OpenSSL-SHA256" to openSslSha, "Ksl-ABI" to abi, "Ksl-Revision" to gitRevision())
}
tasks.withType<Test>().configureEach {
    dependsOn("buildJniHost")
    systemProperty("ksl.native.resources", layout.buildDirectory.dir("jni/resources").get().asFile.path)
}
apply(from = "native.gradle.kts")
