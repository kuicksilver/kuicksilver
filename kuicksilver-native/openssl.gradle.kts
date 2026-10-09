// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Gradle wrappers over tools/openssl and tools/prefix (ADR-0007). Outputs: build/openssl/<target>, build/openssl-prefixed/<target>.
val root = rootProject.projectDir
val opensslTargets = listOf("macos-arm64", "macos-x64" /* JNI for the JVM on Intel Macs only */, "ios-arm64", "ios-sim-arm64", "android-arm64", "android-x86_64", "android-arm", "linux-x64", "linux-arm64", "mingw-x64", "linux-x64-kn", "linux-arm64-kn")
val prefixedTargets = listOf("macos-arm64", "ios-arm64", "ios-sim-arm64", "linux-x64-kn", "linux-arm64-kn", "mingw-x64")

fun String.camel() = split('-').joinToString("") { it.replaceFirstChar(Char::uppercase) }

val opensslFetch by tasks.registering(Exec::class) {
    group = "openssl"; description = "Downloads and verifies the pinned OpenSSL tarball"
    inputs.file(root.resolve("gradle/openssl.toml")); outputs.dir(root.resolve("build/openssl-work/src"))
    commandLine("bash", root.resolve("tools/openssl/fetch.sh").path)
}
opensslTargets.forEach { t ->
    tasks.register<Exec>("opensslBuild${t.camel()}") {
        group = "openssl"; description = "Builds static OpenSSL for $t"; dependsOn(opensslFetch)
        inputs.files(root.resolve("tools/openssl/build.sh"), root.resolve("tools/openssl/configure-flags.txt"), root.resolve("gradle/openssl.toml"))
        outputs.dir(root.resolve("build/openssl/$t"))
        environment("JOBS", providers.gradleProperty("kuicksilver.openssl.jobs").getOrElse("4"))
        // Linux and mingw targets need the manylinux / mingw-w64 toolchains: built inside Docker (tools/openssl/docker)
        val script = if (t == "linux-x64" || t == "linux-arm64" || t == "mingw-x64") "tools/openssl/build-docker.sh" else "tools/openssl/build.sh"
        commandLine("bash", root.resolve(script).path, t)
    }
}
prefixedTargets.forEach { t ->
    tasks.register<Exec>("opensslPrefix${t.camel()}") {
        group = "openssl"; description = "Prefixes OpenSSL symbols with ksl_ossl_ for $t"; dependsOn("opensslBuild${t.camel()}")
        inputs.dir(root.resolve("build/openssl/$t/lib")); outputs.dir(root.resolve("build/openssl-prefixed/$t"))
        commandLine("bash", root.resolve("tools/prefix/prefix.sh").path, t)
    }
}
tasks.register("opensslBuildAll") { group = "openssl"; dependsOn(opensslTargets.map { "opensslBuild${it.camel()}" }) }
tasks.register("opensslPrefixAll") { group = "openssl"; dependsOn(prefixedTargets.map { "opensslPrefix${it.camel()}" }) }
