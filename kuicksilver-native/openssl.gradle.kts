// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Gradle wrappers over tools/openssl and tools/prefix (ADR-0007). Outputs: build/openssl/<target>, build/openssl-prefixed/<target>.
val root = rootProject.projectDir
val opensslTargets = listOf("macos-arm64", "macos-x64" /* JNI for the JVM on Intel Macs only */, "ios-arm64", "ios-sim-arm64", "android-arm64", "android-x86_64", "android-arm", "linux-x64", "linux-arm64", "mingw-x64", "linux-x64-kn", "linux-arm64-kn")
val prefixedTargets = listOf("macos-arm64", "ios-arm64", "ios-sim-arm64", "linux-x64-kn", "linux-arm64-kn", "mingw-x64")

val dockerTargets = setOf("linux-x64", "linux-arm64", "mingw-x64")

fun String.camel() = split('-').joinToString("") { it.replaceFirstChar(Char::uppercase) }

// -Pkuicksilver.openssl.prebuilt=true: an existing build/openssl/<target> is reused instead of running tools/openssl/*.sh when
// it is current (CI downloads it as an artifact; each worktree builds its own). Current = both archives present, the pinned
// version in include/openssl/opensslv.h, the configure-flags.txt that tools/openssl/build.sh copies next to them equal to
// tools/openssl/configure-flags.txt, its configure-target.txt equal (paths aside) to what build.sh --print-target says for
// the target (so an OPT=-O0 -fsanitize=... or another target's build is refused), and its provenance.txt naming the pinned
// tarball's SHA-256, the same target line and the SHA-256 of both archives as they are now (security review 2026-10-14,
// finding 3). A stale one fails the build rather than being overwritten; a missing one is built as usual. A release never
// reuses: tools/release/local-release.sh rebuilds all twelve from the verified tarball (KSL_OPENSSL_FRESH=1).
val prebuilt = providers.gradleProperty("kuicksilver.openssl.prebuilt").map { it.toBoolean() }.getOrElse(false)
val pinnedVersion = Regex("^version = \"(.*)\"", RegexOption.MULTILINE).find(root.resolve("gradle/openssl.toml").readText())?.groupValues?.get(1)
fun prebuiltState(t: String): String? { // null when current, else why not ("missing" when there is nothing to reuse)
    val dir = root.resolve("build/openssl/$t")
    if (!dir.resolve("lib/libcrypto.a").isFile || !dir.resolve("lib/libssl.a").isFile) return "missing"
    val header = dir.resolve("include/openssl/opensslv.h")
    val version = if (header.isFile) Regex("OPENSSL_VERSION_STR \"(.*)\"").find(header.readText())?.groupValues?.get(1) else null
    if (version != pinnedVersion) return "OpenSSL $version there, $pinnedVersion pinned in gradle/openssl.toml"
    val flags = dir.resolve("configure-flags.txt")
    if (!flags.isFile || flags.readText() != root.resolve("tools/openssl/configure-flags.txt").readText()) return "configure-flags.txt differs from tools/openssl/configure-flags.txt"
    fun portable(line: String) = line.split(Regex("\\s+")).filter { it.isNotEmpty() && '/' !in it }.joinToString(" ")
    val expected = ProcessBuilder("bash", root.resolve("tools/openssl/build.sh").path, "--print-target", t).redirectErrorStream(true).start()
        .let { p -> p.inputStream.bufferedReader().readText().trim().also { if (p.waitFor() != 0) return "build.sh --print-target $t failed: $it" } }
    val target = dir.resolve("configure-target.txt").takeIf { it.isFile }?.readText()?.let(::portable)
    if (target != expected) return "configure-target.txt says '$target', build.sh configures '$expected' for $t"
    val provenance = dir.resolve("provenance.txt").takeIf { it.isFile }?.readLines()?.associate { it.substringBefore(' ') to it.substringAfter(' ') }
        ?: return "no provenance.txt (built before it existed: rebuild with tools/openssl/build.sh $t)"
    val pinnedSha = Regex("^sha256 = \"(.*)\"", RegexOption.MULTILINE).find(root.resolve("gradle/openssl.toml").readText())?.groupValues?.get(1)
    if (provenance["tarball-sha256"] != pinnedSha) return "provenance.txt names tarball ${provenance["tarball-sha256"]}, $pinnedSha is pinned"
    if (provenance["target"] != expected) return "provenance.txt names target '${provenance["target"]}', not '$expected'"
    for (a in listOf("libcrypto.a", "libssl.a")) {
        val actual = java.security.MessageDigest.getInstance("SHA-256").digest(dir.resolve("lib/$a").readBytes()).joinToString("") { "%02x".format(it) }
        if (provenance[a] != actual) return "lib/$a changed after it was built (SHA-256 $actual, provenance.txt ${provenance[a]})"
    }
    return null
}

val opensslFetch by tasks.registering(Exec::class) {
    group = "openssl"; description = "Downloads and verifies the pinned OpenSSL tarball"
    inputs.file(root.resolve("gradle/openssl.toml")); outputs.dir(root.resolve("build/openssl-work/src"))
    commandLine("bash", root.resolve("tools/openssl/fetch.sh").path)
    // nothing to fetch when every OpenSSL build this invocation needs is reused
    val buildTasks = opensslTargets.associateBy { "${project.path}:opensslBuild${it.camel()}" }
    if (prebuilt) onlyIf("an OpenSSL build in the task graph is not prebuilt") { _ ->
        gradle.taskGraph.allTasks.any { task -> buildTasks[task.path]?.let { prebuiltState(it) != null } ?: false }
    }
}
opensslTargets.forEach { t ->
    tasks.register<Exec>("opensslBuild${t.camel()}") {
        group = "openssl"; description = "Builds static OpenSSL for $t"; dependsOn(opensslFetch)
        inputs.files(root.resolve("tools/openssl/build.sh"), root.resolve("tools/openssl/configure-flags.txt"), root.resolve("gradle/openssl.toml"))
        if (t in dockerTargets) inputs.files(root.resolve("tools/openssl/build-docker.sh"), fileTree(root.resolve("tools/openssl/docker")))   // review M11: the image is part of the toolchain
        outputs.dir(root.resolve("build/openssl/$t"))
        if (prebuilt) {
            onlyIf("kuicksilver.openssl.prebuilt: build/openssl/$t is not current") { _ -> prebuiltState(t) != null }
            doFirst { prebuiltState(t)?.takeIf { it != "missing" }?.let { throw GradleException("build/openssl/$t is stale ($it); delete it or drop -Pkuicksilver.openssl.prebuilt") } }
        }
        environment("JOBS", providers.gradleProperty("kuicksilver.openssl.jobs").getOrElse("4"))
        // Linux and mingw targets need the manylinux / mingw-w64 toolchains: built inside Docker (tools/openssl/docker)
        val script = if (t in dockerTargets) "tools/openssl/build-docker.sh" else "tools/openssl/build.sh"   // -kn targets: konan clang on the host
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
