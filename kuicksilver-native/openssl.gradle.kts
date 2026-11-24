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
// -Pkuicksilver.openssl.pin=gradle/openssl-next.toml: the pin profile of the CI job openssl-next (OpenSSL 4.x); tools/openssl/*.sh read it as KSL_OPENSSL_PIN
val pinFile = providers.gradleProperty("kuicksilver.openssl.pin").map { root.resolve(it) }.getOrElse(root.resolve("gradle/openssl.toml"))
val pinText = pinFile.readText()
// zlib and brotli, compiled into libcrypto.a by tools/openssl/build.sh (RFC 8879 certificate compression); provenance.txt
// names the tarball SHA-256 of each, which must be the pinned ones
val compressionPin = root.resolve("gradle/compression-libs.toml")
fun compressionSha(table: String): String? =
    Regex("(?ms)^\\[$table]\\s*\\n[^\\[]*?^sha256 = \"([0-9a-f]+)\"").find(compressionPin.readText())?.groupValues?.get(1)
val pinnedVersion = Regex("^version = \"(.*)\"", RegexOption.MULTILINE).find(pinText)?.groupValues?.get(1)
fun prebuiltState(t: String): String? { // null when current, else why not ("missing" when there is nothing to reuse)
    val dir = root.resolve("build/openssl/$t")
    if (!dir.resolve("lib/libcrypto.a").isFile || !dir.resolve("lib/libssl.a").isFile) return "missing"
    val header = dir.resolve("include/openssl/opensslv.h")
    val version = if (header.isFile) Regex("OPENSSL_VERSION_STR \"(.*)\"").find(header.readText())?.groupValues?.get(1) else null
    if (version != pinnedVersion) return "OpenSSL $version there, $pinnedVersion pinned in ${pinFile.name}"
    val flags = dir.resolve("configure-flags.txt")
    if (!flags.isFile || flags.readText() != root.resolve("tools/openssl/configure-flags.txt").readText()) return "configure-flags.txt differs from tools/openssl/configure-flags.txt"
    fun portable(line: String) = line.split(Regex("\\s+")).filter { it.isNotEmpty() && '/' !in it }.joinToString(" ")
    val expected = ProcessBuilder("bash", root.resolve("tools/openssl/build.sh").path, "--print-target", t).redirectErrorStream(true).start()
        .let { p -> p.inputStream.bufferedReader().readText().trim().also { if (p.waitFor() != 0) return "build.sh --print-target $t failed: $it" } }
    val target = dir.resolve("configure-target.txt").takeIf { it.isFile }?.readText()?.let(::portable)
    if (target != expected) return "configure-target.txt says '$target', build.sh configures '$expected' for $t"
    val provenance = dir.resolve("provenance.txt").takeIf { it.isFile }?.readLines()?.associate { it.substringBefore(' ') to it.substringAfter(' ') }
        ?: return "no provenance.txt (built before it existed: rebuild with tools/openssl/build.sh $t)"
    val pinnedSha = Regex("^sha256 = \"(.*)\"", RegexOption.MULTILINE).find(pinText)?.groupValues?.get(1)
    if (provenance["tarball-sha256"] != pinnedSha) return "provenance.txt names tarball ${provenance["tarball-sha256"]}, $pinnedSha is pinned"
    // the patches carried under ADR-0019, when the pin names them (their hashes are in the target line too)
    for ((key, label) in listOf("patch_sha256" to "patch-sha256") + (2..10).map { "patch_${it}_sha256" to "patch-$it-sha256" }) {
        val pinnedPatch = Regex("^$key = \"(.*)\"", RegexOption.MULTILINE).find(pinText)?.groupValues?.get(1)
        if (provenance[label] != pinnedPatch) return "provenance.txt names $label ${provenance[label] ?: "none"}, ${pinnedPatch ?: "none"} is pinned"
    }
    for (lib in listOf("zlib", "brotli")) {
        val pinned = compressionSha(lib)
        if (pinned == null || provenance["$lib-tarball-sha256"] != pinned) return "provenance.txt names $lib tarball ${provenance["$lib-tarball-sha256"]}, $pinned is pinned in ${compressionPin.name}"
    }
    if (provenance["target"] != expected) return "provenance.txt names target '${provenance["target"]}', not '$expected'"
    for (a in listOf("libcrypto.a", "libssl.a")) {
        val actual = java.security.MessageDigest.getInstance("SHA-256").digest(dir.resolve("lib/$a").readBytes()).joinToString("") { "%02x".format(it) }
        if (provenance[a] != actual) return "lib/$a changed after it was built (SHA-256 $actual, provenance.txt ${provenance[a]})"
    }
    return null
}

val opensslFetch = tasks.register<Exec>("opensslFetch") {
    group = "openssl"; description = "Downloads and verifies the pinned OpenSSL tarball"
    inputs.files(pinFile, compressionPin); outputs.dir(root.resolve("build/openssl-work/src"))
    environment("KSL_OPENSSL_PIN", pinFile.path)
    commandLine("bash", root.resolve("tools/openssl/fetch.sh").path)
    // nothing to fetch when every OpenSSL build this invocation needs is reused
    val buildTasks = opensslTargets.associateBy { "${project.path}:opensslBuild${it.camel()}" }
    if (prebuilt) onlyIf("an OpenSSL build in the task graph is not prebuilt") { _ ->
        gradle.taskGraph.allTasks.any { task -> buildTasks[task.path]?.let { prebuiltState(it) != null } ?: false }
    }
}
// The builder's flags, which tools/openssl/build.sh adds to its own (docs/guide/building.md): inputs, so a change reruns the build.
val builderFlags = listOf("CPPFLAGS", "CFLAGS", "LDFLAGS").associateWith { providers.environmentVariable(it).orElse("") }
opensslTargets.forEach { t ->
    tasks.register<Exec>("opensslBuild${t.camel()}") {
        group = "openssl"; description = "Builds static OpenSSL for $t"; dependsOn(opensslFetch)
        inputs.files(root.resolve("tools/openssl/build.sh"), root.resolve("tools/openssl/compression.mk"), fileTree(root.resolve("tools/openssl/brotli")), root.resolve("tools/openssl/configure-flags.txt"), pinFile, compressionPin)
        inputs.files(root.resolve("tools/openssl/apply-patch.pl"), fileTree(root.resolve("tools/openssl/patches")))   // ADR-0019
        inputs.files(root.resolve("tools/check/llvm-tool.sh"))   // finds the Apple targets' llvm-ar (tools/openssl/build.sh)
        // ... from these: another llvm-ar is another archive index, so a change reruns the build
        listOf("LLVM_AR", "ANDROID_NDK_ROOT", "ANDROID_NDK_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT").forEach { inputs.property("env.$it", providers.environmentVariable(it).orElse("")) }
        if (t in dockerTargets) inputs.files(root.resolve("tools/openssl/build-docker.sh"), fileTree(root.resolve("tools/openssl/docker")))   // review M11: the image is part of the toolchain
        builderFlags.forEach { (name, value) -> inputs.property("env.$name", value) }
        // CC: only the macOS builds use the builder's (tools/openssl/build.sh); the others drop it or set their own
        if (t.startsWith("macos-")) inputs.property("env.CC", providers.environmentVariable("CC").orElse(""))
        outputs.dir(root.resolve("build/openssl/$t"))
        if (prebuilt) {
            onlyIf("kuicksilver.openssl.prebuilt: build/openssl/$t is not current") { _ -> prebuiltState(t) != null }
            doFirst { prebuiltState(t)?.takeIf { it != "missing" }?.let { throw GradleException("build/openssl/$t is stale ($it); delete it or drop -Pkuicksilver.openssl.prebuilt") } }
        }
        environment("KSL_OPENSSL_PIN", pinFile.path)
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
