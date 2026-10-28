// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
import org.gradle.process.ExecOperations
import javax.inject.Inject
// JVM native library: built by tools/build-jni.sh for the host classifier, packaged as META-INF/native/<lib> + manifest.sha256.
val root = rootProject.projectDir
val hostClassifier = run {
    val os = System.getProperty("os.name").lowercase(); val arch = System.getProperty("os.arch").lowercase()
    val o = if (os.contains("mac")) "osx" else if (os.contains("win")) "windows" else "linux"
    val a = if (arch == "aarch64" || arch == "arm64") "aarch_64" else "x86_64"
    "$o-$a"
}
val jniOut = layout.buildDirectory.dir("jni")
val buildJniHost = tasks.register<Exec>("buildJniHost") {
    group = "native"; description = "Builds libksl for the host JVM classifier ($hostClassifier)"
    dependsOn("opensslBuild" + (if (hostClassifier == "osx-aarch_64") "MacosArm64" else if (hostClassifier == "osx-x86_64") "MacosX64" else if (hostClassifier == "linux-aarch_64") "LinuxArm64" else if (hostClassifier == "linux-x86_64") "LinuxX64" else "MingwX64"))
    inputs.files(fileTree("src/c"), fileTree("src/jni"), root.resolve("tools/build-jni.sh"))
    outputs.dir(jniOut.map { it.dir("resources") })
    commandLine("bash", root.resolve("tools/build-jni.sh").path, hostClassifier, jniOut.get().asFile.path)
}

// Android: prebuilt libksl.so per ABI into src/androidMain/jniLibs (generated, git-ignored); the AGP KMP library packs jniLibs.
// armeabi-v7a ships by default (0.1.0); -Pkuicksilver.android.armv7=false leaves it out for a faster local build.
val androidArmv7 = providers.gradleProperty("kuicksilver.android.armv7").map { it.toBoolean() }.getOrElse(true)
val androidAbis = listOf("arm64-v8a", "x86_64") + (if (androidArmv7) listOf("armeabi-v7a") else emptyList())
abstract class AndroidJniTask : DefaultTask() {
    @get:Inject abstract val execOps: ExecOperations
    @get:InputFile abstract val script: RegularFileProperty
    @get:InputFiles abstract val sources: ConfigurableFileCollection
    @get:Input abstract val abis: ListProperty<String>
    @get:OutputDirectory abstract val outDir: DirectoryProperty
    @TaskAction fun run() {
        // An ABI left out (-Pkuicksilver.android.armv7=false) must not stay packed from an earlier build.
        outDir.get().asFile.listFiles()?.filter { it.isDirectory && it.name !in abis.get() }?.forEach { it.deleteRecursively() }
        abis.get().forEach { abi -> execOps.exec { commandLine("bash", script.get().asFile.path, abi, outDir.get().asFile.path) } }
    }
}
val buildAndroidJni = tasks.register<AndroidJniTask>("buildAndroidJni") {
    group = "native"; description = "Builds libksl.so for ${androidAbis.joinToString()}"
    dependsOn(listOf("opensslBuildAndroidArm64", "opensslBuildAndroidX86_64") + (if (androidArmv7) listOf("opensslBuildAndroidArm") else emptyList()))
    script.set(root.resolve("tools/build-android-so.sh")); sources.from(fileTree("src/c"), fileTree("src/jni")); abis.set(androidAbis); outDir.set(file("src/androidMain/jniLibs"))
}
tasks.matching { it.name.startsWith("compileAndroid") || it.name.contains("mergeAndroid") || it.name.contains("JniLib") }.configureEach { dependsOn(buildAndroidJni) }

// The Kotlin tests' native hooks (src/testhooks, tools/build-test-hooks.sh): a library of their own, never packaged or published.
// kuicksilver-tls loads the JNI one in jvmTest and links the static one into its macosArm64 tests.
val hostOpenSsl = "opensslBuild" + (if (hostClassifier == "osx-aarch_64") "MacosArm64" else if (hostClassifier == "osx-x86_64") "MacosX64" else if (hostClassifier == "linux-aarch_64") "LinuxArm64" else if (hostClassifier == "linux-x86_64") "LinuxX64" else "MingwX64")
tasks.register<Exec>("buildTestHooksJni") {
    group = "native"; description = "Builds the JVM tests' native hooks for the host"
    onlyIf { !hostClassifier.startsWith("windows") }
    dependsOn(hostOpenSsl)
    inputs.files(fileTree("src/c"), fileTree("src/testhooks"), root.resolve("tools/build-test-hooks.sh"))
    outputs.dir(layout.buildDirectory.dir("test-hooks/jni"))
    commandLine("bash", root.resolve("tools/build-test-hooks.sh").path, "jni", layout.buildDirectory.dir("test-hooks/jni").get().asFile.path)
}
tasks.register<Exec>("buildTestHooksMacosArm64") {
    group = "native"; description = "Builds the macosArm64 tests' native hooks"
    onlyIf { System.getProperty("os.name").lowercase().contains("mac") }
    dependsOn("opensslBuildMacosArm64")
    inputs.files(fileTree("src/c"), fileTree("src/testhooks"), root.resolve("tools/build-test-hooks.sh"))
    outputs.dir(layout.buildDirectory.dir("test-hooks/macos-arm64"))
    commandLine("bash", root.resolve("tools/build-test-hooks.sh").path, "macos-arm64", layout.buildDirectory.dir("test-hooks/macos-arm64").get().asFile.path)
}
