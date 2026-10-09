// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Kotlin/Native: libksl.a + prefixed OpenSSL per target, consumed by the cinterop (ksl.def) through -libraryPath.
import org.gradle.process.ExecOperations
import javax.inject.Inject

val root = rootProject.projectDir
val knTargets = mapOf("MacosArm64" to "macos-arm64", "IosArm64" to "ios-arm64", "IosSimulatorArm64" to "ios-sim-arm64", "LinuxX64" to "linux-x64-kn", "LinuxArm64" to "linux-arm64-kn", "MingwX64" to "mingw-x64")
abstract class KslArchiveTask : DefaultTask() {
    @get:Inject abstract val execOps: ExecOperations
    @get:InputFile abstract val script: RegularFileProperty
    @get:InputFiles abstract val sources: ConfigurableFileCollection
    @get:Input abstract val target: Property<String>
    @get:OutputDirectory abstract val outDir: DirectoryProperty
    @TaskAction fun run() { execOps.exec { commandLine("bash", script.get().asFile.path, target.get()) } }
}
knTargets.forEach { (kt, t) ->
    tasks.register<KslArchiveTask>("buildKslA$kt") {
        group = "native"; description = "Builds libksl.a and the prefixed archives for $t"
        dependsOn("opensslPrefix" + t.split('-').joinToString("") { it.replaceFirstChar(Char::uppercase) })
        script.set(root.resolve("tools/build-ksl-a.sh")); sources.from(fileTree("src/c")); target.set(t); outDir.set(root.resolve("build/openssl-prefixed/$t"))
    }
}
