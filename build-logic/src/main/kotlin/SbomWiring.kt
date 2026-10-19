// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import org.gradle.api.Project
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.tasks.TaskProvider
import org.gradle.kotlin.dsl.newInstance
import org.gradle.kotlin.dsl.register
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.KotlinPlatformType

/**
 * Registers `cyclonedxSbom`, which writes `build/sbom/<artifactId>-<version>.cdx.json` for every publication of this module
 * (CyclonedxSbomTask). For a Kotlin Multiplatform module: one per target, from the configuration its consumers resolve
 * (`jvmRuntimeClasspath`, `androidRuntimeClasspath`, `<target>CompileKlibraries`), and one for the root publication that
 * aggregates them. [platformConstraints]: the modules a BOM constrains, for a java-platform module.
 */
fun Project.registerCyclonedxSbom(description: String, platformConstraints: List<String>? = null): TaskProvider<CyclonedxSbomTask> {
    val root = rootProject.layout.projectDirectory
    val toml = providers.fileContents(root.file("gradle/openssl.toml")).asText
    fun tomlValue(key: String) = toml.map { t -> Regex("^$key = \"(.*)\"", RegexOption.MULTILINE).find(t)?.groupValues?.get(1) ?: error("$key missing in gradle/openssl.toml") }
    // `git` runs on the release Mac; elsewhere (CI containers without git) the SBOM says "unknown"
    val git = providers.exec { commandLine("git", "log", "-1", "--format=%H %cI"); isIgnoreExitValue = true; workingDir(root.asFile) }
        .standardOutput.asText.map { it.trim() }
    return tasks.register<CyclonedxSbomTask>("cyclonedxSbom") {
        group = "publishing"
        this.description = "Writes the CycloneDX SBOM of every publication of this module into build/sbom"
        mavenGroup.set("io.kuicksilver")
        moduleName.set(project.name)
        version.set(project.version.toString())
        pomDescription.set(description)
        gitCommit.set(git.map { it.substringBefore(' ').ifBlank { "unknown" } })
        gitCommitDate.set(git.map { it.substringAfter(' ', "").ifBlank { "1970-01-01T00:00:00Z" } })
        opensslVersion.set(tomlValue("version"))
        opensslSha256.set(tomlValue("sha256"))
        opensslConfigureFlags.set(providers.fileContents(root.file("tools/openssl/configure-flags.txt")).asText.map { t ->
            t.lines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
        })
        kslAbi.set(providers.fileContents(rootProject.project(":kuicksilver-native").layout.projectDirectory.file("src/c/ksl.h")).asText.map {
            Regex("#define KSL_ABI_VERSION (\\d+)u").find(it)?.groupValues?.get(1) ?: error("KSL_ABI_VERSION missing in ksl.h")
        })
        platformConstraints?.let { this.platformConstraints.set(it) }
        outputDirectory.set(layout.buildDirectory.dir("sbom"))
        val kotlin = project.extensions.findByType(KotlinMultiplatformExtension::class.java)
        kotlin?.targets?.matching { it.platformType != KotlinPlatformType.common }?.forEach { t ->
            val (config, packaging) = when (t.platformType) {
                KotlinPlatformType.jvm -> "${t.name}RuntimeClasspath" to "jar"
                KotlinPlatformType.androidJvm -> "${t.name}RuntimeClasspath" to "aar"
                KotlinPlatformType.native -> "${t.name}CompileKlibraries" to "klib"
                else -> error("no SBOM mapping for the ${t.platformType} target ${t.name}")
            }
            val c = project.configurations.getByName(config)
            val external = c.incoming.artifactView {
                componentFilter { it is ModuleComponentIdentifier }
                lenient(false)
            }.artifacts
            publications.add(project.objects.newInstance<SbomPublication>().apply {
                artifactId.set("${project.name}-${t.name.lowercase()}")
                siblingSuffix.set(t.name.lowercase())
                this.packaging.set(packaging)
                graph.set(c.incoming.resolutionResult.rootComponent)
                externalArtifacts.set(external.resolvedArtifacts)
                externalFiles.from(external.artifactFiles)
            })
        }
    }
}
