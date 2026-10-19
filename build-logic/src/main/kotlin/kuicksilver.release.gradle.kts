// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// Release files beside the Maven publication (docs/release.md, "Supply chain"), for the GitHub release and not for Central:
//   validateSbom      every published module's CycloneDX documents against the CycloneDX 1.6 schema (cyclonedx-core-java)
//   sbomZip           build/release/kuicksilver-<version>-sbom.zip: all of them, validated, reproducible
//   signReleaseFiles  -Pkuicksilver.release.sign=<file>[,<file>...]: a detached armored <file>.asc for each, with the key that
//                     signs the Maven artifacts (the same Gradle properties: signingInMemoryKey* or signing.keyId/password/
//                     secretKeyRingFile), so the provenance and the SBOM archive are signed exactly as the artifacts are
plugins { signing }

private val publishedModules = listOf("native", "tls", "ktor-network", "quic", "http3", "ktor-client", "ktor-server", "bom").map { "kuicksilver-$it" }
private val releaseVersion = providers.gradleProperty("kuicksilver.version").getOrElse("0.2.0-SNAPSHOT")

val cyclonedxValidator: Configuration by configurations.creating {
    isCanBeConsumed = false
    description = "cyclonedx-core-java for validateSbom (an isolated class loader, not the build-logic class path)"
}
dependencies { cyclonedxValidator(catalog.findLibrary("cyclonedx-core-java").get()) }

private val sbomDirs = publishedModules.map { project(":$it").layout.buildDirectory.dir("sbom") }

val validateSbom = tasks.register<ValidateCyclonedxTask>("validateSbom") {
    group = "verification"
    description = "Validates the CycloneDX SBOM of every published module and publication against the CycloneDX 1.6 schema"
    dependsOn(publishedModules.map { ":$it:cyclonedxSbom" })
    documents.from(sbomDirs.map { d -> d.map { it.asFileTree.matching { include("*-$releaseVersion.cdx.json") } } })
    validatorClasspath.from(cyclonedxValidator)
    report.set(layout.buildDirectory.file("sbom/validation.txt"))
}

tasks.register<Zip>("sbomZip") {
    group = "publishing"
    description = "Archives the validated CycloneDX SBOMs of every publication for the GitHub release"
    dependsOn(validateSbom)
    from(sbomDirs) { include("*-$releaseVersion.cdx.json") }
    archiveFileName.set("kuicksilver-$releaseVersion-sbom.zip")
    destinationDirectory.set(layout.buildDirectory.dir("release"))
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

// the signatory the vanniktech plugin configures for the publications: the in-memory key when given, else signing.keyId & co.
if (providers.gradleProperty("signingInMemoryKey").isPresent) {
    signing.useInMemoryPgpKeys(
        providers.gradleProperty("signingInMemoryKeyId").orNull,
        providers.gradleProperty("signingInMemoryKey").get(),
        providers.gradleProperty("signingInMemoryKeyPassword").orNull,
    )
}
tasks.register("signReleaseFiles") {
    group = "publishing"
    description = "Signs -Pkuicksilver.release.sign=<file>[,...] with the release key: <file>.asc next to each"
    val requested = providers.gradleProperty("kuicksilver.release.sign")
    val signingExtension = signing
    val base = layout.projectDirectory
    doLast {
        val files = requested.orNull?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }?.map { base.file(it).asFile }
            ?: throw GradleException("pass -Pkuicksilver.release.sign=<file>[,<file>...]")
        files.forEach { require(it.isFile) { "$it does not exist" } }
        signingExtension.sign(*files.toTypedArray())
        files.forEach { logger.lifecycle("signed ${it.name}.asc") }
    }
}
