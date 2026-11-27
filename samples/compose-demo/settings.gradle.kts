// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The Compose Multiplatform demo as an outside project would build it: `composeApp` (the shared UI and screen models,
// Android and iOS), `androidApp` (the Android application around it), `server` (the JVM demo server). They depend on
// io.kuicksilver:* by coordinates; the composite build below substitutes this repository's modules for them, as in
// samples/ios. A real application drops includeBuild and takes the published artifacts. Not published.
// In CI only (kuicksilver.centralMirror=true, set by .github/actions/setup): Google's mirror of Maven Central first,
// Central the fallback (../../settings.gradle.kts says why). A real application leaves the mirror out.
pluginManagement {
    repositories {
        if (providers.gradleProperty("kuicksilver.centralMirror").orNull == "true") {
            maven("https://maven-central.storage-download.googleapis.com/maven2/") {
                name = "MavenCentralMirror"
                // never a plugin marker (Central has some, the Plugin Portal all), the Plugin Portal's own
                // plugins or Google's own groups: Gradle asks the next repository only after a 404, so a 403,
                // 429 or 5xx the mirror answered for a module it does not have would fail the resolution
                mavenContent {
                    releasesOnly()
                    excludeModuleByRegex(".*", ".*\\.gradle\\.plugin")
                    excludeModule("org.jmailen.gradle", "kotlinter-gradle")
                    excludeModule("org.jetbrains.kotlinx", "kotlinx-benchmark-plugin")
                    excludeGroupByRegex("org\\.gradle\\.kotlin(\\..*)?")
                    excludeGroupByRegex("androidx\\..*")
                    excludeGroupByRegex("com\\.android(\\..*)?")
                    excludeGroupByRegex("com\\.google\\.android(\\..*)?")
                    excludeGroupByRegex("com\\.google\\.testing\\.platform(\\..*)?")
                }
            }
        }
        gradlePluginPortal()
        mavenCentral()
        google()
    }
}
val fromMavenLocal = providers.gradleProperty("kuicksilver.fromMavenLocal").orNull == "true"
dependencyResolutionManagement {
    repositories {
        if (fromMavenLocal) mavenLocal()
        if (providers.gradleProperty("kuicksilver.centralMirror").orNull == "true") {
            maven("https://maven-central.storage-download.googleapis.com/maven2/") {
                name = "MavenCentralMirror"
                // never a plugin marker (Central has some, the Plugin Portal all), the Plugin Portal's own
                // plugins or Google's own groups: Gradle asks the next repository only after a 404, so a 403,
                // 429 or 5xx the mirror answered for a module it does not have would fail the resolution
                mavenContent {
                    releasesOnly()
                    excludeModuleByRegex(".*", ".*\\.gradle\\.plugin")
                    excludeModule("org.jmailen.gradle", "kotlinter-gradle")
                    excludeModule("org.jetbrains.kotlinx", "kotlinx-benchmark-plugin")
                    excludeGroupByRegex("org\\.gradle\\.kotlin(\\..*)?")
                    excludeGroupByRegex("androidx\\..*")
                    excludeGroupByRegex("com\\.android(\\..*)?")
                    excludeGroupByRegex("com\\.google\\.android(\\..*)?")
                    excludeGroupByRegex("com\\.google\\.testing\\.platform(\\..*)?")
                }
            }
        }
        mavenCentral()
        google()
    }
}
rootProject.name = "kuicksilver-compose-demo"

// The version floors of ../../settings.gradle.kts, for this build's own tool configurations (the composite build does not
// carry them over): the Android and Kotlin plugins ask for releases with known vulnerabilities (OSV), each floor is the
// first fixed release. None of these configurations reaches the app.
gradle.lifecycle.beforeProject {
    val constraints = dependencies.constraints
    configurations.configureEach {
        val floors = when {
            // GHSA-7r82-7xv7-xcpj: com.android.tools:sdklib asks for httpmime 4.5.6, which asks for httpclient 4.5.6
            name == "androidLintTool" || name.startsWith("unified-test-platform-") ->
                listOf("org.apache.httpcomponents:httpclient:4.5.14")
            // GHSA-ccrj-gw8r-854m, GHSA-rcgg-9c38-7xpx: org.jetbrains.kotlin:swift-export-embeddable asks for 1.41.0
            name == "swiftExportClasspath" -> listOf("io.opentelemetry:opentelemetry-api:1.67.0")
            else -> emptyList()
        }
        for (floor in floors) {
            dependencyConstraints.add(constraints.create(floor) { because("first release without the known vulnerabilities") })
        }
    }
}
include(":composeApp", ":androidApp", ":server")
if (!fromMavenLocal) includeBuild("../..")
