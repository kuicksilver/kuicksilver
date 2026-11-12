// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The Compose Multiplatform demo as an outside project would build it: `composeApp` (the shared UI and screen models,
// Android and iOS), `androidApp` (the Android application around it), `server` (the JVM demo server). They depend on
// io.kuicksilver:* by coordinates; the composite build below substitutes this repository's modules for them, as in
// samples/ios. A real application drops includeBuild and takes the published artifacts. Not published.
pluginManagement {
    repositories { gradlePluginPortal(); mavenCentral(); google() }
}
val fromMavenLocal = providers.gradleProperty("kuicksilver.fromMavenLocal").orNull == "true"
dependencyResolutionManagement {
    repositories { if (fromMavenLocal) mavenLocal(); mavenCentral(); google() }
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
