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
include(":composeApp", ":androidApp", ":server")
if (!fromMavenLocal) includeBuild("../..")
