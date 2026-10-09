// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// An external-style consumer: it depends on io.kuicksilver:* by coordinates, and the composite build below substitutes
// the modules of this repository for them. A real application drops includeBuild and takes the published artifacts.
pluginManagement {
    repositories { gradlePluginPortal(); mavenCentral(); google() }
}
// -Pkuicksilver.fromMavenLocal=true builds the sample from the artifacts in ~/.m2 instead (the consumer smoke test of a release: `tools/check/consumer-smoke.sh`).
val fromMavenLocal = providers.gradleProperty("kuicksilver.fromMavenLocal").orNull == "true"
dependencyResolutionManagement {
    repositories { if (fromMavenLocal) mavenLocal(); mavenCentral(); google() }
}
rootProject.name = "realtime-telemetry"
if (!fromMavenLocal) includeBuild("../..")
