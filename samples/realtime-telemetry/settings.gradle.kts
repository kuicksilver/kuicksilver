// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// An external-style consumer: it depends on io.kuicksilver:* by coordinates, and the composite build below substitutes
// the modules of this repository for them. A real application drops includeBuild and takes the published artifacts.
pluginManagement {
    repositories { gradlePluginPortal(); mavenCentral(); google() }
}
// -Pkuicksilver.fromMavenLocal=true builds the sample from the artifacts in ~/.m2 instead, -Pkuicksilver.fromMavenCentral=true
// from Maven Central only (the consumer smoke tests of a release: `tools/check/consumer-smoke.sh [--central]`).
val fromMavenLocal = providers.gradleProperty("kuicksilver.fromMavenLocal").orNull == "true"
val fromMavenCentral = providers.gradleProperty("kuicksilver.fromMavenCentral").orNull == "true"
dependencyResolutionManagement {
    repositories {
        if (fromMavenLocal) mavenLocal()
        mavenCentral()
        google()
    }
}
rootProject.name = "realtime-telemetry"
if (!fromMavenLocal && !fromMavenCentral) includeBuild("../..")
