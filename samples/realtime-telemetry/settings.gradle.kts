// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// An external-style consumer: it depends on io.kuicksilver:* by coordinates, and the composite build below substitutes
// the modules of this repository for them. A real application drops includeBuild and takes the published artifacts.
// In CI only (kuicksilver.centralMirror=true, set by .github/actions/setup): Google's mirror of Maven Central first,
// Central the fallback (../../settings.gradle.kts says why); never with
// -Pkuicksilver.fromMavenCentral=true, which tests Central itself. A real application leaves the mirror out.
pluginManagement {
    repositories {
        if (providers.gradleProperty("kuicksilver.centralMirror").orNull == "true" &&
            providers.gradleProperty("kuicksilver.fromMavenCentral").orNull != "true") {
            maven("https://maven-central.storage-download.googleapis.com/maven2/") {
                name = "MavenCentralMirror"
                mavenContent { releasesOnly() }
            }
        }
        gradlePluginPortal()
        mavenCentral()
        google()
    }
}
// -Pkuicksilver.fromMavenLocal=true builds the sample from the artifacts in ~/.m2 instead, -Pkuicksilver.fromMavenCentral=true
// from Maven Central only (the consumer smoke tests of a release: `tools/check/consumer-smoke.sh [--central]`).
val fromMavenLocal = providers.gradleProperty("kuicksilver.fromMavenLocal").orNull == "true"
val fromMavenCentral = providers.gradleProperty("kuicksilver.fromMavenCentral").orNull == "true"
dependencyResolutionManagement {
    repositories {
        if (fromMavenLocal) mavenLocal()
        if (providers.gradleProperty("kuicksilver.centralMirror").orNull == "true" && !fromMavenCentral) {
            maven("https://maven-central.storage-download.googleapis.com/maven2/") {
                name = "MavenCentralMirror"
                mavenContent { releasesOnly() }
            }
        }
        mavenCentral()
        google()
    }
}
rootProject.name = "realtime-telemetry"
if (!fromMavenLocal && !fromMavenCentral) includeBuild("../..")
