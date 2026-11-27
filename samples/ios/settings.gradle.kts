// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The iOS sample as an outside project would build it: `shared` (the KMP code the SwiftUI app calls, one static
// framework) and `kuicksilver-swift` (the umbrella that produces Kuicksilver.xcframework for Swift-only apps). Both depend
// on io.kuicksilver:* by coordinates; the composite build below substitutes this repository's modules for them, so they
// resolve to project dependencies. A real application drops includeBuild and takes the published artifacts.
// In CI only (kuicksilver.centralMirror=true, set by .github/actions/setup): Google's mirror of Maven Central first,
// Central the fallback (../../settings.gradle.kts says why). A real application leaves the mirror out.
pluginManagement {
    repositories {
        if (providers.gradleProperty("kuicksilver.centralMirror").orNull == "true") {
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
val fromMavenLocal = providers.gradleProperty("kuicksilver.fromMavenLocal").orNull == "true"
dependencyResolutionManagement {
    repositories {
        if (fromMavenLocal) mavenLocal()
        if (providers.gradleProperty("kuicksilver.centralMirror").orNull == "true") {
            maven("https://maven-central.storage-download.googleapis.com/maven2/") {
                name = "MavenCentralMirror"
                mavenContent { releasesOnly() }
            }
        }
        mavenCentral()
        google()
    }
}
rootProject.name = "kuicksilver-ios-sample"
include(":shared", ":kuicksilver-swift")
if (!fromMavenLocal) includeBuild("../..")
