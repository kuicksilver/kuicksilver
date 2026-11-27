// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The repositories of ../settings.gradle.kts, which says why (in CI the mirror of Central first, then Central, the Plugin
// Portal for its own plugins only). pluginManagement's list serves this build's own plugins (kotlin-dsl and its Kotlin
// artifacts): without one it would be the Plugin Portal alone, behind its redirect to Central.
pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("androidx\\..*")
                includeGroupByRegex("com\\.android(\\..*)?")
                includeGroupByRegex("com\\.google\\..*")
            }
        }
        if (providers.gradleProperty("kuicksilver.centralMirror").orNull == "true") {
            maven("https://maven-central.storage-download.googleapis.com/maven2/") {
                name = "MavenCentralMirror"
                mavenContent { releasesOnly() }
            }
        }
        mavenCentral()
        exclusiveContent {
            forRepository { gradlePluginPortal() }
            filter {
                includeModule("org.jmailen.gradle", "kotlinter-gradle")
                includeModule("org.jetbrains.kotlinx", "kotlinx-benchmark-plugin")
                includeGroupByRegex("org\\.gradle\\.kotlin(\\..*)?")
            }
        }
    }
}
dependencyResolutionManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("androidx\\..*")
                includeGroupByRegex("com\\.android(\\..*)?")
                includeGroupByRegex("com\\.google\\..*")
            }
        }
        if (providers.gradleProperty("kuicksilver.centralMirror").orNull == "true") {
            maven("https://maven-central.storage-download.googleapis.com/maven2/") {
                name = "MavenCentralMirror"
                mavenContent { releasesOnly() }
            }
        }
        mavenCentral()
        exclusiveContent {
            forRepository { gradlePluginPortal() }
            filter {
                includeModule("org.jmailen.gradle", "kotlinter-gradle")
                includeModule("org.jetbrains.kotlinx", "kotlinx-benchmark-plugin")
                includeGroupByRegex("org\\.gradle\\.kotlin(\\..*)?")
            }
        }
    }
    versionCatalogs { create("libs") { from(files("../gradle/libs.versions.toml")) } }
}
rootProject.name = "build-logic"
