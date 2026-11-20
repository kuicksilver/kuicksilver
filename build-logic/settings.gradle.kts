// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The repositories of ../settings.gradle.kts, which says why (Central before the Plugin Portal, the mirror of Central
// last). pluginManagement's list serves this build's own plugins (kotlin-dsl and its Kotlin artifacts): without one it
// would be the Plugin Portal alone, behind its redirect to Central.
pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("androidx\\..*")
                includeGroupByRegex("com\\.android(\\..*)?")
                includeGroupByRegex("com\\.google\\..*")
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
        if (providers.gradleProperty("kuicksilver.centralMirror").orNull == "true") {
            maven("https://maven-central.storage-download.googleapis.com/maven2/") {
                name = "MavenCentralMirror"
                mavenContent { releasesOnly() }
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
        mavenCentral()
        exclusiveContent {
            forRepository { gradlePluginPortal() }
            filter {
                includeModule("org.jmailen.gradle", "kotlinter-gradle")
                includeModule("org.jetbrains.kotlinx", "kotlinx-benchmark-plugin")
                includeGroupByRegex("org\\.gradle\\.kotlin(\\..*)?")
            }
        }
        if (providers.gradleProperty("kuicksilver.centralMirror").orNull == "true") {
            maven("https://maven-central.storage-download.googleapis.com/maven2/") {
                name = "MavenCentralMirror"
                mavenContent { releasesOnly() }
            }
        }
    }
    versionCatalogs { create("libs") { from(files("../gradle/libs.versions.toml")) } }
}
rootProject.name = "build-logic"
