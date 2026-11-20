// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The repositories of ../settings.gradle.kts, which says why (Central before the Plugin Portal, the mirror of Central
// last). pluginManagement's list serves this build's own plugins (kotlin-dsl and its Kotlin artifacts): without one it
// would be the Plugin Portal alone, behind its redirect to Central.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
        maven("https://maven-central.storage-download.googleapis.com/maven2/") {
            name = "MavenCentralMirror"
            mavenContent { releasesOnly() }
        }
    }
}
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
        maven("https://maven-central.storage-download.googleapis.com/maven2/") {
            name = "MavenCentralMirror"
            mavenContent { releasesOnly() }
        }
    }
    versionCatalogs { create("libs") { from(files("../gradle/libs.versions.toml")) } }
}
rootProject.name = "build-logic"
