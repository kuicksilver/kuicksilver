// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

dependencyResolutionManagement {
    repositories { gradlePluginPortal(); google(); mavenCentral() }
    versionCatalogs { create("libs") { from(files("../gradle/libs.versions.toml")) } }
}
rootProject.name = "build-logic"
