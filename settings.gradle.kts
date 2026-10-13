// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

pluginManagement {
    includeBuild("build-logic")
    repositories { gradlePluginPortal(); google(); mavenCentral() }
}
dependencyResolutionManagement {
    repositories { google(); mavenCentral() }
}
rootProject.name = "kuicksilver"
include(":kuicksilver-native", ":kuicksilver-tls", ":kuicksilver-ktor-network", ":kuicksilver-quic", ":kuicksilver-testing", ":kuicksilver-interop", ":kuicksilver-bench")
include(":kuicksilver-http3", ":kuicksilver-ktor-server", ":kuicksilver-ktor-client", ":kuicksilver-bom")
include(":kuicksilver-soak")
