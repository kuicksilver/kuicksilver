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

// Version floors for tool libraries that the Android and Kotlin plugins resolve in configurations of their own: the
// versions they ask for have known vulnerabilities (OSV), each floor is the first fixed release. None of these
// configurations reaches a published module or a runtime class path: Android lint (androidLintTool), the device tests'
// Unified Test Platform plugins, and Swift export (unused here, resolved by ksResolveAll). A constraint only raises a
// version, and a configuration without the module ignores it. The plugin class path gets its floors in
// build-logic/build.gradle.kts.
gradle.lifecycle.beforeProject {
    val constraints = dependencies.constraints
    configurations.configureEach {
        val floors = when {
            // GHSA-7r82-7xv7-xcpj: com.android.tools:sdklib asks for httpmime 4.5.6, which asks for httpclient 4.5.6
            name == "androidLintTool" || name.startsWith("unified-test-platform-") ->
                listOf("org.apache.httpcomponents:httpclient:4.5.14")
            // GHSA-ccrj-gw8r-854m, GHSA-rcgg-9c38-7xpx: org.jetbrains.kotlin:swift-export-embeddable asks for 1.41.0
            name == "swiftExportClasspath" -> listOf("io.opentelemetry:opentelemetry-api:1.67.0")
            else -> emptyList()
        }
        for (floor in floors) {
            dependencyConstraints.add(constraints.create(floor) { because("first release without the known vulnerabilities") })
        }
    }
}

include(":kuicksilver-native", ":kuicksilver-tls", ":kuicksilver-ktor-network", ":kuicksilver-quic", ":kuicksilver-testing", ":kuicksilver-interop", ":kuicksilver-bench")
include(":kuicksilver-http3", ":kuicksilver-http2", ":kuicksilver-ktor-server", ":kuicksilver-ktor-client", ":kuicksilver-bom")
include(":kuicksilver-soak")
include(":kuicksilver-dokka")
