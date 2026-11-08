// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The aggregated API reference of the published modules (root project): `./gradlew :dokkaGenerate` writes one Dokka HTML
// site to build/dokka/html. tools/docs/site.sh puts it under /<version>/api/ of the documentation site (docs/release.md).
plugins { id("org.jetbrains.dokka") }

private val documentedModules = listOf("native", "tls", "ktor-network", "quic", "http3", "http2", "ktor-client", "ktor-server").map { "kuicksilver-$it" }

dokka {
    moduleName.set("Kuicksilver")
    // the documented modules' version (kuicksilver.kmp), so the reference never names another one
    moduleVersion.set(provider { project(":${documentedModules.first()}").version.toString() })
    dokkaPublications.html {
        outputDirectory.set(layout.buildDirectory.dir("dokka/html"))
    }
}

dependencies { documentedModules.forEach { dokka(project(":$it")) } }
