// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// Ktor server engine: embeddedServer(Kuicksilver) — HTTP/1.1 over TLS on TCP and HTTP/3 on UDP, on one port (docs/guide/ktor.md).
plugins {
    id("kuicksilver.kmp")
    id("kuicksilver.publish")
}
kotlin {
    sourceSets {
        commonMain.dependencies {
            api(project(":kuicksilver-http3"))
            api(project(":kuicksilver-ktor-network"))
            api(libs.ktor.server.core)
            implementation(libs.ktor.http.cio) // the HTTP/1.1 request parser (the connection pipeline is vendored, h1/ServerPipeline.kt)
        }
        commonTest.dependencies {
            implementation(libs.ktor.server.websockets)
            implementation(libs.ktor.websockets)
            // the vendored Ktor 3.6.0 engine contract suites: our client engine as the test client, and the plugins they install
            implementation(project(":kuicksilver-ktor-client"))
            implementation(libs.ktor.server.sse)
            implementation(libs.ktor.server.status.pages)
            implementation(libs.ktor.server.partial.content)
            implementation(libs.ktor.server.hsts)
            implementation(libs.ktor.server.forwarded.header)
            implementation(libs.ktor.server.auto.head.response)
        }
        jvmTest.dependencies {
            implementation(kotlin("test-junit5"))
        }
    }
}
tasks.named<Test>("jvmTest") { useJUnitPlatform() }
