// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// Ktor client engine: HttpClient(Kuicksilver) — HTTP/3 and HTTP/1.1 over TLS 1.3, Alt-Svc discovery (docs/guide/ktor.md).
plugins {
    id("kuicksilver.kmp")
    id("kuicksilver.publish")
}
kotlin {
    sourceSets {
        commonMain.dependencies {
            api(project(":kuicksilver-http3"))
            api(project(":kuicksilver-ktor-network"))
            api(libs.ktor.client.core)
            implementation(libs.ktor.http.cio)
            implementation(libs.ktor.websockets)
        }
        commonTest.dependencies {
            implementation(project(":kuicksilver-ktor-server"))   // the peer of the engine tests (test scope is outside the layer rule)
            implementation(libs.ktor.server.websockets)
            implementation(libs.ktor.server.sse)
        }
        jvmTest.dependencies {
            implementation(kotlin("test-junit5"))
        }
    }
}
tasks.named<Test>("jvmTest") { useJUnitPlatform() }
