// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// Cross-engine interop bench (not published, JVM only, test sources only): Kuicksilver's Ktor client engine against Ktor's
// Netty and CIO servers and a plain Netty server, and Kuicksilver's Ktor server engine against OkHttp, the JDK's
// HttpClient and Ktor's CIO, OkHttp and Java client engines, in one process over loopback (docs/spec/interop.md,
// "Engine interop"). The QUIC library interop with other QUIC stacks is the QUIC Interop Runner's (tools/interop).
//   ./gradlew --max-workers=2 :kuicksilver-engine-interop:jvmTest
plugins {
    id("org.jetbrains.kotlin.multiplatform")
    id("org.jmailen.kotlinter")
}
kotlin {
    jvmToolchain(21)
    compilerOptions { allWarningsAsErrors.set(providers.gradleProperty("kuicksilver.warningsAsErrors").map { it.toBoolean() }.orElse(true)) }   // as in the kmp convention plugin (same -Pkuicksilver.warningsAsErrors switch)
    jvm()
    sourceSets {
        all { languageSettings.optIn("io.kuicksilver.annotations.ExperimentalKuicksilverApi") }   // internal tooling: uses the library's experimental API directly
        jvmTest.dependencies {
            implementation(kotlin("test-junit5"))
            implementation(project(":kuicksilver-ktor-client"))
            implementation(project(":kuicksilver-ktor-server"))
            implementation(libs.ktor.server.websockets)
            implementation(libs.ktor.server.auto.head.response)
            // the peers: Ktor's other server and client engines, OkHttp (the JDK's HttpClient needs nothing)
            implementation(libs.ktor.server.netty)
            implementation(libs.ktor.server.cio)
            implementation(libs.ktor.client.cio)
            implementation(libs.ktor.client.okhttp)
            implementation(libs.ktor.client.java)
            implementation(libs.okhttp)
        }
        // the test PKI as the C tests have it (tools/certs/gen-testcerts.sh): the same DER files, no copy in Kotlin
        jvmTest { resources.srcDir(rootProject.file("kuicksilver-native/src/c/test/testdata")) }
    }
}
// ktor-server-netty asks for Jetty's ALPN API of 2016 (Java 8's boot class path ALPN); JDK 9 and later have ALPN and Netty
// does not load it, and its parent POM's signing key is on no key server and not in Jetty's KEYS.txt, so it stays out
configurations.matching { it.name.startsWith("jvmTest") }.configureEach { exclude(group = "org.eclipse.jetty.alpn") }
tasks.named<Test>("jvmTest") {
    useJUnitPlatform()
    maxHeapSize = "1g"
    providers.gradleProperty("kuicksilver.native.path").orNull?.let { systemProperty("kuicksilver.native.path", it) }
}
