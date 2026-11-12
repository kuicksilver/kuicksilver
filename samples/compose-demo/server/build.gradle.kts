// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

plugins {
    kotlin("jvm")
    application
}

val kuicksilver = rootProject.extra["kuicksilver"] as String

kotlin {
    jvmToolchain(21)
    compilerOptions {
        allWarningsAsErrors.set(true)
        optIn.add("io.kuicksilver.annotations.ExperimentalKuicksilverApi")
    }
}

dependencies {
    implementation("io.kuicksilver:kuicksilver-ktor-server:$kuicksilver")
    implementation("io.ktor:ktor-server-core:3.6.1")   // as gradle/libs.versions.toml of the repository
}

// ./gradlew -p samples/compose-demo :server:run --args="--help"; :server:installDist for server/netem.sh
application {
    mainClass.set("io.kuicksilver.sample.compose.server.DemoServerKt")
}
