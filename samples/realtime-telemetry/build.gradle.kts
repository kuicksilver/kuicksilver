// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

plugins {
    kotlin("multiplatform") version "2.4.20"
}

val kuicksilver = providers.gradleProperty("kuicksilver.version").getOrElse("0.3.0-SNAPSHOT")   // the version under test; the composite build substitutes it unless -Pkuicksilver.fromMavenLocal=true

kotlin {
    jvmToolchain(21)
    jvm {
        mainRun { mainClass.set("io.kuicksilver.sample.telemetry.MainKt") }
    }
    macosArm64()

    sourceSets {
        commonMain.dependencies {
            implementation("io.kuicksilver:kuicksilver-quic:$kuicksilver")
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation("io.kuicksilver:kuicksilver-testing:$kuicksilver")
        }
    }
}

// Swift export, which this sample does not use, asks for opentelemetry-api 1.41.0 (GHSA-ccrj-gw8r-854m,
// GHSA-rcgg-9c38-7xpx). The repository's dependency verification covers this build, so it takes the first fixed release.
// The Kotlin plugin creates the configuration late, hence matching().
configurations.matching { it.name == "swiftExportClasspath" }.configureEach {
    dependencyConstraints.add(project.dependencies.constraints.create("io.opentelemetry:opentelemetry-api:1.67.0"))
}
