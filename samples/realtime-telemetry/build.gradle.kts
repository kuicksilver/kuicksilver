// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

plugins {
    kotlin("multiplatform") version "2.4.20"
}

val kuicksilver = providers.gradleProperty("kuicksilver.version").getOrElse("0.2.1-SNAPSHOT")   // the version under test; the composite build substitutes it unless -Pkuicksilver.fromMavenLocal=true

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
