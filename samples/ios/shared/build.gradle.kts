// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

plugins {
    kotlin("multiplatform")
}

val kuicksilver = providers.gradleProperty("kuicksilver.version").getOrElse("0.1.0-SNAPSHOT")

kotlin {
    // One static framework for the whole app (see docs/guide/ios.md: never two Kotlin/Native frameworks in one app).
    // The Xcode Run Script phase calls :shared:embedAndSignAppleFrameworkForXcode, which builds the slice Xcode asks for.
    listOf(iosArm64(), iosSimulatorArm64()).forEach { target ->
        target.binaries.framework {
            baseName = "Shared"
            isStatic = true   // linked into the app; the size budget reads the app's linker map (tools/check/ios-size.sh)
        }
    }

    sourceSets {
        commonMain.dependencies {
            implementation("io.kuicksilver:kuicksilver-http3:$kuicksilver")
        }
        iosTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}
