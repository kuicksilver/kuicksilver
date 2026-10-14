// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import java.security.MessageDigest
import org.jetbrains.kotlin.gradle.plugin.mpp.apple.XCFramework

plugins {
    kotlin("multiplatform")
}

val kuicksilver = providers.gradleProperty("kuicksilver.version").getOrElse("0.2.0-SNAPSHOT")

// Kuicksilver.xcframework for Swift-only applications (docs/guide/ios.md, "Swift-only"): a dynamic framework, so each
// slice carries its own dSYM and its own PrivacyInfo.xcprivacy, distributed as a SwiftPM binaryTarget.
//   ./gradlew -p samples/ios :kuicksilver-swift:assembleKuicksilverReleaseXCFramework
//   -> kuicksilver-swift/build/XCFrameworks/release/Kuicksilver.xcframework (+ Kuicksilver.framework.dSYM per slice)
//   ./gradlew -p samples/ios :kuicksilver-swift:zipKuicksilverXCFramework   (the zip and checksum SwiftPM needs)
kotlin {
    val xcf = XCFramework("Kuicksilver")
    listOf(iosArm64(), iosSimulatorArm64()).forEach { target ->
        target.binaries.framework {
            baseName = "Kuicksilver"
            isStatic = false
            // the public API of these modules is visible from Swift; everything else they use stays internal
            export("io.kuicksilver:kuicksilver-tls:$kuicksilver")
            export("io.kuicksilver:kuicksilver-quic:$kuicksilver")
            export("io.kuicksilver:kuicksilver-http3:$kuicksilver")
            binaryOption("bundleId", "io.kuicksilver.Kuicksilver")
            binaryOption("bundleShortVersionString", kuicksilver.substringBefore('-'))
            xcf.add(this)
        }
    }
    sourceSets {
        commonMain.dependencies {
            api("io.kuicksilver:kuicksilver-tls:$kuicksilver")
            api("io.kuicksilver:kuicksilver-quic:$kuicksilver")
            api("io.kuicksilver:kuicksilver-http3:$kuicksilver")
        }
    }
}

// Apple reads a framework's privacy manifest from the framework bundle (the root of a shallow iOS bundle).
val privacyManifest = rootProject.file("../../kuicksilver-native/apple/PrivacyInfo.xcprivacy")
tasks.matching { it.name.startsWith("assembleKuicksilver") && it.name.endsWith("XCFramework") }.configureEach {
    inputs.file(privacyManifest)
    doLast {
        outputs.files.files.flatMap { it.walkTopDown().filter { f -> f.isDirectory && f.name == "Kuicksilver.framework" }.toList() }
            .forEach { privacyManifest.copyTo(it.resolve("PrivacyInfo.xcprivacy"), overwrite = true) }
    }
}

// SwiftPM's binaryTarget takes a zip and its checksum (`swift package compute-checksum` gives the same SHA-256).
tasks.register<Zip>("zipKuicksilverXCFramework") {
    dependsOn("assembleKuicksilverReleaseXCFramework")
    from(layout.buildDirectory.dir("XCFrameworks/release")) { include("Kuicksilver.xcframework/**") }
    archiveFileName.set("Kuicksilver.xcframework.zip")
    destinationDirectory.set(layout.buildDirectory.dir("spm"))
    isPreserveFileTimestamps = false; isReproducibleFileOrder = true
    doLast {
        val zip = archiveFile.get().asFile
        val sha = MessageDigest.getInstance("SHA-256").digest(zip.readBytes()).joinToString("") { "%02x".format(it) }
        zip.resolveSibling("checksum.txt").writeText("$sha\n")
        logger.lifecycle("SwiftPM binaryTarget checksum: $sha")
    }
}
