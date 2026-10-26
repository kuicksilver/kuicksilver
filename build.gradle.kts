// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

plugins {
    id("kuicksilver.spdx")
    id("kuicksilver.layers")
    id("kuicksilver.coverage")
    id("kuicksilver.release")
}

// R8 for the keep-rule smoke runs (tools/check/android-keep-rules.sh, service-keep-rules.sh): AGP bundles its own copy and
// downloads none, so a clean machine (a CI runner) had no r8 jar. `./gradlew -q ksR8Jar` prints the pinned one, verified
// like every other dependency.
val r8: Configuration by configurations.creating {
    isCanBeConsumed = false
    isTransitive = false
}
dependencies { r8(libs.r8) }
val r8Files: FileCollection = r8
tasks.register("ksR8Jar") {
    inputs.files(r8Files)
    doLast { println(r8Files.singleFile.absolutePath) }
}
