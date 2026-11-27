// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

plugins {
    id("kuicksilver.spdx")
    id("kuicksilver.layers")
    id("kuicksilver.coverage")
    id("kuicksilver.release")
    id("kuicksilver.docs")
}

// R8 for the keep-rule smoke runs (tools/check/android-keep-rules.sh, service-keep-rules.sh, r8-inlining.sh): AGP bundles
// its own copy and downloads none, so a clean machine (a CI runner) had no r8 jar. `./gradlew -q ksR8Jar` prints the pinned
// one, verified like every other dependency.
val r8: Configuration = configurations.create("r8") {
    isCanBeConsumed = false
    isTransitive = false
}
dependencies { r8(libs.r8) }
val r8Files: FileCollection = r8
tasks.register("ksR8Jar") {
    inputs.files(r8Files)
    doLast { println(r8Files.singleFile.absolutePath) }
}
// The kotlin-stdlib JVM jar R8 shrinks the AAR's classes with (tools/check/android-keep-rules.sh): the build's Kotlin version,
// verified, wherever Gradle keeps it (the Gradle user home, or the read-only dependency cache of GRADLE_RO_DEP_CACHE in
// CI, which Gradle reads in place and never copies). `./gradlew -q ksKotlinStdlibJar` prints its path.
val kotlinStdlib: Configuration = configurations.create("kotlinStdlibJar") {
    isCanBeConsumed = false
    isTransitive = false
    attributes {
        attribute(Usage.USAGE_ATTRIBUTE, objects.named(Usage.JAVA_RUNTIME))
        attribute(Category.CATEGORY_ATTRIBUTE, objects.named(Category.LIBRARY))
        attribute(LibraryElements.LIBRARY_ELEMENTS_ATTRIBUTE, objects.named(LibraryElements.JAR))
        attribute(TargetJvmEnvironment.TARGET_JVM_ENVIRONMENT_ATTRIBUTE, objects.named(TargetJvmEnvironment.STANDARD_JVM))
    }
}
dependencies { kotlinStdlib("org.jetbrains.kotlin:kotlin-stdlib:${libs.versions.kotlin.get()}") }
val kotlinStdlibFiles: FileCollection = kotlinStdlib
tasks.register("ksKotlinStdlibJar") {
    inputs.files(kotlinStdlibFiles)
    doLast { println(kotlinStdlibFiles.singleFile.absolutePath) }
}
