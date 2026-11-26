// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// `./gradlew -q :<module>:ksAndroidRuntimeJars`: the class jars an Android app links with this library, one path per line.
// The R8 checks of tools/check (r8-inlining.sh) shrink and dex them with the AAR as an app's build would. Applied by the
// modules those checks build an app from (kuicksilver-ktor-client, kuicksilver-ktor-server).
val androidRuntimeJars: FileCollection =
    files(
        provider {
            configurations.getByName("androidRuntimeClasspath").incoming.artifactView {
                attributes { attribute(Attribute.of("artifactType", String::class.java), "android-classes-jar") }
            }.files
        },
    )
tasks.register("ksAndroidRuntimeJars") {
    inputs.files(androidRuntimeJars)
    doLast { androidRuntimeJars.forEach { println(it.absolutePath) } }
}
