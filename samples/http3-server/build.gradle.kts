// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

plugins {
    kotlin("jvm") version "2.4.20"
    application
}

val kuicksilver = providers.gradleProperty("kuicksilver.version").getOrElse("0.3.0-SNAPSHOT")   // the version under test; the composite build substitutes it unless -Pkuicksilver.fromMavenLocal=true

kotlin {
    jvmToolchain(21)
    compilerOptions { allWarningsAsErrors.set(true) }
}

dependencies {
    implementation("io.kuicksilver:kuicksilver-ktor-server:$kuicksilver")   // brings Ktor's server core
    runtimeOnly("org.slf4j:slf4j-simple:2.0.17")                           // Ktor's log ("Responding at ...") on the console
    testImplementation("io.kuicksilver:kuicksilver-ktor-client:$kuicksilver")
    testImplementation(kotlin("test"))
}

// ./gradlew -p samples/http3-server run, after certs/gen.sh (application.conf reads build/dev-certs)
application { mainClass.set("io.kuicksilver.sample.http3.MainKt") }

// A test JVM out of heap exits at once and leaves a heap dump in build/test-heap-dumps, as the repository's modules do (the
// kuicksilver.test-jvm plugin of its build-logic, which this build of its own cannot apply): never a JVM that hangs a CI job.
tasks.test {
    useJUnitPlatform()
    val dumps = layout.buildDirectory.dir("test-heap-dumps").get().asFile
    val dumpPath = workingDir.toPath().relativize(dumps.toPath()).toString().replace(File.separatorChar, '/')
    jvmArgs("-XX:+ExitOnOutOfMemoryError", "-XX:+HeapDumpOnOutOfMemoryError", "-XX:HeapDumpPath=$dumpPath")
    doFirst { dumps.mkdirs() }
}
