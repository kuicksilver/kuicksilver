// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

plugins {
    kotlin("multiplatform") version "2.4.20"
}

val kuicksilver = providers.gradleProperty("kuicksilver.version").getOrElse("0.3.0-SNAPSHOT")   // the version under test; the composite build substitutes it unless -Pkuicksilver.fromMavenLocal=true

kotlin {
    jvmToolchain(21)
    jvm {
        mainRun { mainClass.set("io.kuicksilver.sample.chat.MainKt") }
    }
    // the chat client and server in commonMain build for Apple too (an iOS app takes ChatClient as it is); the tests
    // and the command line run on the JVM
    macosArm64()
    iosArm64()
    iosSimulatorArm64()

    compilerOptions {
        allWarningsAsErrors.set(true)
        optIn.add("io.kuicksilver.annotations.ExperimentalKuicksilverApi")   // WebTransport is experimental in 0.3.0
    }
    sourceSets {
        commonMain.dependencies {
            implementation("io.kuicksilver:kuicksilver-ktor-server:$kuicksilver")
            implementation("io.kuicksilver:kuicksilver-ktor-client:$kuicksilver")
        }
        jvmMain.dependencies {
            runtimeOnly("org.slf4j:slf4j-simple:2.0.17") // Ktor's log on the console of the command line server
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}

// Swift export, which this sample does not use, asks for opentelemetry-api 1.41.0 (GHSA-ccrj-gw8r-854m,
// GHSA-rcgg-9c38-7xpx). The repository's dependency verification covers this build, so it takes the first fixed release.
// The Kotlin plugin creates the configuration late, hence matching().
configurations.matching { it.name == "swiftExportClasspath" }.configureEach {
    dependencyConstraints.add(project.dependencies.constraints.create("io.opentelemetry:opentelemetry-api:1.67.0"))
}

// A test JVM out of heap exits at once and leaves a heap dump in build/test-heap-dumps, as the repository's modules do (the
// kuicksilver.test-jvm plugin of its build-logic, which this build of its own cannot apply): never a JVM that hangs a CI job.
tasks.withType<Test>().configureEach {
    val dumps = layout.buildDirectory.dir("test-heap-dumps").get().asFile
    val dumpPath = workingDir.toPath().relativize(dumps.toPath()).toString().replace(File.separatorChar, '/')
    jvmArgs("-XX:+ExitOnOutOfMemoryError", "-XX:+HeapDumpOnOutOfMemoryError", "-XX:HeapDumpPath=$dumpPath")
    doFirst { dumps.mkdirs() }
}

// the console client reads its messages from the terminal: `./gradlew jvmRun --args="client ..." --console=plain`
tasks.withType<JavaExec>().matching { it.name == "jvmRun" }.configureEach { standardInput = System.`in` }
