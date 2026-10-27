// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import org.jetbrains.kotlin.gradle.dsl.abi.ExperimentalAbiValidation

plugins {
    id("org.jetbrains.kotlin.multiplatform")
    id("com.android.kotlin.multiplatform.library")
    id("org.jetbrains.dokka")
    id("kuicksilver.coverage")
    id("org.jmailen.kotlinter")   // ktlint (ktlint_official, 140 columns, .editorconfig): `formatKotlin` rewrites, `lintKotlin` gates `check`
}

group = "io.kuicksilver"
version = providers.gradleProperty("kuicksilver.version").getOrElse("0.2.1-SNAPSHOT")

// `<package>.<Class>.**` of the top-level @InternalKuicksilverApi classes in the main sources (see the ABI filter below)
val internalAbiPatterns: Provider<List<String>> =
    providers.provider { internalClassPatterns(kotlin.sourceSets.filterNot { it.name.endsWith("Test") }.flatMap { it.kotlin.srcDirs }) }

kotlin {
    explicitApi()
    applyDefaultHierarchyTemplate {
        common { group("jvmCommon") { withJvm(); withCompilations { it.platformType == org.jetbrains.kotlin.gradle.plugin.KotlinPlatformType.androidJvm } } }
    }
    jvmToolchain(21)
    jvm {
        compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
        // the published JVM artifacts link against the JDK 17 API only, whatever toolchain builds them; tests may use the toolchain's JDK
        compilations.getByName("main").compileTaskProvider.configure { compilerOptions.freeCompilerArgs.add("-Xjdk-release=17") }
    }
    androidLibrary {
        // "native" is a Java keyword: R classes need a valid Java package, so that module uses io.kuicksilver.nativelib
        namespace = "io.kuicksilver." + project.name.removePrefix("kuicksilver-").replace('-', '.').replace("native", "nativelib")
        compileSdk = 35
        minSdk = 24
        withHostTestBuilder {}.configure {}
        withDeviceTestBuilder { sourceSetTreeName = "test" }.configure { instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner" }
        packaging { resources.excludes += setOf("META-INF/AL2.0", "META-INF/LGPL2.1", "META-INF/*.kotlin_module") }   // LICENSE/NOTICE stay: every artifact carries them (Apache-2.0 section 4)
    }
    linuxX64(); linuxArm64()
    macosArm64()   // macosX64 dropped 2026-10-09 (owner decision): deprecated by Kotlin, never tested; the JVM on Intel Macs keeps its JNI library
    iosArm64(); iosSimulatorArm64()
    mingwX64()

    // internal API is not part of the public ABI, so it stays out of the ABI dumps. annotatedWith drops the annotated
    // declarations; in the JVM dumps it keeps their companions and nested classes, so the top-level internal classes are
    // also excluded by name with everything inside them (checkInternalAbi below verifies the result)
    @OptIn(ExperimentalAbiValidation::class)
    abiValidation {
        filters {
            exclude {
                annotatedWith.add(INTERNAL_API_ANNOTATION)
                byNames.addAll(internalAbiPatterns)
            }
        }
    }

    // test source sets may use the internal API (NullCryptoProvider, address literals); production code opts in per use site
    sourceSets.matching { it.name.endsWith("Test") }.configureEach { languageSettings.optIn("io.kuicksilver.annotations.InternalKuicksilverApi") }
    sourceSets {
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(catalog.findLibrary("kotlinx-coroutines-test").get())
        }
        getByName("androidDeviceTest").dependencies {
            implementation(kotlin("test-junit"))
            implementation("androidx.test:runner:1.6.2")
            implementation("androidx.test.ext:junit:1.2.1")
        }
    }
}

// Every published artifact (jar, AAR) carries the project LICENSE and NOTICE and the OpenSSL license it links statically (Apache-2.0 section 4(a)/(d)).
val licenseResources = tasks.register<Sync>("licenseResources") {
    from(rootProject.file("LICENSE")) { into("META-INF") }
    from(rootProject.file("NOTICE")) { into("META-INF") }
    // AGP strips META-INF/LICENSE and META-INF/NOTICE from an AAR by default, and an app that depends on several of our AARs
    // fails its resource merge on any path two of them share: the texts also travel under META-INF/licenses/<module>/
    val dir = "META-INF/licenses/${project.name}"
    from(rootProject.file("licenses/LICENSE.openssl.txt")) { into(dir) }
    from(rootProject.file("LICENSE")) { into(dir); rename { "LICENSE.txt" } }
    from(rootProject.file("NOTICE")) { into(dir); rename { "NOTICE.txt" } }
    into(layout.buildDirectory.dir("generated/license-resources"))
}
kotlin.sourceSets.getByName("commonMain").resources.srcDir(licenseResources.map { it.destinationDir })
kotlin.sourceSets.getByName("androidMain").resources.srcDir(licenseResources.map { it.destinationDir })   // the AAR packages androidMain resources, not commonMain ones
tasks.withType<Jar>().configureEach { from(rootProject.file("LICENSE")) { into("META-INF") }; from(rootProject.file("NOTICE")) { into("META-INF") }; from(rootProject.file("licenses/LICENSE.openssl.txt")) { into("META-INF/licenses") }; duplicatesStrategy = DuplicatesStrategy.EXCLUDE }

// Explicit native library for the JVM tests (Linux containers, CI): -Pkuicksilver.native.path=... is forwarded to the test JVM.
tasks.withType<Test>().configureEach { providers.gradleProperty("kuicksilver.native.path").orNull?.let { systemProperty("kuicksilver.native.path", it) } }
// CI jdk-compat job (review I7, M3): -Pkuicksilver.test.jdk=<N> runs the JVM tests on JDK N (a toolchain Gradle can find, e.g. through
// -Porg.gradle.java.installations.paths=...), -Pkuicksilver.test.jvmArgs="<args>" passes JVM flags to them (JDK 24+: --illegal-native-access=deny).
tasks.withType<Test>().matching { it.name == "jvmTest" }.configureEach {
    providers.gradleProperty("kuicksilver.test.jdk").orNull?.let { v ->
        javaLauncher.set(project.extensions.getByType<org.gradle.jvm.toolchain.JavaToolchainService>().launcherFor { languageVersion.set(org.gradle.jvm.toolchain.JavaLanguageVersion.of(v)) })
    }
    providers.gradleProperty("kuicksilver.test.jvmArgs").orNull?.let { a -> jvmArgs(a.split(' ').filter { it.isNotBlank() }) }
}

// The JVM and Android dumps must not list a class nested in an @InternalKuicksilverApi class (its companion, a nested
// type): checked from the compiled classes, independently of the dump filter above.
val checkInternalAbi = tasks.register<CheckInternalAbiTask>("checkInternalAbi") {
    group = "verification"
    description = "Fails when an ABI dump lists a class annotated, or nested in a class annotated, with @InternalKuicksilverApi"
    dumps.from(layout.projectDirectory.file("api/jvm/${project.name}.api"), layout.projectDirectory.file("api/android/${project.name}.api"))
    for (compile in listOf("compileKotlinJvm", "compileAndroidMain")) {
        classDirs.from(tasks.named<org.jetbrains.kotlin.gradle.tasks.KotlinJvmCompile>(compile).flatMap { it.destinationDirectory })
    }
}
tasks.matching { it.name == "check" || it.name == "checkKotlinAbi" }.configureEach { if (name == "check") dependsOn(checkInternalAbi) else finalizedBy(checkInternalAbi) }
