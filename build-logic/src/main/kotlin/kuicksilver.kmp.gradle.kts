// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.abi.ExperimentalAbiValidation

plugins {
    id("org.jetbrains.kotlin.multiplatform")
    id("com.android.kotlin.multiplatform.library")
    id("org.jetbrains.dokka")
    id("kuicksilver.coverage")
    id("org.jmailen.kotlinter")   // ktlint (ktlint_official, 140 columns, .editorconfig): `formatKotlin` rewrites, `lintKotlin` gates `check`
}

group = "io.kuicksilver"
version = providers.gradleProperty("kuicksilver.version").getOrElse("0.3.0-SNAPSHOT")

// API reference (Dokka HTML), aggregated by kuicksilver.docs in the root project and published by tools/docs/site.sh.
// Source links point at the release tag v<version>; a -SNAPSHOT has no tag and links to main.
private val docsVersion = version.toString()
private val docsSourceRef = if (docsVersion.endsWith("-SNAPSHOT")) "main" else "v$docsVersion"
private val defaultLinkLists = mapOf(
    "kotlinStdlib" to "kotlinStdlib.package-list",
    "jdk" to "jdk.element-list",
    "androidSdk" to "androidSdk.package-list",
    "androidX" to "androidX.package-list",
)
private val externalApiDocs = mapOf(
    "kotlinx-coroutines" to "https://kotlinlang.org/api/kotlinx.coroutines/",
    "kotlinx-io" to "https://kotlinlang.org/api/kotlinx-io/",
    "ktor" to "https://api.ktor.io/",
)
dokka {
    moduleName.set(project.name)
    moduleVersion.set(docsVersion)
    // only these local values are captured by the lazy link configuration below (configuration cache)
    val defaultLinkFiles: Map<String, java.net.URI> = defaultLinkLists.mapValues { rootProject.file("docs/api/package-lists/${it.value}").toURI() }
    dokkaSourceSets.configureEach {
        // Module.md: the module and package descriptions (Dokka's module documentation format)
        if (layout.projectDirectory.file("Module.md").asFile.exists()) includes.from(layout.projectDirectory.file("Module.md"))
        // test source sets are not API
        if (name.endsWith("Test")) suppress.set(true)
        // -Pkuicksilver.docs.reportUndocumented: a warning for every public declaration without KDoc, counted by tools/docs/site.sh
        reportUndocumented.set(providers.gradleProperty("kuicksilver.docs.reportUndocumented").map { it != "false" }.orElse(false))
        sourceLink {
            localDirectory.set(layout.projectDirectory)
            remoteUrl("https://github.com/kuicksilver/kuicksilver/blob/$docsSourceRef/${project.name}")
            remoteLineSuffix.set("#L")
        }
        // every package-list is read from the repository (refreshed by tools/docs/package-lists.sh), never downloaded, so
        // an offline build keeps the external links: Dokka's default links (stdlib, JDK, Android, AndroidX) get the
        // repository copy, and the three libraries the API exposes are added
        jdkVersion.set(17)   // the JVM API level of the published jars (-Xjdk-release=17): the JDK 17 javadoc
        externalDocumentationLinks.configureEach { defaultLinkFiles[name]?.let { packageListUrl.set(it) } }
        for ((key, docsUrl) in externalApiDocs) {
            externalDocumentationLinks.register(key) {
                url(docsUrl)
                packageListUrl.set(rootProject.file("docs/api/package-lists/$key.package-list").toURI())
            }
        }
    }
}

// the undocumented-declaration warnings are only printed when Dokka runs: with the property, the module's Dokka run is
// never up to date or taken from the cache (tools/docs/site.sh counts them against tools/docs/api-baseline.properties)
if (providers.gradleProperty("kuicksilver.docs.reportUndocumented").map { it != "false" }.getOrElse(false)) {
    tasks.withType<org.jetbrains.dokka.gradle.tasks.DokkaGenerateModuleTask>().configureEach {
        outputs.upToDateWhen { false }
        outputs.cacheIf { false }
    }
}

// strict gate of the site build: with the property, any Dokka warning (an undocumented public declaration, an unresolved
// KDoc link) fails the module's run, so none can come back; the ratchet in tools/docs/api-baseline.properties stays as the
// second check of the finished pages
if (providers.gradleProperty("kuicksilver.docs.reportUndocumented").map { it != "false" }.getOrElse(false)) {
    dokka { dokkaPublications.configureEach { failOnWarning.set(true) } }
}

// @InternalKuicksilverApi declarations stay out of the API reference (kuicksilver-dokka)
dependencies { dokkaPlugin(project(":kuicksilver-dokka")) }

// `<package>.<Class>.**` of the top-level @InternalKuicksilverApi classes in the main sources (see the ABI filter below)
val internalAbiPatterns: Provider<List<String>> =
    providers.provider { internalClassPatterns(kotlin.sourceSets.filterNot { it.name.endsWith("Test") }.flatMap { it.kotlin.srcDirs }) }

kotlin {
    explicitApi()
    @OptIn(ExperimentalKotlinGradlePluginApi::class)
    applyDefaultHierarchyTemplate {
        common { group("jvmCommon") { withJvm(); withCompilations { it.platformType == org.jetbrains.kotlin.gradle.plugin.KotlinPlatformType.androidJvm } } }
    }
    jvmToolchain(21)
    // the expect/actual classes are Beta (KT-61573): this is Kotlin's documented acknowledgement, not a behaviour change
    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
        // main and test compilations stay free of warnings; -Pkuicksilver.warningsAsErrors=false only to look at a dependency bump's new ones
        allWarningsAsErrors.set(providers.gradleProperty("kuicksilver.warningsAsErrors").map { it.toBoolean() }.orElse(true))
    }
    jvm {
        compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
        // the published JVM artifacts link against the JDK 17 API only, whatever toolchain builds them; tests may use the toolchain's JDK
        compilations.getByName("main").compileTaskProvider.configure { compilerOptions.freeCompilerArgs.add("-Xjdk-release=17") }
    }
    android {
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
    // klibs record source paths relative to the checkout: in their debug information and in the names Kotlin/Native derives
    // from file paths (ObjC block bridges), so the published klibs and Kuicksilver.xcframework do not depend on, or reveal,
    // where the checkout was (tools/release/xcframework.sh relies on it for the SwiftPM checksum). The cost: the absolute
    // base is part of freeCompilerArgs, a task input, so a Kotlin/Native compilation is no longer taken from the build
    // cache of another checkout directory (another worktree); KotlinNativeCompile has no argument provider that could
    // hide it, and the compiler wants an absolute base. Before, such a hit would have brought the other path along.
    targets.withType<org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget>().configureEach {
        compilations.configureEach {
            compileTaskProvider.configure { compilerOptions.freeCompilerArgs.add("-Xklib-relative-path-base=${rootDir.canonicalPath}") }
        }
    }

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

    // test source sets may use the internal API (NullCryptoProvider, address literals) and exercise the experimental one;
    // production code opts in per use site
    // the library may use its own experimental API (consumers still get the opt-in warning)
    sourceSets.matching { !it.name.endsWith("Test") }.configureEach {
        languageSettings.optIn("io.kuicksilver.annotations.ExperimentalKuicksilverApi")
    }
    sourceSets.matching { it.name.endsWith("Test") }.configureEach {
        languageSettings.optIn("io.kuicksilver.annotations.InternalKuicksilverApi")
        languageSettings.optIn("io.kuicksilver.annotations.ExperimentalKuicksilverApi")
        languageSettings.optIn("io.kuicksilver.annotations.DelicateKuicksilverApi") // tests drive the delicate knobs on purpose
    }
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

// jvmCommonMain (JVM and Android) has no compilation of its own, so Dokka gets no classpath for it and renders the
// dependency types it uses (SelectorManager, HttpClientEngineFactory) as error classes: it gets the JVM one (declared by
// the kotlin block above)
val jvmDocsClasspath = configurations.named("jvmCompileClasspath")
dokka { dokkaSourceSets.matching { it.name == "jvmCommonMain" }.configureEach { classpath.from(jvmDocsClasspath) } }

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
// Flake hunting (tools/ci/flake-hunt.sh): -Pkuicksilver.test.repeat=<N> runs the JVM suite N times in one build, jvmTest
// then jvmTestRepeat2..N, each with its own results directory and jvmTest's filter (--tests included);
// -Pkuicksilver.test.forks=<K> runs K test JVMs side by side.
providers.gradleProperty("kuicksilver.test.forks").orNull?.toInt()?.let { k -> tasks.withType<Test>().configureEach { maxParallelForks = k } }
// -Pkuicksilver.test.allowNoMatch: a --tests pattern that matches nothing in a module does not fail its test task (one
// pattern given to several modules' tasks, flake-hunt.sh -T)
if (providers.gradleProperty("kuicksilver.test.allowNoMatch").orNull.let { it != null && it != "false" }) {
    tasks.withType<AbstractTestTask>().configureEach { filter.isFailOnNoMatchingTests = false }
}
providers.gradleProperty("kuicksilver.test.repeat").orNull?.toInt()?.takeIf { it > 1 }?.let { n ->
    val jvmTest = tasks.named<Test>("jvmTest")
    val repeats = (2..n).map { i ->
        tasks.register<Test>("jvmTestRepeat$i") {
            group = "verification"
            description = "Run $i of $n of the JVM tests"
            val base = jvmTest.get()
            testClassesDirs = base.testClassesDirs
            classpath = base.classpath
            javaLauncher.set(base.javaLauncher)
            jvmArgs(base.jvmArgs)
            systemProperties(base.systemProperties)
            environment(base.environment)
            workingDir = base.workingDir
            maxHeapSize = base.maxHeapSize
            if (base.options is org.gradle.api.tasks.testing.junitplatform.JUnitPlatformOptions) useJUnitPlatform() else useJUnit()
            // jvmTest's filter, also its --tests patterns: read when the run starts, after the command line was applied
            doFirst {
                val from = base.filter
                filter.includePatterns.addAll(from.includePatterns)
                filter.excludePatterns.addAll(from.excludePatterns)
                (from as? org.gradle.api.internal.tasks.testing.filter.DefaultTestFilter)?.commandLineIncludePatterns?.let {
                    (filter as org.gradle.api.internal.tasks.testing.filter.DefaultTestFilter).setCommandLineIncludePatterns(it)
                }
                filter.isFailOnNoMatchingTests = from.isFailOnNoMatchingTests
            }
            outputs.upToDateWhen { false }
            outputs.cacheIf { false }
            mustRunAfter(jvmTest)
            if (i > 2) mustRunAfter("jvmTestRepeat${i - 1}")
        }
    }
    jvmTest.configure { finalizedBy(repeats) }
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
