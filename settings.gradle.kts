// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// Repositories. In CI (kuicksilver.centralMirror=true, set by .github/actions/setup) Google's mirror of Maven Central
// comes before Central: Central answers 429 Too Many Requests to GitHub's runners when a matrix of jobs resolves at
// once (runs 44892895905, 45958310638), and now and then 404 for files it has (runs 44630132347, 44657561143,
// 44674970605). Gradle takes a 404 as "not there" and asks the next repository, so Central stays as the fallback for a
// module the mirror does not have (yet); any other answer (a 403, 429 or 5xx) fails the resolution, so the mirror's
// content filter keeps away what Central does not serve: plugin markers, the Plugin Portal's own plugins, Google's own
// groups. A version range would list the versions of every repository on every resolution, so the build has none
// (build-logic pins the one the Kotlin plugin asks for). Builds outside CI (the release included) leave the mirror out:
// a machine behind a filter may not reach it, and an unreachable repository fails the resolution rather than falling
// through. It changes no trust: every file still has to match gradle/verification-metadata.xml (signature or SHA-256,
// per artifact, whatever repository served it; CONTRIBUTING.md, "Dependency verification"). Central comes before the
// Gradle Plugin Portal, which answers for Central's modules with a redirect there, one more hop that can fail; the
// portal is asked only for the plugins only it has (exclusiveContent), Google's repository only for the Android and
// Google groups. build-logic/settings.gradle.kts and the samples have the same lists. A missing file of a module that
// was found (a jar) is asked for only where its metadata came from: tools/ci/gradlew-retry.sh retries that in CI.
pluginManagement {
    includeBuild("build-logic")
    repositories {
        google {
            content {
                includeGroupByRegex("androidx\\..*")
                includeGroupByRegex("com\\.android(\\..*)?")
                includeGroupByRegex("com\\.google\\..*")
            }
        }
        if (providers.gradleProperty("kuicksilver.centralMirror").orNull == "true") {
            maven("https://maven-central.storage-download.googleapis.com/maven2/") {
                name = "MavenCentralMirror"
                // never a plugin marker (Central has some, the Plugin Portal all), the Plugin Portal's own
                // plugins or Google's own groups: Gradle asks the next repository only after a 404, so a 403,
                // 429 or 5xx the mirror answered for a module it does not have would fail the resolution
                mavenContent {
                    releasesOnly()
                    excludeModuleByRegex(".*", ".*\\.gradle\\.plugin")
                    excludeModule("org.jmailen.gradle", "kotlinter-gradle")
                    excludeModule("org.jetbrains.kotlinx", "kotlinx-benchmark-plugin")
                    excludeGroupByRegex("org\\.gradle\\.kotlin(\\..*)?")
                    excludeGroupByRegex("androidx\\..*")
                    excludeGroupByRegex("com\\.android(\\..*)?")
                    excludeGroupByRegex("com\\.google\\.android(\\..*)?")
                    excludeGroupByRegex("com\\.google\\.testing\\.platform(\\..*)?")
                }
            }
        }
        mavenCentral()
        exclusiveContent {
            forRepository { gradlePluginPortal() }
            filter {
                includeModule("org.jmailen.gradle", "kotlinter-gradle")
                includeModule("org.jetbrains.kotlinx", "kotlinx-benchmark-plugin")
                includeGroupByRegex("org\\.gradle\\.kotlin(\\..*)?")
            }
        }
    }
}
dependencyResolutionManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("androidx\\..*")
                includeGroupByRegex("com\\.android(\\..*)?")
                includeGroupByRegex("com\\.google\\..*")
            }
        }
        if (providers.gradleProperty("kuicksilver.centralMirror").orNull == "true") {
            maven("https://maven-central.storage-download.googleapis.com/maven2/") {
                name = "MavenCentralMirror"
                // never a plugin marker (Central has some, the Plugin Portal all), the Plugin Portal's own
                // plugins or Google's own groups: Gradle asks the next repository only after a 404, so a 403,
                // 429 or 5xx the mirror answered for a module it does not have would fail the resolution
                mavenContent {
                    releasesOnly()
                    excludeModuleByRegex(".*", ".*\\.gradle\\.plugin")
                    excludeModule("org.jmailen.gradle", "kotlinter-gradle")
                    excludeModule("org.jetbrains.kotlinx", "kotlinx-benchmark-plugin")
                    excludeGroupByRegex("org\\.gradle\\.kotlin(\\..*)?")
                    excludeGroupByRegex("androidx\\..*")
                    excludeGroupByRegex("com\\.android(\\..*)?")
                    excludeGroupByRegex("com\\.google\\.android(\\..*)?")
                    excludeGroupByRegex("com\\.google\\.testing\\.platform(\\..*)?")
                }
            }
        }
        mavenCentral()
    }
}
rootProject.name = "kuicksilver"

// Version floors for tool libraries that the Android and Kotlin plugins resolve in configurations of their own: the
// versions they ask for have known vulnerabilities (OSV), each floor is the first fixed release. None of these
// configurations reaches a published module or a runtime class path: Android lint (androidLintTool), the device tests'
// Unified Test Platform plugins, and Swift export (unused here, resolved by ksResolveAll). A constraint only raises a
// version, and a configuration without the module ignores it. The plugin class path gets its floors in
// build-logic/build.gradle.kts.
gradle.lifecycle.beforeProject {
    val constraints = dependencies.constraints
    configurations.configureEach {
        val floors = when {
            // GHSA-7r82-7xv7-xcpj: com.android.tools:sdklib asks for httpmime 4.5.6, which asks for httpclient 4.5.6
            name == "androidLintTool" || name.startsWith("unified-test-platform-") ->
                listOf("org.apache.httpcomponents:httpclient:4.5.14")
            // GHSA-ccrj-gw8r-854m, GHSA-rcgg-9c38-7xpx: org.jetbrains.kotlin:swift-export-embeddable asks for 1.41.0
            name == "swiftExportClasspath" -> listOf("io.opentelemetry:opentelemetry-api:1.67.0")
            else -> emptyList()
        }
        for (floor in floors) {
            dependencyConstraints.add(constraints.create(floor) { because("first release without the known vulnerabilities") })
        }
    }
}

include(":kuicksilver-native", ":kuicksilver-tls", ":kuicksilver-ktor-network", ":kuicksilver-quic", ":kuicksilver-testing", ":kuicksilver-interop", ":kuicksilver-bench")
include(":kuicksilver-http3", ":kuicksilver-http2", ":kuicksilver-ktor-server", ":kuicksilver-ktor-client", ":kuicksilver-bom")
include(":kuicksilver-soak")
include(":kuicksilver-engine-interop")
include(":kuicksilver-dokka")
