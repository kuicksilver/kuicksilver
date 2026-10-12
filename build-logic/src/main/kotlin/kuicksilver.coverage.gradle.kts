// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// Line coverage of the JVM tests, reported without a threshold (K7 D). Applied by every library module through
// kuicksilver.kmp and by the root project. The custom variant `jvmTests` holds the JVM target only:
// `koverHtmlReportJvmTests` in a module, and in the root `koverHtmlReportJvmTests` / `koverXmlReportJvmTests` merge the
// published modules. Kover's total variant would also run `testAndroidHostTest`, and the host JVM cannot load the
// Android JNI library there.
//
// Instrumentation is opt-in: without `-Pkuicksilver.coverage` no test task gets the Kover agent, so `jvmTest`, the fuzz
// and Monte-Carlo runs and `testAndroidHostTest` run uninstrumented. The report tasks need the property.
plugins { id("org.jetbrains.kotlinx.kover") }

kover { currentProject { instrumentation { disabledForAll = !providers.gradleProperty("kuicksilver.coverage").isPresent } } }

if (project == rootProject) {
    val published = listOf("native", "tls", "ktor-network", "quic", "http3", "ktor-client", "ktor-server")
    dependencies { published.forEach { add("kover", project(":kuicksilver-$it")) } }
    kover { currentProject { createVariant("jvmTests") {} } }   // empty here: the merged report collects the modules' variants
} else {
    kover { currentProject { createVariant("jvmTests") { add("jvm") } } }
}

// generated QPACK tables (tools generate them; RFC 9204 appendix A, RFC 7541 appendix B): data, not logic
kover { reports { filters { excludes { classes("io.kuicksilver.http3.qpack.StaticTableData*", "io.kuicksilver.http3.qpack.HuffmanTable*") } } } }
