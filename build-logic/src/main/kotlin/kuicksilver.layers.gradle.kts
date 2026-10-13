// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// Layer rule (ADR-0005): each module depends only on the module directly below it.
val allowed = mapOf(
    "kuicksilver-native" to emptySet(),
    "kuicksilver-tls" to setOf("kuicksilver-native"),
    "kuicksilver-ktor-network" to setOf("kuicksilver-tls"),
    "kuicksilver-quic" to setOf("kuicksilver-tls"),
    "kuicksilver-testing" to setOf("kuicksilver-quic"),
    "kuicksilver-interop" to setOf("kuicksilver-quic", "kuicksilver-http3"),
    "kuicksilver-bench" to setOf("kuicksilver-quic"),
    "kuicksilver-http3" to setOf("kuicksilver-quic"),
    "kuicksilver-ktor-server" to setOf("kuicksilver-http3", "kuicksilver-ktor-network"),
    "kuicksilver-ktor-client" to setOf("kuicksilver-http3", "kuicksilver-ktor-network"),
    "kuicksilver-soak" to setOf("kuicksilver-ktor-client", "kuicksilver-ktor-server"),   // the soak harness drives the whole stack (not published)
)
val checkLayerDependencies by tasks.registering {
    group = "verification"
    description = "Fails when a module depends on a project outside its allowed neighbour"
    val violations = subprojects.flatMap { p ->
        // test configurations are not part of the published layering: engine tests may run the other engine as a peer
        p.configurations.filter { (it.name.endsWith("Api") || it.name.endsWith("Implementation") || it.name == "api" || it.name == "implementation") && !it.name.contains("Test") }.flatMap { c ->
            c.dependencies.withType(ProjectDependency::class.java).map { d -> Triple(p.name, c.name, d.name) }
        }
    }.filter { (from, _, to) -> to !in (allowed[from] ?: emptySet()) }.map { (from, c, to) -> "$from ($c) -> $to" }
    doLast {
        if (violations.isNotEmpty()) throw GradleException("Layer rule violated:\n" + violations.joinToString("\n"))
        println("Layer dependencies OK")
    }
}
tasks.matching { it.name == "check" }.configureEach { dependsOn(checkLayerDependencies) }
