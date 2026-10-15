// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Init script for updating gradle/verification-metadata.xml (CONTRIBUTING.md, "Dependency verification"): ksResolveAll resolves
// every resolvable configuration of every project, leniently, and ksCompileAllTests compiles every test source set, so that
// --write-verification-metadata records all artifacts the build can use, not only those of the tasks one happens to run.
// With -Pkuicksilver.resolveAll.strict=true ksResolveAll is the gate's check instead (tools/ci/local-matrix.sh, "check: dependency
// verification"): verification on, it fails when any configuration has an artifact the metadata does not cover, so a gap fails in
// minutes rather than in the one late step that happens to resolve that configuration (the AAR's lint tool and the device tests'
// UTP plugins after the AGP pin moved, 2026-10-15). Other resolution failures (variants no consumer asks for) are only reported.
val strict = gradle.startParameter.projectProperties["kuicksilver.resolveAll.strict"] == "true"

/** True when [e] or one of its causes is a dependency verification failure. */
fun isVerificationFailure(e: Throwable?): Boolean =
    generateSequence(e) { it.cause }.any {
        it.javaClass.name.contains("DependencyVerification") || it.message?.contains("Dependency verification failed") == true
    }

allprojects {
    tasks.register("ksResolveAll") {
        notCompatibleWithConfigurationCache("resolves configurations at execution time")
        doLast {
            var ok = 0
            var failed = 0
            val unverified = ArrayList<String>()
            project.configurations.filter { it.isCanBeResolved }.forEach { c ->
                try {
                    val artifacts = c.incoming.artifactView { lenient(true) }.artifacts
                    artifacts.artifactFiles.files
                    // a lenient view swallows failures: report them, dependency verification failures above all
                    artifacts.failures.forEach { f ->
                        val line = f.message?.lineSequence()?.firstOrNull()
                        logger.lifecycle("ksResolveAll ${project.path}:${c.name} unresolved: $line")
                        if (isVerificationFailure(f)) unverified += "${project.path}:${c.name}: ${f.message}"
                    }
                    ok++
                } catch (e: Exception) {
                    failed++
                    logger.lifecycle("ksResolveAll ${project.path}:${c.name} failed: ${e.message?.lineSequence()?.firstOrNull()}")
                    if (isVerificationFailure(e)) unverified += "${project.path}:${c.name}: ${e.message}"
                }
            }
            logger.lifecycle("ksResolveAll ${project.path}: $ok resolved, $failed failed, ${unverified.size} failed verification")
            if (strict && unverified.isNotEmpty()) {
                // Gradle lists each failed artifact as "  - <file> (<coordinates>) from repository <name>"; one line per artifact
                val artifacts =
                    unverified
                        .flatMap { it.lineSequence().map(String::trim).filter { l -> l.startsWith("- ") }.toList() }
                        .toSortedSet()
                throw GradleException(
                    "dependency verification failed in ${unverified.size} configuration(s) of ${project.path} " +
                        "(${unverified.first().substringBefore(": ")} ...) for:\n" + artifacts.joinToString("\n") +
                        "\nUpdate gradle/verification-metadata.xml as CONTRIBUTING.md (\"Dependency verification\") says.",
                )
            }
        }
    }
}
allprojects {
    tasks.register("ksCompileAllTests") {
        val pattern = Regex("compileTestKotlin.+|compile.*UnitTestKotlin.*|compile.*AndroidTest.*Kotlin.*|compile.*DeviceTest.*Kotlin.*|jvmTestClasses")
        dependsOn(provider { tasks.names.filter { pattern.matches(it) } })
    }
}
