// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Init script for updating gradle/verification-metadata.xml (CONTRIBUTING.md, "Dependency verification"): ksResolveAll resolves
// every resolvable configuration of every project, leniently, and ksCompileAllTests compiles every test source set, so that
// --write-verification-metadata records all artifacts the build can use, not only those of the tasks one happens to run.
// With -Pkuicksilver.resolveAll.strict=true ksResolveAll is the gate's check instead (tools/ci/local-matrix.sh, "check: dependency
// verification"): verification on, it fails when any configuration has an artifact the metadata does not cover, so a gap fails in
// minutes rather than in the one late step that happens to resolve that configuration (the AAR's lint tool and the device tests'
// UTP plugins after the AGP pin moved, 2026-10-15). Other resolution failures (variants no consumer asks for, about 214 of
// them) are only reported, except a repository that could not be reached or answered an HTTP error (a 429 Too Many Requests,
// a 5xx, a refused connection): that cause is printed as Gradle wrote it ("Could not GET '...'. Received status code 429
// from server: ...", which tools/ci/gradlew-retry.sh retries) and fails the task in strict mode, so the gradle-deps job of
// build.yml never saves a cache that misses what a refused request left out. So does a missing file of a module whose
// metadata was found ("Could not find lib-1.0.jar (g:a:1.0)."): Gradle asks for that file only the repository that served
// the metadata, never the next one, and records the miss in the cache, so a read-only cache saved with it fails every job
// that reads it, without a request; printed as Gradle wrote it, it gets gradlew-retry.sh's one refreshed retry. A module
// no repository has ("Could not find g:a:1.0.") stays benign, as does every variant no consumer asks for.
val strict = gradle.startParameter.projectProperties["kuicksilver.resolveAll.strict"] == "true"

/** True when [e] or one of its causes is a dependency verification failure. */
fun isVerificationFailure(e: Throwable?): Boolean =
    generateSequence(e) { it.cause }.any {
        it.javaClass.name.contains("DependencyVerification") || it.message?.contains("Dependency verification failed") == true
    }

/** The cause of [e] that is a failed request (an HTTP error status or a failed connection), or null. */
fun httpFailure(e: Throwable?): Throwable? =
    generateSequence(e) { it.cause }.firstOrNull {
        val m = it.message.orEmpty()
        it.javaClass.simpleName in setOf("HttpErrorStatusCodeException", "HttpRequestException") ||
            "Received status code" in m || "Could not GET" in m || "Could not HEAD" in m
    }

/** The cause of [e] that is a missing file of a found module (Gradle's "Could not find <file> (<g:a:v>)."), or null. */
val missingFileLine = Regex("""Could not find [^ ]+ \([^ ]+:[^ ]+:[^ ]+\)\.""")

fun missingFile(e: Throwable?): Throwable? =
    generateSequence(e) { it.cause }.firstOrNull {
        it.javaClass.simpleName == "ArtifactNotFoundException" ||
            missingFileLine.matches(it.message?.lineSequence()?.firstOrNull().orEmpty().trim())
    }

allprojects {
    tasks.register("ksResolveAll") {
        notCompatibleWithConfigurationCache("resolves configurations at execution time")
        doLast {
            var ok = 0
            var failed = 0
            val unverified = ArrayList<String>()
            val unreachable = ArrayList<String>()
            val missingFiles = ArrayList<String>()
            fun reportHttp(c: Configuration, e: Throwable) {
                missingFile(e)?.let { cause ->
                    // verbatim, on a line of its own: gradlew-retry.sh reads "Could not find <file> (<g:a:v>)." as not found
                    val line = cause.message?.lineSequence()?.firstOrNull().orEmpty().trim()
                    logger.lifecycle("ksResolveAll ${project.path}:${c.name} file missing:\n> $line")
                    missingFiles += "${project.path}:${c.name}: $line"
                    return
                }
                val cause = httpFailure(e) ?: return
                // verbatim, on a line of its own: gradlew-retry.sh reads "Could not GET '...'. Received status code 429"
                val line = cause.message?.lineSequence()?.firstOrNull().orEmpty()
                logger.lifecycle("ksResolveAll ${project.path}:${c.name} request failed:\n> $line")
                generateSequence(cause.cause) { it.cause }.mapNotNull { it.message?.lineSequence()?.firstOrNull() }
                    .forEach { logger.lifecycle("  caused by: $it") }
                unreachable += "${project.path}:${c.name}: $line"
            }
            project.configurations.filter { it.isCanBeResolved }.forEach { c ->
                try {
                    val artifacts = c.incoming.artifactView { lenient(true) }.artifacts
                    artifacts.artifactFiles.files
                    // a lenient view swallows failures: report them, dependency verification failures above all
                    artifacts.failures.forEach { f ->
                        val line = f.message?.lineSequence()?.firstOrNull()
                        logger.lifecycle("ksResolveAll ${project.path}:${c.name} unresolved: $line")
                        if (isVerificationFailure(f)) unverified += "${project.path}:${c.name}: ${f.message}" else reportHttp(c, f)
                    }
                    ok++
                } catch (e: Exception) {
                    failed++
                    logger.lifecycle("ksResolveAll ${project.path}:${c.name} failed: ${e.message?.lineSequence()?.firstOrNull()}")
                    if (isVerificationFailure(e)) unverified += "${project.path}:${c.name}: ${e.message}" else reportHttp(c, e)
                }
            }
            // no "failed verification" here: tools/ci/gradlew-retry.sh never retries a log with those words, and this line
            // is printed on every run
            logger.lifecycle(
                "ksResolveAll ${project.path}: $ok resolved, $failed failed, ${unverified.size} unverified, " +
                    "${unreachable.size} with a failed request, ${missingFiles.size} missing a file",
            )
            if (strict && unverified.isNotEmpty()) {
                // Gradle lists each failed artifact as "  - <file> (<coordinates>) from repository <name>"; one line per artifact
                val artifacts =
                    unverified
                        .flatMap { it.lineSequence().map(String::trim).filter { l -> l.startsWith("- ") }.toList() }
                        .toSortedSet()
                throw GradleException(
                    "Dependency verification failed in ${unverified.size} configuration(s) of ${project.path} " +
                        "(${unverified.first().substringBefore(": ")} ...) for:\n" + artifacts.joinToString("\n") +
                        "\nUpdate gradle/verification-metadata.xml as CONTRIBUTING.md (\"Dependency verification\") says.",
                )
            }
            if (strict && unreachable.isNotEmpty()) {
                throw GradleException(
                    "a repository request failed in ${unreachable.size} configuration(s) of ${project.path}, so not everything " +
                        "was resolved:\n" + unreachable.toSortedSet().joinToString("\n"),
                )
            }
            if (strict && missingFiles.isNotEmpty()) {
                throw GradleException(
                    "a file of a found module is missing in ${missingFiles.size} configuration(s) of ${project.path} (asked " +
                        "only of the repository that served its metadata):\n" + missingFiles.toSortedSet().joinToString("\n"),
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
