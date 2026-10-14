// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Init script for updating gradle/verification-metadata.xml (CONTRIBUTING.md, "Dependency verification"): ksResolveAll resolves
// every resolvable configuration of every project, leniently, and ksCompileAllTests compiles every test source set, so that
// --write-verification-metadata records all artifacts the build can use, not only those of the tasks one happens to run.
allprojects {
    tasks.register("ksResolveAll") {
        notCompatibleWithConfigurationCache("resolves configurations at execution time")
        doLast {
            var ok = 0; var failed = 0
            project.configurations.filter { it.isCanBeResolved }.forEach { c ->
                try {
                    val artifacts = c.incoming.artifactView { lenient(true) }.artifacts
                    artifacts.artifactFiles.files
                    // a lenient view swallows failures: report them, dependency verification failures above all
                    artifacts.failures.forEach { f ->
                        logger.lifecycle("ksResolveAll ${project.path}:${c.name} unresolved: ${f.message?.lineSequence()?.firstOrNull()}")
                    }
                    ok++
                } catch (e: Exception) {
                    failed++
                    logger.lifecycle("ksResolveAll ${project.path}:${c.name} failed: ${e.message?.lineSequence()?.firstOrNull()}")
                }
            }
            logger.lifecycle("ksResolveAll ${project.path}: $ok resolved, $failed failed")
        }
    }
}
allprojects {
    tasks.register("ksCompileAllTests") {
        val pattern = Regex("compileTestKotlin.+|compile.*UnitTestKotlin.*|compile.*AndroidTest.*Kotlin.*|compile.*DeviceTest.*Kotlin.*|jvmTestClasses")
        dependsOn(provider { tasks.names.filter { pattern.matches(it) } })
    }
}
