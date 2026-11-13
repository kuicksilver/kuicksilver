// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// Every test JVM of a project that applies this (kuicksilver.kmp does; kuicksilver-bench, -soak and -interop too) ends at
// once when it runs out of heap, and fails its task: without it, the coroutines of such a JVM went on failing with
// OutOfMemoryError in their exception handlers and the JVM never ended, until the CI job's timeout (windows-jvm, 2 hours).
// Its heap dump (java_pid<N>.hprof) goes to build/test-heap-dumps, which the CI test jobs upload when they fail; the
// broader report uploads leave it out. samples/realtime-telemetry, a build of its own, sets the same flags itself.
tasks.withType<Test>().configureEach {
    val dumps = layout.buildDirectory.dir("test-heap-dumps").get().asFile
    // relative to the test JVM's working directory (the project directory) and with '/' on every host: the flag is part of
    // the task's cache key
    val dumpPath = workingDir.toPath().relativize(dumps.toPath()).toString().replace(File.separatorChar, '/')
    jvmArgs("-XX:+ExitOnOutOfMemoryError", "-XX:+HeapDumpOnOutOfMemoryError", "-XX:HeapDumpPath=$dumpPath")
    doFirst { dumps.mkdirs() } // a HeapDumpPath that is no directory would be taken as a file name
}
