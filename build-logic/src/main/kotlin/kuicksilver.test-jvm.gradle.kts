// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// Every module with JVM tests applies this (through kuicksilver.kmp, or directly): its test JVMs end at once when they run
// out of heap, and fail their task. Without it, the coroutines of such a JVM went on failing with OutOfMemoryError in their
// exception handlers and the JVM never ended, until the CI job's timeout (windows-jvm, 2 hours). The heap dump
// (java_pid<N>.hprof) goes to build/test-heap-dumps, beside the fuzz tests' fuzz-case-<pid>.txt (the case running last);
// the CI test jobs upload that directory when they fail, and the broader report uploads leave dumps out.
// samples/realtime-telemetry, a build of its own, sets the same flags itself.
tasks.withType<Test>().configureEach {
    val dumps = layout.buildDirectory.dir("test-heap-dumps").get().asFile
    // relative to the test JVM's working directory (the project directory) and with '/' on every host: the flag is part of
    // the task's cache key
    val dumpPath = workingDir.toPath().relativize(dumps.toPath()).toString().replace(File.separatorChar, '/')
    jvmArgs("-XX:+ExitOnOutOfMemoryError", "-XX:+HeapDumpOnOutOfMemoryError", "-XX:HeapDumpPath=$dumpPath")
    systemProperty("kuicksilver.test.heapDumps", dumpPath) // where the fuzz tests name the case running last (FuzzCase.kt)
    doFirst { dumps.mkdirs() } // a HeapDumpPath that is no directory would be taken as a file name
}
