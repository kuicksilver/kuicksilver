// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The test plugin of every module with tests (through kuicksilver.kmp, or directly). Despite its name it covers more than
// the JVM: the console logging of a failure at the end applies to every test task, Kotlin/Native's included.
//
// JVM tests: the test JVMs end at once when they run out of heap, and fail their task. Without it, the coroutines of such
// a JVM went on failing with OutOfMemoryError in their exception handlers and the JVM never ended, until the CI job's
// timeout (windows-jvm, 2 hours). The heap dump (java_pid<N>.hprof) goes to build/test-heap-dumps, beside the fuzz tests'
// fuzz-case-<pid>.txt (the case running last); the CI test jobs upload that directory when they fail, and the broader
// report uploads leave dumps out.
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

// A failed test shows its assertion's message and stack on the console, so the CI job's log says what failed. Gradle's
// default (exceptionFormat SHORT) printed only the exception's class and a location, "kotlin.AssertionError at null:-1" for
// a Kotlin/Native test, and the message was only in the uploaded HTML report. Every test task: the JVM's Test and Kotlin/
// Native's KotlinNativeTest (both AbstractTestTask). Failures only: no event for a test that passed, started or was skipped;
// the stack is cut at the test's entry point (Gradle's TRUNCATE filter, the default).
tasks.withType<AbstractTestTask>().configureEach {
    testLogging {
        events(org.gradle.api.tasks.testing.logging.TestLogEvent.FAILED)
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showExceptions = true
        showCauses = true
        showStackTraces = true
    }
}
