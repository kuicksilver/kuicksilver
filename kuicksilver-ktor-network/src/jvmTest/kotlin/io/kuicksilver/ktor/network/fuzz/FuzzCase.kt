// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network.fuzz

import org.junit.jupiter.api.TestInfo
import java.io.File
import java.io.IOException

// This file is the same in every fuzz package but for its package line (the modules share no test source set):
// tools/check/fuzz-case-sync.sh fails when a copy drifts. Change them all together.

/**
 * Where the fuzz case running last is named: build/test-heap-dumps/fuzz-case-<pid>.txt of the module (the directory
 * comes from the kuicksilver.test-jvm plugin), or nowhere when the JVM was not started by Gradle (Jazzer on its own).
 * A JVM that ends normally deletes it; one out of heap exits at once (-XX:+ExitOnOutOfMemoryError, no shutdown hooks) and
 * leaves it beside its heap dump, which the CI test jobs upload together.
 */
private val caseFile: File? by lazy {
    System.getProperty("kuicksilver.test.heapDumps")?.let { dir ->
        File(dir, "fuzz-case-${ProcessHandle.current().pid()}.txt").also { f ->
            f.parentFile.mkdirs()
            Runtime.getRuntime().addShutdownHook(Thread { f.delete() })
        }
    }
}

/**
 * Names the fuzz case about to run in [caseFile], overwriting the one before: its target and its input (a file of the
 * regression corpus, or Jazzer's empty input; one case for a whole fuzzing run). The write is done and the file closed
 * before the case runs, so a JVM that dies in the case leaves its name on disk. Nothing goes to the console.
 */
internal fun fuzzCase(case: TestInfo) {
    val file = caseFile ?: return
    val target = case.testClass.map { it.name }.orElse("?") + "." + case.testMethod.map { it.name }.orElse("?")
    try {
        file.writeText("$target ${case.displayName}\n")
    } catch (_: IOException) {
        // naming the case is a help for a crash, never a reason to fail the case
    }
}
