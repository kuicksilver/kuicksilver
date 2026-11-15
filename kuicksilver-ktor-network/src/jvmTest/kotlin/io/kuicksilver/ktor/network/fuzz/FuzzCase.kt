// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network.fuzz

import org.junit.jupiter.api.TestInfo
import java.io.File
import java.io.IOException

// This file is the same in every fuzz package but for its package line (the modules share no test source set):
// tools/check/fuzz-case-sync.sh fails when a copy drifts. Change them all together. It also holds the replay of the
// committed corpora (CommittedCorpusReplayTest), so every module with fuzz targets runs its own.

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

/**
 * Replays every committed corpus input of this module's Jazzer targets: `tools/fuzz/corpus/<target>/` (what campaigns grew
 * and `tools/fuzz/campaign.sh minimize` committed) is otherwise read only by later campaigns, so an invariant that went
 * stale or a regression on one of those inputs went unnoticed (the stateful connection fuzzer's bound on owed
 * PATH_RESPONSEs did). The targets are the `jvm` rows of campaign.sh's table for this module (the test's working directory
 * is the module's); each input runs once, as the target runs it, and every failure is listed. Inputs whose target method
 * no longer exists fail too.
 */
class CommittedCorpusReplayTest {
    @org.junit.jupiter.api.Test
    fun everyCommittedInputPasses() {
        val project = File(System.getProperty("user.dir"))
        val root = project.parentFile
        val script = File(root, "tools/fuzz/campaign.sh")
        if (!script.isFile) return // a module built outside the repository (a published source set) has no corpora
        val lines = script.readLines()
        val from = lines.indexOfFirst { it.startsWith("targets_table()") }
        val rows =
            lines
                .drop(from + 1)
                .dropWhile { !it.contains("<<'EOF'") }
                .drop(1)
                .takeWhile { it != "EOF" }
                .map { it.trim().split(Regex("\\s+")) }
                .filter { it.size == 5 && it[1] == "jvm" && it[2] == project.name }
        val failures = ArrayList<String>()
        var inputs = 0
        val started = System.nanoTime()
        for ((id, _, _, cls, method) in rows) {
            val dir = File(root, "tools/fuzz/corpus/$id")
            val files = dir.listFiles()?.filter { it.isFile }?.sortedBy { it.name } ?: continue
            val target =
                try {
                    Class.forName(cls).getMethod(method, ByteArray::class.java)
                } catch (e: ReflectiveOperationException) {
                    failures += "$id: no target $cls.$method (${e::class.simpleName})"
                    continue
                }
            val instance = target.declaringClass.getDeclaredConstructor().newInstance()
            for (f in files) {
                inputs++
                try {
                    target.invoke(instance, f.readBytes())
                } catch (e: java.lang.reflect.InvocationTargetException) {
                    val c = e.targetException
                    failures += "$id/${f.name}: ${c::class.qualifiedName}: ${c.message}"
                }
            }
        }
        val ms = (System.nanoTime() - started) / 1_000_000
        println("committed corpora of ${project.name}: $inputs inputs of ${rows.size} targets in $ms ms")
        if (failures.isNotEmpty()) {
            throw AssertionError("${failures.size} committed corpus input(s) fail:\n" + failures.take(20).joinToString("\n"))
        }
    }
}
