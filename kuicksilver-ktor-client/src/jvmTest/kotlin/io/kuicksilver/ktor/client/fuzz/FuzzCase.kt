// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.fuzz

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
 * stale or a regression on one of those inputs went unnoticed. The targets are the `jvm` rows of campaign.sh's table for
 * this module; every row's target method must resolve, whether or not it has a corpus; each input runs once, as the target
 * runs it, and every failure is listed. Nothing passes silently: the script must be found, the module must have rows, and a
 * target without a committed corpus must be listed in `tools/fuzz/no-corpus.txt` (and one listed there must have none).
 */
class CommittedCorpusReplayTest {
    @org.junit.jupiter.api.Test
    fun everyCommittedInputPasses() {
        val start = File(System.getProperty("user.dir")).absoluteFile
        val root =
            generateSequence(start) { it.parentFile }.firstOrNull { File(it, "tools/fuzz/campaign.sh").isFile }
                ?: throw AssertionError("tools/fuzz/campaign.sh not found above $start")
        val module = generateSequence(start) { it.parentFile }.first { it.parentFile == root }.name
        val lines = File(root, "tools/fuzz/campaign.sh").readLines()
        val from = lines.indexOfFirst { it.startsWith("targets_table()") }
        val rows =
            lines
                .drop(from + 1)
                .dropWhile { !it.contains("<<'EOF'") }
                .drop(1)
                .takeWhile { it != "EOF" }
                .map { it.trim().split(Regex("\\s+")) }
                .filter { it.size == 5 && it[1] == "jvm" && it[2] == module }
        if (rows.isEmpty()) throw AssertionError("no jvm target of $module in campaign.sh's table, but $module has fuzz targets")
        val noCorpus =
            File(root, "tools/fuzz/no-corpus.txt")
                .readLines()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
                .toSet()
        val failures = ArrayList<String>()
        var inputs = 0
        val started = System.nanoTime()
        for ((id, _, _, cls, method) in rows) {
            val target =
                try {
                    Class.forName(cls).getMethod(method, ByteArray::class.java)
                } catch (e: ReflectiveOperationException) {
                    failures += "$id: no target $cls.$method (${e::class.simpleName})"
                    continue
                }
            val files =
                File(root, "tools/fuzz/corpus/$id")
                    .listFiles()
                    ?.filter { it.isFile }
                    ?.sortedBy { it.name }
                    .orEmpty()
            if (files.isEmpty()) {
                if (id in
                    noCorpus
                ) {
                    println("$id: no committed corpus yet (tools/fuzz/no-corpus.txt)")
                } else {
                    failures +=
                        "$id: no committed corpus and not in tools/fuzz/no-corpus.txt"
                }
                continue
            }
            if (id in noCorpus) failures += "$id: has a committed corpus but is listed in tools/fuzz/no-corpus.txt"
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
        println("committed corpora of $module: $inputs inputs of ${rows.size} targets in $ms ms")
        if (failures.isNotEmpty()) {
            throw AssertionError("${failures.size} committed corpus problem(s):\n" + failures.take(20).joinToString("\n"))
        }
    }
}
