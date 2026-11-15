// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.fuzz

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

/**
 * The rows of campaign.sh's `targets_table` in [lines]: each must have exactly the five fields `id kind module class method` (a row
 * with another count, as a sixth column once made, would otherwise be skipped with all its inputs), and every id must be unique.
 * Each malformed row is added to [failures]; only well-formed rows are returned.
 */
internal fun campaignTable(
    lines: List<String>,
    failures: MutableList<String>,
): List<List<String>> {
    val from = lines.indexOfFirst { it.startsWith("targets_table()") }
    if (from < 0) {
        failures += "campaign.sh has no targets_table()"
        return emptyList()
    }
    val body =
        lines
            .drop(from + 1)
            .dropWhile { !it.contains("<<'EOF'") }
            .drop(1)
            .takeWhile { it != "EOF" }
    val rows = ArrayList<List<String>>()
    val ids = HashSet<String>()
    for (line in body) {
        if (line.isBlank()) {
            failures += "campaign.sh's target table has a blank line"
            continue
        }
        val f = line.trim().split(Regex("\\s+"))
        if (f.size != 5) {
            failures += "campaign.sh's target row has ${f.size} fields, not 5 (id kind module class method): $line"
            continue
        }
        if (!ids.add(f[0])) failures += "campaign.sh lists target ${f[0]} twice"
        rows += f
    }
    if (rows.isEmpty()) failures += "campaign.sh's target table is empty"
    return rows
}

/** The ids of `tools/fuzz/no-corpus.txt` in [lines]; each must be a target of [table] (a stale or misspelled entry is in [failures]). */
internal fun noCorpusList(
    lines: List<String>,
    table: List<List<String>>,
    failures: MutableList<String>,
): Set<String> {
    val known = table.map { it[0] }.toSet()
    val ids = lines.map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
    for (id in ids) if (id !in known) failures += "tools/fuzz/no-corpus.txt lists $id, which is not a target of campaign.sh"
    return ids.toSet()
}

/** Negative controls of [campaignTable] and [noCorpusList]: the shapes of table and list that must not pass. */
class CampaignTableTest {
    private val good = "quic.a jvm kuicksilver-quic io.x.A a"

    private fun table(vararg rows: String) = listOf("targets_table() {", "  cat <<'EOF'") + rows.toList() + listOf("EOF", "}")

    @org.junit.jupiter.api.Test
    fun aWellFormedTablePasses() {
        val failures = ArrayList<String>()
        val rows = campaignTable(table(good, "ksl.p c kuicksilver-native ksl_fuzz parsers"), failures)
        org.junit.jupiter.api.Assertions
            .assertEquals(2, rows.size)
        org.junit.jupiter.api.Assertions
            .assertEquals(emptyList<String>(), failures)
        noCorpusList(listOf("# comment", "", "quic.a"), rows, failures)
        org.junit.jupiter.api.Assertions
            .assertEquals(emptyList<String>(), failures)
    }

    @org.junit.jupiter.api.Test
    fun negative_aRowWithSixFieldsFails() {
        val failures = ArrayList<String>()
        val rows = campaignTable(table(good, "quic.b jvm kuicksilver-quic io.x.B b extra"), failures)
        org.junit.jupiter.api.Assertions
            .assertEquals(1, rows.size)
        org.junit.jupiter.api.Assertions
            .assertTrue(failures.single().contains("6 fields"), failures.toString())
    }

    @org.junit.jupiter.api.Test
    fun negative_aRowWithFourFieldsOrABlankLineOrATwinFails() {
        val failures = ArrayList<String>()
        campaignTable(table(good, "quic.c jvm kuicksilver-quic io.x.C", "", good), failures)
        org.junit.jupiter.api.Assertions
            .assertEquals(3, failures.size, failures.toString())
    }

    @org.junit.jupiter.api.Test
    fun negative_aNoCorpusEntryThatIsNoTargetFails() {
        val failures = ArrayList<String>()
        noCorpusList(listOf("quic.a", "quic.renamed"), campaignTable(table(good), failures), failures)
        org.junit.jupiter.api.Assertions
            .assertTrue(failures.single().contains("quic.renamed"), failures.toString())
    }
}

class CommittedCorpusReplayTest {
    @org.junit.jupiter.api.Test
    fun everyCommittedInputPasses() {
        val start = File(System.getProperty("user.dir")).absoluteFile
        val root =
            generateSequence(start) { it.parentFile }.firstOrNull { File(it, "tools/fuzz/campaign.sh").isFile }
                ?: throw AssertionError("tools/fuzz/campaign.sh not found above $start")
        val module = generateSequence(start) { it.parentFile }.first { it.parentFile == root }.name
        val failures = ArrayList<String>()
        val table = campaignTable(File(root, "tools/fuzz/campaign.sh").readLines(), failures)
        val rows = table.filter { it[1] == "jvm" && it[2] == module }
        if (rows.isEmpty()) throw AssertionError("no jvm target of $module in campaign.sh's table, but $module has fuzz targets")
        val noCorpus = noCorpusList(File(root, "tools/fuzz/no-corpus.txt").readLines(), table, failures)
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
