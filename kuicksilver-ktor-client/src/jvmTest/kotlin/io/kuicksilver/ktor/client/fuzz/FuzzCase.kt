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
 * The operations a fuzz program decodes from its input, as the program states them: a target whose input is a program
 * (operations read one after another, as `ConnProgram` is) calls [fuzzOp] once per decoded operation with what that
 * operation does (its kind by name, its side, the values it was given, where it starts and where the next one starts).
 * While [record] runs a target on this thread, those texts are hashed into the input's fingerprint; otherwise [fuzzOp]
 * costs one thread-local read. CommittedCorpusReplayTest records the fingerprint of every committed input and compares
 * it with tools/fuzz/formats/<target>.lock, so a change to a program's decoder that makes a committed input do something
 * else fails until the inputs are rewritten (to keep their meaning, which leaves their fingerprints as they were) or
 * recorded again with a reason (tools/fuzz/formats/changes.txt, which tools/check/fuzz-formats.py asks for).
 */
internal object FuzzTrace {
    private class Run(
        val digest: java.security.MessageDigest,
        val text: StringBuilder?,
    ) {
        var ops = 0
    }

    private val run = ThreadLocal<Run?>()

    val on: Boolean get() = run.get() != null

    fun add(text: String) {
        val r = run.get() ?: return
        val b = text.toByteArray(Charsets.UTF_8)
        r.digest.update(b)
        r.digest.update(10)
        r.text?.append(text)?.append('\n')
        r.ops++
    }

    /** One run of [block] recorded: the fingerprint (null when no operation was decoded), the trace when [keepText], and what it threw. */
    fun record(
        keepText: Boolean,
        block: () -> Unit,
    ): Triple<String?, String?, Throwable?> {
        val r = Run(java.security.MessageDigest.getInstance("SHA-256"), if (keepText) StringBuilder() else null)
        run.set(r)
        val thrown =
            try {
                block()
                null
            } catch (t: Throwable) {
                t
            } finally {
                run.set(null)
            }
        val fp =
            if (r.ops == 0) {
                null
            } else {
                r.digest
                    .digest()
                    .joinToString("") { "%02x".format(it) }
                    .take(16)
            }
        return Triple(fp, r.text?.toString(), thrown)
    }
}

/** Adds one decoded operation to the trace of the program running on this thread ([FuzzTrace]); [text] is built only then. */
internal inline fun fuzzOp(text: () -> String) {
    if (FuzzTrace.on) FuzzTrace.add(text())
}

private fun sha16(b: ByteArray): String =
    java.security.MessageDigest
        .getInstance("SHA-256")
        .digest(b)
        .joinToString("") { "%02x".format(it) }
        .take(16)

/**
 * Replays every committed input of this module's Jazzer targets: `tools/fuzz/corpus/<target>/` (what campaigns grew and
 * `tools/fuzz/campaign.sh minimize` committed) and the regression inputs `<Class>Inputs/<method>/` of the test resources.
 * The corpus is otherwise read only by later campaigns, so an invariant that went stale or a regression on one of those
 * inputs went unnoticed. The targets are the `jvm` rows of campaign.sh's table for this module; every row's target method
 * must resolve, whether or not it has a corpus; each input runs once, as the target runs it, and every failure is listed.
 * Nothing passes silently: the script must be found, the module must have rows, and a target without a committed corpus
 * must be listed in `tools/fuzz/no-corpus.txt` (and one listed there must have none).
 *
 * Each run is recorded with [FuzzTrace]: a target whose program traces its operations has a lock,
 * `tools/fuzz/formats/<target>.lock`, with one line per committed input (`<path>`, the SHA-256 of its bytes and of its
 * trace, 16 hex digits each), and every input must decode as recorded there: an input that is new, changed or gone, or
 * that decodes to other operations, is a failure; so is a traced target without a lock and a target with a lock whose
 * program traced nothing (its trace calls were removed). `KUICKSILVER_FUZZ_FORMATS=record` writes the locks instead of
 * comparing (tools/check/fuzz-formats.py then wants a reason for every recorded input whose decoding changed);
 * `KUICKSILVER_FUZZ_FORMATS=dump:<dir>` also writes each input's trace to `<dir>/<target>/<file>.txt`, to see what changed.
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
        val mode = System.getenv("KUICKSILVER_FUZZ_FORMATS").orEmpty()
        val dump = if (mode.startsWith("dump:")) File(mode.removePrefix("dump:")) else null
        val failures = ArrayList<String>()
        var inputs = 0
        var traced = 0
        val started = System.nanoTime()
        for ((id, _, _, cls, method) in rows) {
            val target =
                try {
                    Class.forName(cls).getMethod(method, ByteArray::class.java)
                } catch (e: ReflectiveOperationException) {
                    failures += "$id: no target $cls.$method (${e::class.simpleName})"
                    continue
                }
            val corpus =
                File(root, "tools/fuzz/corpus/$id")
                    .listFiles()
                    ?.filter { it.isFile }
                    ?.sortedBy { it.name }
                    .orEmpty()
            if (corpus.isEmpty()) {
                if (id in noCorpus) {
                    println("$id: no committed corpus yet (tools/fuzz/no-corpus.txt)")
                } else {
                    failures += "$id: no committed corpus and not in tools/fuzz/no-corpus.txt"
                }
            } else if (id in noCorpus) {
                failures += "$id: has a committed corpus but is listed in tools/fuzz/no-corpus.txt"
            }
            val regression =
                File(root, "$module/src/jvmTest/resources/${cls.replace('.', '/')}Inputs/$method")
                    .listFiles()
                    ?.filter { it.isFile }
                    ?.sortedBy { it.name }
                    .orEmpty()
            val instance = target.declaringClass.getDeclaredConstructor().newInstance()
            val seen = LinkedHashMap<String, Pair<String, String?>>() // path -> (bytes, trace)
            for (f in corpus + regression) {
                inputs++
                val bytes = f.readBytes()
                val path = f.absoluteFile.relativeTo(root).invariantSeparatorsPath
                val (fp, text, thrown) = FuzzTrace.record(dump != null) { target.invoke(instance, bytes) }
                if (thrown != null) {
                    val c = (thrown as? java.lang.reflect.InvocationTargetException)?.targetException ?: thrown
                    failures += "$path: ${c::class.qualifiedName}: ${c.message}"
                }
                seen[path] = sha16(bytes) to fp
                if (dump != null && text != null) File(dump, "$id/${f.name}.txt").apply { parentFile.mkdirs() }.writeText(text)
            }
            failures += formats(root, id, seen, mode == "record")
            if (seen.values.any { it.second != null }) traced++
        }
        val ms = (System.nanoTime() - started) / 1_000_000
        println("committed inputs of $module: $inputs inputs of ${rows.size} targets ($traced traced) in $ms ms")
        if (failures.isNotEmpty()) {
            throw AssertionError("${failures.size} committed input problem(s):\n" + failures.take(30).joinToString("\n"))
        }
    }

    /** Compares (or, [record]ing, writes) target [id]'s lock with what its committed inputs decoded to now. */
    private fun formats(
        root: File,
        id: String,
        seen: Map<String, Pair<String, String?>>,
        record: Boolean,
    ): List<String> {
        val lock = File(root, "tools/fuzz/formats/$id.lock")
        val traced = seen.values.any { it.second != null }
        if (record) {
            if (!traced) {
                lock.delete()
                return emptyList()
            }
            lock.parentFile.mkdirs()
            lock.writeText(
                "# $id: <input> <SHA-256 of its bytes> <SHA-256 of the operations its program decodes> (16 hex digits each);\n" +
                    "# written by CommittedCorpusReplayTest with KUICKSILVER_FUZZ_FORMATS=record (docs/process.md)\n" +
                    seen.entries.sortedBy { it.key }.joinToString("") { (p, v) -> "$p\t${v.first}\t${v.second ?: "-"}\n" },
            )
            return emptyList()
        }
        if (!lock.isFile) {
            return if (traced) {
                listOf(
                    "$id: its program traces its operations but tools/fuzz/formats/$id.lock is missing: record it",
                )
            } else {
                emptyList()
            }
        }
        if (!traced && seen.isNotEmpty()) return listOf("$id: tools/fuzz/formats/$id.lock exists but its program traced no operation")
        val out = ArrayList<String>()
        val recorded = LinkedHashMap<String, Pair<String, String>>()
        for (line in lock.readLines()) {
            if (line.isBlank() || line.startsWith("#")) continue
            val f = line.split('\t')
            if (f.size != 3) {
                out += "tools/fuzz/formats/$id.lock: malformed line `$line`"
                continue
            }
            recorded[f[0]] = f[1] to f[2]
        }
        for ((path, now) in seen) {
            val was = recorded[path]
            when {
                was == null -> {
                    out += "$path: not recorded in tools/fuzz/formats/$id.lock (a new input): record it"
                }

                was.first != now.first -> {
                    out +=
                        "$path: its bytes changed since tools/fuzz/formats/$id.lock recorded it: record it with a reason"
                }

                was.second != (now.second ?: "-") -> {
                    val got = now.second ?: "none"
                    out += "$path: decodes to other operations than tools/fuzz/formats/$id.lock recorded (${was.second}, now $got): " +
                        "the decoder changed what a committed input does; rewrite the inputs to keep their meaning, " +
                        "or record them with a reason"
                }
            }
        }
        for (path in recorded.keys - seen.keys) out += "$path: recorded in tools/fuzz/formats/$id.lock but gone: record it"
        return out
    }
}
