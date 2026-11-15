// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import io.kuicksilver.native.KslLoader
import java.io.File
import kotlin.test.Test

/**
 * The reach table of the connection fuzzer: every seed and committed corpus input of `connectionNull` and `connectionTls`
 * runs once and [QuicReach] counts the inputs that reached each feature. Opt-in (`KUICKSILVER_FUZZ_REACH=1`): it prints the
 * table and asserts nothing; `ConnectionSeededTest` is the check that runs in every build.
 */
class ConnectionReachReport {
    /** `KUICKSILVER_FUZZ_HEX=<program in hex>` (and `KUICKSILVER_FUZZ_TLS=1` for real TLS): runs that one program, for debugging. */
    @Test fun runOne() {
        val hex = System.getenv("KUICKSILVER_FUZZ_HEX") ?: return
        KslLoader.ensureLoaded()
        val program = ByteArray(hex.length / 2) { hex.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
        try {
            if (System.getenv("KUICKSILVER_FUZZ_TLS") ==
                "1"
            ) {
                ConnectionFuzzTest().connectionTls(program)
            } else {
                ConnectionFuzzTest().connectionNull(program)
            }
            println("PASS")
        } catch (e: Throwable) {
            println("FAIL: ${e.message}")
            e.printStackTrace(System.out)
        }
    }

    @Test fun printReach() {
        if (System.getenv("KUICKSILVER_FUZZ_REACH") != "1") return
        KslLoader.ensureLoaded()
        val module = File(System.getProperty("user.dir"))
        val target = ConnectionFuzzTest()
        val rows = LinkedHashMap<String, Map<String, Long>>()
        val sizes = LinkedHashMap<String, Long>()
        for (method in listOf("connectionNull", "connectionTls")) {
            val seeds = File(module, "src/jvmTest/resources/io/kuicksilver/quic/fuzz/ConnectionFuzzTestInputs/$method")
            val corpus = File(module.parentFile, "tools/fuzz/corpus/quic.$method")
            val only = System.getenv("KUICKSILVER_FUZZ_ONLY")?.split(",")
            val files =
                listOf(seeds, corpus)
                    .flatMap { d ->
                        d.listFiles()?.filter { it.isFile }?.sortedBy { it.name } ?: emptyList()
                    }.filter { f ->
                        only == null || only.any { f.name.startsWith(it) }
                    }
            QuicReach.reset()
            val started = System.nanoTime()
            var failed = 0
            val examples = LinkedHashMap<String, MutableList<String>>()
            for (f in files) {
                val before = QuicReach.snapshot()
                try {
                    if (method == "connectionNull") target.connectionNull(f.readBytes()) else target.connectionTls(f.readBytes())
                } catch (e: Throwable) {
                    if (failed++ < 30) println("FAIL ${f.name}: ${e::class.simpleName}: ${e.message}")
                    if (only != null) e.printStackTrace(System.out)
                }
                for ((k, v) in QuicReach.snapshot()) {
                    if (v > (before[k] ?: 0L)) examples.getOrPut(k) { ArrayList() }.let { if (it.size < 2) it += f.name }
                }
            }
            for (k in listOf(
                "migration.fallback",
                "migration.reverted",
                "migration.noViablePath",
            )) {
                println("examples $method $k: ${examples[k]}")
            }
            val ms = (System.nanoTime() - started) / 1_000_000
            println("reach $method: ${files.size} inputs, $failed failing, $ms ms")
            rows[method] = QuicReach.snapshot()
            sizes[method] = files.size.toLong()
        }
        println("| feature | " + rows.keys.joinToString(" | ") { "$it (${sizes[it]})" } + " |")
        println("|---|" + rows.keys.joinToString("|") { "---:" } + "|")
        for (f in QuicReach.FEATURES) println("| $f | " + rows.values.joinToString(" | ") { (it[f] ?: 0L).toString() } + " |")
    }
}
