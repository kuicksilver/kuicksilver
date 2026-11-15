// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.fuzz

import io.kuicksilver.native.KslLoader
import java.io.File
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The `h3Connection` fuzz target ([H3Run]) on fixed random programs in the normal test run: the invariants hold on each,
 * and together they reach the features the target is for (blocked QPACK streams, GOAWAY from both sides, requests the
 * GOAWAY refused, resets, trailers). With KUICKSILVER_FUZZ_SEEDS_OUT set it also writes the programs as the target's
 * seed corpus (`tools/fuzz/gen-seeds.sh`).
 */
class H3ConnectionSeededTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun seededProgramsHoldTheInvariantsAndReachTheFeatures() {
        val reach = H3Reach()
        val out =
            System.getenv("KUICKSILVER_FUZZ_SEEDS_OUT")?.let {
                File(it, "H3ConnectionFuzzTestInputs/h3Connection").also { d ->
                    d.mkdirs()
                }
            }
        for (seed in 0 until SEEDS) {
            val program = program(seed)
            try {
                H3Run(program, reach).run()
            } catch (e: H3Finding) {
                File("build/h3-connection-finding-seed-$seed.txt").writeText(e.trace.joinToString("\n"))
                fail("seed $seed: ${e.message}\n" + e.trace.takeLast(45).joinToString("\n"), e)
            }
            if (seed < CORPUS) {
                val name = "seed-${seed.toString().padStart(3, '0')}"
                if (out != null) {
                    File(out, name).writeBytes(program)
                } else {
                    // the committed seed corpus is this generator's output (tools/fuzz/gen-seeds.sh regenerates it)
                    val committed = javaClass.getResourceAsStream("H3ConnectionFuzzTestInputs/h3Connection/$name")?.use { it.readBytes() }
                    assertTrue(
                        committed != null && committed.contentEquals(program),
                        "$name differs from its generator: run tools/fuzz/gen-seeds.sh",
                    )
                }
            }
        }
        val table = reach.hits.entries.joinToString("\n") { (k, v) -> "  $k: $v" }
        println("h3Connection reach over $SEEDS seeded programs:\n$table")
        for (feature in REQUIRED) {
            assertTrue(reach.hits.keys.any { it.startsWith(feature) }, "no seeded program reached '$feature':\n$table")
        }
    }

    companion object {
        const val SEEDS = 120

        /** The first programs are the target's committed seed corpus. */
        const val CORPUS = 40

        val REQUIRED =
            listOf(
                "qpack: blocked stream seen",
                "qpack: dynamic table inserts",
                "goaway: server",
                "goaway: client",
                "client: RequestNotProcessed",
                "client: request cancelled",
                "server: request reset",
                "transport: piece delivered out of order",
                "client: response 200 with trailers",
                "connection: closed with H3_NO_ERROR",
            )

        /** A program biased toward progress: many deliveries, some requests, a GOAWAY now and then. */
        fun program(seed: Int): ByteArray {
            val r = Random(seed)
            val b = ByteArray(200 + r.nextInt(600)) { r.nextInt(256).toByte() }
            // settings: the dynamic table on both sides in most programs
            b[0] = (2 + 3 * 2 + 9 * r.nextInt(2)).toByte()
            b[2] = (2 + 3 * r.nextInt(3)).toByte()
            return b
        }
    }
}
