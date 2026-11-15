// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.ksl
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * The connection fuzzer ([ConnectionFuzz]) on a fixed set of programs in the normal test run: every program of
 * [ConnectionPathSeeds] over NullCryptoProvider and over real TLS, and seeded random programs over every dimension. Together they
 * must reach each feature of [QuicReach.FEATURES] (PMTUD probes, black holes and Packet Too Big; ECN validated, failed and CE;
 * Retry, Version Negotiation, compatible upgrade and a refused downgrade; Stateless Resets sent, recognised and ignored; the
 * preferred address and client migration), so a harness change that cuts one of them off fails here instead of silently
 * fuzzing less. `KUICKSILVER_CONN_SEEDS` runs that many random programs instead of the default (a longer hunt).
 */
class ConnectionSeededTest {
    private val seeds = System.getenv("KUICKSILVER_CONN_SEEDS")?.toIntOrNull() ?: 60

    private fun run(
        name: String,
        program: ByteArray,
        tls: Boolean,
    ) {
        try {
            ConnectionFuzz(program, if (tls) ksl else NullCryptoProvider).run()
        } catch (e: Throwable) {
            throw AssertionError(
                "$name (${if (tls) "tls" else "null"}), program ${program.joinToString("") { "%02x".format(it) }}: ${e.message}",
                e,
            )
        }
    }

    @Test fun everyPathFeatureIsReached() {
        KslLoader.ensureLoaded()
        QuicReach.reset()
        val started = System.nanoTime()
        for ((name, program) in ConnectionPathSeeds.programs) {
            run(name, program, tls = false)
            run(name, program, tls = true)
        }
        for (s in 0 until seeds) {
            val program = ConnectionPathSeeds.random(Random(4000L + s))
            run("random-$s", program, tls = s % 4 == 0)
        }
        val reach = QuicReach.snapshot()
        println("connection fuzzer reach over ${QuicReach.runs()} runs in ${(System.nanoTime() - started) / 1_000_000} ms: $reach")
        val missing = QuicReach.FEATURES.filter { (reach[it] ?: 0L) == 0L }
        assertTrue(missing.isEmpty(), "the seeded programs never reached $missing; reached: $reach")
    }
}
