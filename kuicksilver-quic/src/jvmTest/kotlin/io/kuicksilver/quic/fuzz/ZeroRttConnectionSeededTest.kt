// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import io.kuicksilver.quic.fuzz.ZeroRttConnectionFuzz.Expect
import io.kuicksilver.quic.fuzz.ZeroRttProgram.ACCEPT
import io.kuicksilver.quic.fuzz.ZeroRttProgram.LOST
import io.kuicksilver.quic.fuzz.ZeroRttProgram.NO_RESET_AT
import io.kuicksilver.quic.fuzz.ZeroRttProgram.NO_SERVER_EARLY_DATA
import io.kuicksilver.quic.fuzz.ZeroRttProgram.REJECT_ALPN
import io.kuicksilver.quic.fuzz.ZeroRttProgram.REJECT_APPLICATION
import io.kuicksilver.quic.fuzz.ZeroRttProgram.REJECT_LIMITS
import io.kuicksilver.quic.fuzz.ZeroRttProgram.REJECT_REQUIRED
import io.kuicksilver.quic.fuzz.ZeroRttProgram.RETRY
import io.kuicksilver.quic.fuzz.ZeroRttProgram.SMALL
import io.kuicksilver.quic.fuzz.ZeroRttProgram.VERSION_NEGOTIATION
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * The 0-RTT connection fuzzer ([ZeroRttConnectionFuzz]) on a fixed set of seeded programs, in the normal test run: every
 * outcome (accepted, rejected and going on, rejected and closing, no answer) with and without a Retry or a Version
 * Negotiation before it, small and default remembered limits, clean networks (where the outcome must be the configured
 * one) and faulty ones. `KUICKSILVER_ZRTT_SEEDS` runs that many seeds per case instead of the default (a longer hunt;
 * the open-ended search is the Jazzer target `ZeroRttFuzzTest.zeroRttConnection`).
 */
class ZeroRttConnectionSeededTest {
    private val seeds = System.getenv("KUICKSILVER_ZRTT_SEEDS")?.toIntOrNull() ?: 1

    private fun expected(
        outcome: Int,
        flags: Int,
    ): Expect? =
        when (outcome) {
            LOST -> null

            REJECT_REQUIRED, REJECT_ALPN -> Expect.RejectedCloses

            // the handshake that a Version Negotiation restarts has no ticket: 0-RTT is rejected
            ACCEPT -> if (flags and VERSION_NEGOTIATION != 0) Expect.RejectedGoesOn else Expect.Accepted

            else -> Expect.RejectedGoesOn
        }

    private fun run(
        seed: Long,
        outcome: Int,
        flags: Int,
        faults: Boolean,
    ) {
        val program = ZeroRttProgram.random(Random(seed), outcome, flags, network = faults)
        try {
            ZeroRttConnectionFuzz(program, if (faults) null else expected(outcome, flags)).run()
        } catch (e: Throwable) {
            throw AssertionError(
                "seed $seed, outcome $outcome, flags $flags, faults $faults, program ${program.joinToString(
                    "",
                ) { "%02x".format(it) }}: ${e.message}",
                e,
            )
        }
    }

    @Test fun everyOutcomeBeforeAndAfterRetryAndVersionNegotiation() {
        val before = ZeroRttCoverage.snapshot()
        val variants = listOf(0, RETRY, VERSION_NEGOTIATION, SMALL, SMALL or RETRY, NO_RESET_AT)
        for (outcome in 0 until ZeroRttProgram.OUTCOMES) {
            for (flags in variants) {
                for (s in 0 until seeds) {
                    val seed = 1000L * outcome + 10L * flags + s
                    run(seed, outcome, flags, faults = false)
                    run(seed + 500_000, outcome, flags, faults = true)
                }
            }
        }
        val after = ZeroRttCoverage.snapshot()
        println("0-RTT fuzzer coverage: $after")
        val missing =
            REACHED.filter { (after[it] ?: 0L) <= (before[it] ?: 0L) }
        assertTrue(missing.isEmpty(), "the seeded programs never reached $missing; reached: $after")
    }

    private companion object {
        /** What the seed set must reach: each outcome, the restarts with 0-RTT in flight, every call before the answer. */
        val REACHED =
            listOf(
                "accepted",
                "rejected.goesOn",
                "rejected.closes",
                "rejected.outcome$REJECT_APPLICATION",
                "rejected.outcome$REJECT_LIMITS",
                "rejected.outcome$REJECT_REQUIRED",
                "rejected.outcome$REJECT_ALPN",
                "rejected.outcome$NO_SERVER_EARLY_DATA",
                "lostBeforeAnswer",
                "retry.after0rtt",
                "retry.answered",
                "retry.earlyDataArrived",
                "vn.after0rtt",
                "vn.rejected",
                "early.open",
                "early.write",
                "early.finish",
                "early.reset",
                "early.resetAt",
                "early.stopSending",
                "early.read",
                "early.close",
                // queued before the answer: they go in 1-RTT (a client MAY send DATAGRAM in 0-RTT, RFC 9221 section 3; this one does not)
                "early.datagram",
            )
    }
}
