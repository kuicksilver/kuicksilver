// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.quic.TimeMark
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** The server's 0-RTT replay register (ADR-0015): single use within the window, bounded, fails closed. */
class ZeroRttReplayRegisterTest {
    private val t0 = TimeMark(1_000_000_000_000L)

    private fun id(n: Int) = ByteArray(32) { (n shr (8 * (it % 4))).toByte() }.also { it[31] = 0x5a }

    @Test fun secondUseWithinWindowRefused() {
        val r = ZeroRttReplayRegister(Random(1))
        assertTrue(r.admit(id(1), t0))
        assertFalse(r.admit(id(1), t0 + 5.seconds), "a replay inside the window")
        assertTrue(r.admit(id(2), t0 + 5.seconds))
    }

    @Test fun rememberedForAtLeastTheFreshnessWindow() {
        val r = ZeroRttReplayRegister(Random(2))
        assertTrue(r.admit(id(1), t0))
        assertFalse(r.admit(id(1), t0 + ZeroRttReplayRegister.HALF_SPAN), "still known one half later (more than the 10 s allowance)")
        assertTrue(r.admit(id(1), t0 + ZeroRttReplayRegister.HALF_SPAN * 3), "forgotten after two rotations")
    }

    @Test fun liveEntriesExpireInStripesNoAdmissionTouches() {
        // stripes rotate only on an admission: the probe must not count entries a quiet stripe still holds past the window
        // (the soak saw the count creep up at a low 0-RTT rate while the fixed storage stayed the same)
        val r = ZeroRttReplayRegister(Random(5))
        for (i in 0 until 500) assertTrue(r.admit(id(i + 1000), t0))
        assertEquals(500, r.liveEntries(t0 + 1.seconds))
        assertEquals(500, r.liveEntries(t0 + ZeroRttReplayRegister.HALF_SPAN), "still fresh one half later")
        assertEquals(0, r.liveEntries(t0 + ZeroRttReplayRegister.HALF_SPAN * 2), "nothing is fresh after two halves")
    }

    @Test fun releaseForgets() {
        val r = ZeroRttReplayRegister(Random(3))
        assertTrue(r.admit(id(7), t0))
        r.release(id(7))
        assertTrue(r.admit(id(7), t0), "a hello whose early data TLS refused does not block the ticket")
    }

    @Test fun negative_registerFailsClosedWhenFull() {
        val r = ZeroRttReplayRegister(Random(4))
        var admitted = 0
        for (i in 0 until ZeroRttReplayRegister.CAPACITY * 2) if (r.admit(id(i + 100), t0)) admitted++
        assertTrue(admitted <= ZeroRttReplayRegister.CAPACITY, "bounded: $admitted")
        assertTrue(admitted > ZeroRttReplayRegister.CAPACITY / 2, "most of the capacity is usable: $admitted")
        assertFalse(r.admit(id(999_999), t0), "full: early data refused, never a forgotten entry")
        assertTrue(r.admit(id(999_999), t0 + ZeroRttReplayRegister.HALF_SPAN * 3), "room again after rotation")
        assertEquals(ZeroRttReplayRegister.CAPACITY * 2 * 8L, r.memoryBytes, "two halves of 64-bit fingerprints")
    }

    @Test fun negative_wallClockStepBackDoesNotReopenReplay() {
        // OpenSSL judges freshness by the wall clock, the register forgets by the monotonic one: a wall clock stepped back after
        // the entry expired would make the captured hello look fresh again
        val r = ZeroRttReplayRegister(Random(7))
        val wall0 = 1_800_000_000_000L
        assertTrue(r.admit(id(1), t0, wall0))
        val later = t0 + ZeroRttReplayRegister.HALF_SPAN * 3 // the entry is gone
        assertFalse(r.admit(id(1), later, wall0 + 5_000), "the wall clock went back 55 s: the replay is refused")
        assertFalse(r.admit(id(1), later + 10.seconds, wall0 + 15_000), "still inside the old hello's freshness window")
        assertTrue(r.admit(id(1), later + 30.seconds, wall0 + 35_000), "once the wall clock passed that window, 0-RTT resumes")
        assertFalse(r.admit(id(1), later + 31.seconds, wall0 + 36_000), "and the register tracks the new admission")
    }

    @Test fun steadyClocksKeepAdmitting() {
        val r = ZeroRttReplayRegister(Random(8))
        val wall0 = 1_800_000_000_000L
        for (i in 0 until 200) assertTrue(r.admit(id(1000 + i), t0 + (i * 500L).milliseconds, wall0 + i * 500L + (i % 3)))
        assertTrue(r.admit(id(1), t0 + 200.seconds, wall0 + 200_000), "wall and monotonic clocks advancing together never refuse")
    }

    /**
     * After an idle stretch of two halves or more (routine for a stripe of a lightly loaded server), the next rotation must
     * still keep one half of history: a hello admitted after the idle stretch is refused right after the following rotation
     * (re-review of the 0-RTT fixes: the no-keep rotation aliased `previous` and `current`, so every later rotation cleared
     * the only table). One identity, so every step hits the same stripe.
     */
    @Test fun negative_replayAcrossRotationAfterIdleStripeRefused() {
        val r = ZeroRttReplayRegister(Random(1))
        val half = ZeroRttReplayRegister.HALF_SPAN
        assertTrue(r.admit(id(1), t0))
        // idle for more than two halves: this admission rotates without keeping history (nothing in it is fresh any more)
        assertTrue(r.admit(id(1), t0 + half * 2 + 10.seconds), "forgotten after two idle halves (outside freshness)")
        // the next rotation (one half later) must keep it: a replay 21 s after its admission is still inside the register
        assertFalse(r.admit(id(1), t0 + half * 3 + 11.seconds), "a replay right after a rotation that followed an idle stretch")
    }

    /** The register starts small and grows with its load (ADR-0026): one admission does not allocate the whole capacity. */
    @Test fun aNewRegisterStartsSmallAndGrows() {
        val r = ZeroRttReplayRegister(Random(9))
        assertTrue(r.admit(id(1), t0))
        val first = r.memoryBytes
        assertEquals(ZeroRttReplayRegister.STRIPES * ZeroRttReplayRegister.INITIAL_SLOTS * 2 * 8L, first)
        assertTrue(first < 1024 * 1024, "less than 1 MiB at first: $first")
        for (i in 2..20_000) r.admit(id(i), t0)
        assertTrue(r.memoryBytes > first, "grown with the load: ${r.memoryBytes}")
        assertTrue(r.memoryBytes <= ZeroRttReplayRegister.CAPACITY * 2 * 8L, "never past the capacity: ${r.memoryBytes}")
    }

    /** No replay gets through while a stripe grows, in either half: growing rehashes what both halves remember. */
    @Test fun negative_noReplayGetsThroughAGrowth() {
        val r = ZeroRttReplayRegister(Random(10), stripeCount = 1, slots = 1024)
        val before = (0 until 90).map { id(10_000 + it) }
        for (x in before) assertTrue(r.admit(x, t0))
        // one half later the first batch sits in the previous half; the next admissions grow the stripe past 128, 256, 512
        val t1 = t0 + ZeroRttReplayRegister.HALF_SPAN
        val admitted = mutableListOf<ByteArray>()
        for (n in 0 until 700) {
            val x = id(n)
            assertTrue(r.admit(x, t1), "fresh $n")
            admitted += x
            if (n % 50 == 49 || n in 90..100 || n in 186..200 || n in 380..390) {
                for (y in admitted) assertFalse(r.admit(y, t1), "a replay after $n admissions")
                for (y in before) assertFalse(r.admit(y, t1), "a replay of the previous half after $n admissions")
            }
        }
        assertEquals(1024L * 2 * 8, r.memoryBytes, "grown to its largest size")
        assertFalse(r.admit(id(5), t1 + 5.seconds), "still refused once grown")
    }

    /** A NEW_TOKEN register of the default capacity (1 Mi tokens, 32 MiB at most) takes far less after its first token. */
    @Test fun firstNewTokenAllocatesLessThanOneMebibyte() {
        io.kuicksilver.native.KslLoader
            .ensureLoaded()
        val tokens = AddressTokens(io.kuicksilver.tls.KslQuicCrypto, Random(11))
        try {
            assertTrue(tokens.admitNewToken(42, t0))
            assertTrue(tokens.replayMemoryBytesForTest in 1 until 1024 * 1024, "${tokens.replayMemoryBytesForTest}")
            assertFalse(tokens.admitNewToken(42, t0), "and never twice")
        } finally {
            tokens.close()
        }
    }
}
