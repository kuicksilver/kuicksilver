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
}
