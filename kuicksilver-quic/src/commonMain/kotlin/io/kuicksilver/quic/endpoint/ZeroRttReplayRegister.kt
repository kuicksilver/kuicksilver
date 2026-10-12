// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.quic.TimeMark
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds

/**
 * The server's 0-RTT replay register (RFC 8446 section 8.2, ADR-0015): a ticket identity (`key_name ‖ iv` of our stateless
 * ticket) gets early data at most once while it could still pass OpenSSL's freshness check (±10 s). One per process in
 * production (`ProcessReplayRegister`), shared by every endpoint and loop. Fingerprints are SipHash-64 under a random key, so a client cannot aim collisions at another
 * client's tickets; a collision only costs one round trip (1-RTT instead of 0-RTT).
 *
 * Layout: [STRIPES] lock-striped buckets, each with two halves of [SLOTS] open-addressed 64-bit fingerprints; a half covers
 * [HALF_SPAN], so an entry lives between one and two spans (20–40 s). A half at 3/4 load refuses further admissions (fails
 * closed) until it rotates. Memory: [CAPACITY] × 2 × 8 bytes = 1 MiB.
 */
@OptIn(ExperimentalAtomicApi::class)
internal class ZeroRttReplayRegister(
    random: Random,
) {
    private val k0 = random.nextLong()
    private val k1 = random.nextLong()

    private class Stripe {
        val lock = AtomicInt(0)
        var current = LongArray(SLOTS)
        var previous = LongArray(SLOTS)
        var used = 0 // live entries and tombstones of [current]
        var start = TimeMark.NEVER
    }

    private val stripes = Array(STRIPES) { Stripe() }

    /** Bytes of fingerprint storage. */
    val memoryBytes: Long get() = STRIPES.toLong() * SLOTS * 2 * 8

    private fun fingerprint(id: ByteArray): Long {
        val h = SipHash.hash24(k0, k1, id)
        return if (h == EMPTY || h == TOMBSTONE) 1L else h
    }

    private inline fun <T> locked(
        s: Stripe,
        block: () -> T,
    ): T {
        while (!s.lock.compareAndSet(0, 1)) { /* a few instructions per holder: spin */ }
        try {
            return block()
        } finally {
            s.lock.store(0)
        }
    }

    private fun stripeOf(fp: Long) = stripes[((fp ushr 58).toInt()) and (STRIPES - 1)]

    private fun rotate(
        s: Stripe,
        now: TimeMark,
    ) {
        if (s.start == TimeMark.NEVER) {
            s.start = now
            return
        }
        if (now < s.start + HALF_SPAN) return
        val keepPrevious = now < s.start + HALF_SPAN * 2
        val old = s.previous
        s.previous = if (keepPrevious) s.current else old.also { it.fill(EMPTY) }
        s.current = old.also { it.fill(EMPTY) }
        s.used = 0
        s.start = now
    }

    private fun find(
        table: LongArray,
        fp: Long,
    ): Int {
        var i = (fp.toInt() and (SLOTS - 1))
        repeat(SLOTS) {
            val v = table[i]
            if (v == EMPTY) return -1
            if (v == fp) return i
            i = (i + 1) and (SLOTS - 1)
        }
        return -1
    }

    /** True when [id] was not seen within the window (and is remembered now); false for a replay or a full register. */
    fun admit(
        id: ByteArray,
        now: TimeMark,
    ): Boolean {
        val fp = fingerprint(id)
        val s = stripeOf(fp)
        return locked(s) {
            rotate(s, now)
            if (find(s.current, fp) >= 0 || find(s.previous, fp) >= 0) return@locked false
            if (s.used >= SLOTS * 3 / 4) return@locked false
            var i = (fp.toInt() and (SLOTS - 1))
            while (s.current[i] != EMPTY && s.current[i] != TOMBSTONE) i = (i + 1) and (SLOTS - 1)
            if (s.current[i] == EMPTY) s.used++
            s.current[i] = fp
            true
        }
    }

    /** Forgets [id]: TLS refused the early data it was admitted for. */
    fun release(id: ByteArray) {
        val fp = fingerprint(id)
        val s = stripeOf(fp)
        locked(s) {
            val i = find(s.current, fp)
            if (i >= 0) s.current[i] = TOMBSTONE
        }
    }

    companion object {
        const val STRIPES = 64
        const val SLOTS = 1024
        const val CAPACITY = STRIPES * SLOTS
        private const val EMPTY = 0L
        private const val TOMBSTONE = -1L

        /** One half of the window: more than OpenSSL's 10 s ticket-age allowance plus clock slack. */
        val HALF_SPAN = 20.seconds
    }
}
