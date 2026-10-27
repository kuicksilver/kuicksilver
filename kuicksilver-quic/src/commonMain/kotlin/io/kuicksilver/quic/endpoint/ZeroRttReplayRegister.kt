// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.quic.TimeMark
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * The server's 0-RTT replay register (RFC 9846 section 8.2, ADR-0015): a ticket identity (`key_name ‖ iv` of our stateless
 * ticket) gets early data at most once while it could still pass OpenSSL's freshness check (±10 s). One per process in
 * production (`ProcessReplayRegister`), shared by every endpoint and loop. Fingerprints are SipHash-64 under a random key, so a client cannot aim collisions at another
 * client's tickets; a collision only costs one round trip (1-RTT instead of 0-RTT).
 *
 * Layout: [STRIPES] lock-striped buckets, each with two halves of [SLOTS] open-addressed 64-bit fingerprints; a half covers
 * [HALF_SPAN], so an entry lives between one and two spans (20–40 s). A half at 3/4 load refuses further admissions (fails
 * closed) until it rotates; released slots do not count toward that load. Memory: [CAPACITY] × 2 × 8 bytes = 1 MiB.
 */
@OptIn(ExperimentalAtomicApi::class)
internal class ZeroRttReplayRegister(
    /** The SipHash key of the fingerprints, from a CSPRNG. */
    private val k0: Long,
    private val k1: Long,
    /** Stripes (a power of two); tests and the fuzzer shrink the layout so that fills and rotations are cheap to reach. */
    private val stripeCount: Int = STRIPES,
    /** Slots per half (a power of two). */
    private val slots: Int = SLOTS,
    /**
     * One half of the window: an entry is remembered between one and two of these. [HALF_SPAN] for 0-RTT tickets; the lifetime of a
     * NEW_TOKEN token for [AddressTokens], so a token is never forgotten while it could still be shown.
     */
    private val halfSpan: Duration = HALF_SPAN,
) {
    init {
        require(stripeCount > 0 && stripeCount and (stripeCount - 1) == 0 && stripeCount <= 64) { "stripes: a power of two up to 64" }
        require(slots >= 4 && slots and (slots - 1) == 0) { "slots: a power of two of at least 4" }
        require(halfSpan.isPositive()) { "halfSpan must be positive" }
    }

    /** A register keyed from [random] (two values, in this order). */
    constructor(
        random: Random,
        stripeCount: Int = STRIPES,
        slots: Int = SLOTS,
        halfSpan: Duration = HALF_SPAN,
    ) : this(random.nextLong(), random.nextLong(), stripeCount, slots, halfSpan)

    /** Fingerprints (live plus tombstones) a half holds before it compacts or fails closed: 3/4 of [slots]. */
    private val limit = slots * 3 / 4

    private class Stripe(
        slots: Int,
    ) {
        val lock = AtomicInt(0)
        var current = LongArray(slots)
        var previous = LongArray(slots)
        var live = 0 // fingerprints in [current]
        var tombstones = 0 // released slots of [current]
        var start = TimeMark.NEVER

        // the wall clock against the monotonic one (milliseconds): see [wallClockStepped]
        var clockSeen = false
        var offsetHigh = 0L // highest wall - monotonic seen
        var wallHigh = 0L // latest wall clock of an admission
    }

    private val stripes = Array(stripeCount) { Stripe(slots) }

    /**
     * Fingerprints in the current halves still inside the window at [now] (the resource probe; storage itself is fixed). A stripe
     * rotates only on an admission, so a quiet stripe's count is stale once two halves passed: it counts as zero.
     */
    fun liveEntries(now: TimeMark): Int =
        stripes.sumOf { s -> locked(s) { if (s.start == TimeMark.NEVER || now >= s.start + halfSpan * 2) 0 else s.live } }

    /** Bytes of fingerprint storage. */
    val memoryBytes: Long get() = stripeCount.toLong() * slots * 2 * 8

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

    private fun stripeOf(fp: Long) = stripes[((fp ushr 58).toInt()) and (stripeCount - 1)]

    private fun rotate(
        s: Stripe,
        now: TimeMark,
    ) {
        if (s.start == TimeMark.NEVER) {
            s.start = now
            return
        }
        if (now < s.start + halfSpan) return
        if (now < s.start + halfSpan * 2) {
            // one half passed: the current half becomes the previous one, the oldest is reused for the new half
            val oldest = s.previous
            s.previous = s.current
            s.current = oldest.also { it.fill(EMPTY) }
        } else {
            // idle for two halves or more: nothing in either half is fresh. Clear both and keep them distinct arrays —
            // aliasing them made every later rotation clear the only table (a replay right after a rotation got through).
            s.previous.fill(EMPTY)
            s.current.fill(EMPTY)
        }
        s.live = 0
        s.tombstones = 0
        s.start = now
    }

    private fun find(
        table: LongArray,
        fp: Long,
    ): Int {
        var i = (fp.toInt() and (slots - 1))
        repeat(slots) {
            val v = table[i]
            if (v == EMPTY) return -1
            if (v == fp) return i
            i = (i + 1) and (slots - 1)
        }
        return -1
    }

    /**
     * True while a backward wall-clock step could make a forgotten hello fresh again. OpenSSL judges a ticket's age by the
     * wall clock and accepts a hello within 10 s of the age it passed with the first time (age in [claimed - 1 s,
     * claimed + 9 s]); the register forgets by the monotonic clock after at least [halfSpan]. Without a step, a forgotten
     * hello is stale for good; after the wall clock fell back by more than [WALL_SLACK] against the monotonic one, every
     * hello this stripe admitted could still be fresh until the wall clock passes the latest of them plus [halfSpan], so
     * the stripe refuses early data until then and then takes the new offset as its baseline.
     */
    private fun wallClockStepped(
        s: Stripe,
        now: TimeMark,
        wallMillis: Long,
    ): Boolean {
        val offset = wallMillis - now.nanos / 1_000_000
        if (!s.clockSeen) {
            s.clockSeen = true
            s.offsetHigh = offset
            return false
        }
        if (offset >= s.offsetHigh - WALL_SLACK.inWholeMilliseconds) {
            if (offset > s.offsetHigh) s.offsetHigh = offset
            return false
        }
        if (wallMillis <= s.wallHigh + halfSpan.inWholeMilliseconds) return true
        s.offsetHigh = offset
        return false
    }

    /** Rebuilds [Stripe.current] without its tombstones, so released slots do not lengthen probes or count as load. */
    private fun compact(s: Stripe) {
        val old = s.current.copyOf()
        s.current.fill(EMPTY)
        for (v in old) {
            if (v == EMPTY || v == TOMBSTONE) continue
            var i = (v.toInt() and (slots - 1))
            while (s.current[i] != EMPTY) i = (i + 1) and (slots - 1)
            s.current[i] = v
        }
        s.tombstones = 0
    }

    /**
     * True when [id] was not seen within the window (and is reserved now); false for a replay, a full register or a wall
     * clock ([wallMillis], what OpenSSL's ticket age uses) stepped back (see [wallClockStepped]). The
     * reservation is what makes two concurrent hellos with one ticket get early data once; it stays only if TLS accepts the
     * early data (ticket decrypted, binder verified, fresh, same configuration), otherwise [release] frees it at once.
     */
    fun admit(
        id: ByteArray,
        now: TimeMark,
        wallMillis: Long = now.nanos / 1_000_000,
    ): Boolean {
        val fp = fingerprint(id)
        val s = stripeOf(fp)
        return locked(s) {
            if (wallClockStepped(s, now, wallMillis)) return@locked false
            rotate(s, now)
            if (find(s.current, fp) >= 0 || find(s.previous, fp) >= 0) return@locked false
            if (s.live >= limit) return@locked false
            if (s.live + s.tombstones >= limit) compact(s)
            var i = (fp.toInt() and (slots - 1))
            while (s.current[i] != EMPTY && s.current[i] != TOMBSTONE) i = (i + 1) and (slots - 1)
            if (s.current[i] == TOMBSTONE) s.tombstones--
            s.current[i] = fp
            s.live++
            if (wallMillis > s.wallHigh) s.wallHigh = wallMillis
            true
        }
    }

    /** Forgets [id]: TLS refused the early data it was reserved for (a forged or stale ticket, another configuration). */
    fun release(id: ByteArray) {
        val fp = fingerprint(id)
        val s = stripeOf(fp)
        locked(s) {
            val i = find(s.current, fp)
            if (i >= 0) {
                s.current[i] = TOMBSTONE
                s.live--
                s.tombstones++
            }
        }
    }

    /** Fingerprints held (both halves); tests. */
    internal fun liveForTest(): Int = stripes.sumOf { s -> locked(s) { s.live + s.previous.count { it != EMPTY && it != TOMBSTONE } } }

    companion object {
        const val STRIPES = 64
        const val SLOTS = 1024
        const val CAPACITY = STRIPES * SLOTS

        private const val EMPTY = 0L
        private const val TOMBSTONE = -1L

        /** One half of the window: more than OpenSSL's 10 s ticket-age allowance plus clock slack. */
        val HALF_SPAN = 20.seconds

        /**
         * A backward wall-clock step the register tolerates: a replay after an entry expired needs the wall clock back by at
         * least [HALF_SPAN] minus OpenSSL's 10 s window, so a smaller step (an NTP correction) never reopens one.
         */
        val WALL_SLACK = 5.seconds
    }
}
