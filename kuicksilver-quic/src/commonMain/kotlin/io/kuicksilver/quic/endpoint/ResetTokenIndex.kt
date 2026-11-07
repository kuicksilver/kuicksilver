// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.quic.endpoint

import io.kuicksilver.native.PacketBuffer
import kotlin.concurrent.atomics.AtomicArray
import kotlin.concurrent.atomics.AtomicInt
import kotlin.random.Random

/**
 * The peers' stateless reset tokens of every connection of a loop group that shares one socket, each with the loops that hold
 * it: a Stateless Reset (RFC 9000 section 10.3) carries no connection ID of ours, only the token in its last 16 bytes, so
 * the receiver of the shared socket finds the loop by that token ([loopOf]) and the loop's connection checks it (section
 * 10.3.1: "an endpoint MUST" detect a reset for a connection it has). The loops add a token when a connection learns it
 * (the `stateless_reset_token` transport parameter, NEW_CONNECTION_ID, `preferred_address`) and remove it when the peer ID
 * leaves or the connection is removed. A token several connections hold (a peer may repeat one) keeps a count per loop,
 * and routes to a loop that still holds it.
 *
 * Copy-on-write per bucket: [BUCKETS] buckets chosen by SipHash under a random key (a peer chooses its tokens: it cannot
 * aim them at one bucket), each a short immutable array. The receiver reads one bucket with no lock, so a loop preempted in
 * the middle of a change never stalls it; a change copies its one bucket (a few entries: 400,000 tokens make about 25 a
 * bucket) and publishes the copy with a compare-and-set, retrying when another loop changed that bucket meanwhile. A fixed
 * count keeps it simple: 16,384 references per group, and no resize to coordinate. Tokens are compared in constant time once their keyed
 * hashes are equal (section 10.3.1: "without leaking information about the value of the token").
 */
internal class ResetTokenIndex(
    random: Random,
) {
    private val k0 = random.nextLong()
    private val k1 = random.nextLong()

    /** One token and its holders, `[loop, count]` pairs with counts above 0; immutable. */
    private class Entry(
        val hash: Long,
        val token: ByteArray,
        val holders: IntArray,
    )

    private val buckets = AtomicArray(Array(BUCKETS) { EMPTY })

    /**
     * Distinct tokens held, never below the published ones: raised before a new token is published, lowered after one is
     * withdrawn, so the receiver's shortcut for an empty index never skips a token it could find.
     */
    private val live = AtomicInt(0)

    /** Distinct tokens held now (tests). */
    val size: Int get() = live.load()

    fun add(
        token: ByteArray,
        loop: Int,
    ) {
        if (token.size != TOKEN || token.all { it == 0.toByte() }) return // a zero token never matches (StatelessReset.matches)
        change(SipHash.hash24(k0, k1, token), token) { old ->
            if (old == null) return@change intArrayOf(loop, 1)
            val i = indexOfLoop(old.holders, loop)
            if (i >= 0) old.holders.copyOf().also { it[i + 1]++ } else old.holders + intArrayOf(loop, 1)
        }
    }

    fun remove(
        token: ByteArray,
        loop: Int,
    ) {
        if (token.size != TOKEN) return
        val h = SipHash.hash24(k0, k1, token)
        change(h, token) { old ->
            if (old == null) return@change null
            val i = indexOfLoop(old.holders, loop)
            when {
                i < 0 -> old.holders
                old.holders[i + 1] > 1 -> old.holders.copyOf().also { it[i + 1]-- }
                old.holders.size == 2 -> null
                else -> old.holders.copyOfRange(0, i) + old.holders.copyOfRange(i + 2, old.holders.size)
            }
        }
    }

    /** The loop holding the token in the last 16 bytes of `buf[0, end)`, or -1 (none, or the datagram is too short). */
    fun loopOf(
        buf: PacketBuffer,
        end: Int,
    ): Int {
        if (end < StatelessReset.MIN_SIZE || live.load() == 0) return -1
        val off = end - TOKEN
        val h = SipHash.hash24(k0, k1, buf, off, TOKEN)
        val b = buckets.loadAt(bucketOf(h))
        for (e in b) if (e.hash == h && ConstantTime.equals(buf, off, e.token, 0, TOKEN)) return e.holders[0]
        return -1
    }

    /**
     * Replaces the holders of the token with hash [h] (and bytes [token], our own copy when it is new) by what [update] makes
     * of them (null: the token goes), as one compare-and-set of its bucket.
     */
    private inline fun change(
        h: Long,
        token: ByteArray,
        update: (Entry?) -> IntArray?,
    ) {
        val at = bucketOf(h)
        while (true) {
            val b = buckets.loadAt(at)
            var k = -1
            for (i in b.indices) if (b[i].hash == h && ConstantTime.equals(b[i].token, token)) k = i
            val old = if (k >= 0) b[k] else null
            val holders = update(old)
            if (holders === old?.holders) return
            val next: Array<Entry> =
                when {
                    holders == null -> Array(b.size - 1) { b[if (it < k) it else it + 1] }

                    // withdrawn
                    old == null -> Array(b.size + 1) { if (it < b.size) b[it] else Entry(h, token.copyOf(), holders) }

                    else -> b.copyOf().also { it[k] = Entry(h, old.token, holders) }
                }
            val adding = old == null
            if (adding) live.addAndFetch(1) // before it can be found
            if (buckets.compareAndSetAt(at, b, next)) {
                if (holders == null) live.addAndFetch(-1) // after it can no longer be found
                return
            }
            if (adding) live.addAndFetch(-1)
        }
    }

    private fun indexOfLoop(
        holders: IntArray,
        loop: Int,
    ): Int {
        var i = 0
        while (i < holders.size) {
            if (holders[i] == loop) return i
            i += 2
        }
        return -1
    }

    private fun bucketOf(h: Long): Int = (h xor (h ushr 32)).toInt() and (BUCKETS - 1)

    private companion object {
        const val TOKEN = 16
        const val BUCKETS = 16_384
        val EMPTY = emptyArray<Entry>()
    }
}
