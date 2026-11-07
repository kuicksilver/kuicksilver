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
 * Copy-on-write in [STRIPES] stripes chosen by SipHash under a random key (a peer chooses its tokens: it cannot aim them at
 * one stripe or bucket): the receiver reads an immutable snapshot of one stripe with no lock, so a loop preempted in the
 * middle of a change never stalls it; a change builds a new snapshot of its stripe and publishes it with a compare-and-set,
 * retrying when another loop changed that stripe meanwhile. A change copies one stripe (about a 64th of the tokens), and
 * changes are rare next to the datagrams the receiver looks up. Tokens are compared in constant time once their keyed
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

    /** An open-addressed table of one stripe; immutable once published. */
    private class Stripe(
        val entries: Array<Entry?>,
        val live: Int,
    )

    private val stripes = AtomicArray(Array(STRIPES) { EMPTY })
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
        val s = stripes.loadAt(stripeOf(h))
        val e = find(s, h) { ConstantTime.equals(buf, off, it.token, 0, TOKEN) } ?: return -1
        return e.holders[0]
    }

    private inline fun find(
        s: Stripe,
        h: Long,
        eq: (Entry) -> Boolean,
    ): Entry? {
        val a = s.entries
        if (a.isEmpty()) return null
        val mask = a.size - 1
        var i = slotOf(h, mask)
        while (true) {
            val e = a[i] ?: return null
            if (e.hash == h && eq(e)) return e
            i = (i + 1) and mask
        }
    }

    /**
     * Replaces the holders of the token with hash [h] (and bytes [token], our own copy when it is new) by what [update] makes
     * of them (null: the token goes), as one compare-and-set of its stripe.
     */
    private inline fun change(
        h: Long,
        token: ByteArray,
        update: (Entry?) -> IntArray?,
    ) {
        val at = stripeOf(h)
        while (true) {
            val s = stripes.loadAt(at)
            val old = find(s, h) { ConstantTime.equals(it.token, token) }
            val holders = update(old)
            if (holders === old?.holders) return
            val next = rebuild(s, old, if (holders == null) null else Entry(h, old?.token ?: token.copyOf(), holders))
            if (stripes.compareAndSetAt(at, s, next)) {
                if (old == null && holders != null) live.addAndFetch(1)
                if (old != null && holders == null) live.addAndFetch(-1)
                return
            }
        }
    }

    /** [s] without [drop] and with [put], in a table at least twice its tokens (never below [MIN_SLOTS]). */
    private fun rebuild(
        s: Stripe,
        drop: Entry?,
        put: Entry?,
    ): Stripe {
        val n = s.live - (if (drop != null) 1 else 0) + (if (put != null) 1 else 0)
        if (n == 0) return EMPTY
        var cap = MIN_SLOTS
        while (cap < n * 2) cap *= 2
        val a = arrayOfNulls<Entry>(cap)
        val mask = cap - 1

        fun place(e: Entry) {
            var i = slotOf(e.hash, mask)
            while (a[i] != null) i = (i + 1) and mask
            a[i] = e
        }
        for (e in s.entries) if (e != null && e !== drop) place(e)
        if (put != null) place(put)
        return Stripe(a, n)
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

    private fun stripeOf(h: Long): Int = (h ushr 58).toInt() and (STRIPES - 1)

    private fun slotOf(
        h: Long,
        mask: Int,
    ): Int = (h xor (h ushr 29)).toInt() and mask

    private companion object {
        const val TOKEN = 16
        const val STRIPES = 64
        const val MIN_SLOTS = 8
        val EMPTY = Stripe(emptyArray(), 0)
    }
}
