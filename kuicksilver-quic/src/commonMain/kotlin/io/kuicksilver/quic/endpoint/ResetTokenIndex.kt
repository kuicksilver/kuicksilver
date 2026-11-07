// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.quic.endpoint

import io.kuicksilver.native.PacketBuffer
import kotlin.concurrent.atomics.AtomicInt
import kotlin.random.Random

/**
 * The peers' stateless reset tokens of every connection of a loop group that shares one socket, each with the loop that holds
 * it: a Stateless Reset (RFC 9000 section 10.3) carries no connection ID of ours, only the token in its last 16 bytes, so
 * the receiver of the shared socket finds the loop by that token ([loopOf]) and the loop's connection checks it (section
 * 10.3.1: "an endpoint MUST" detect a reset for a connection it has). The loops add a token when a connection learns it
 * (the `stateless_reset_token` transport parameter, NEW_CONNECTION_ID, `preferred_address`) and remove it when the peer ID
 * leaves or the connection is removed.
 *
 * An open-addressed table keyed by SipHash of the token under a random key (a peer chooses its tokens: it cannot aim them
 * at one bucket), guarded by a spin lock: the loops write rarely, the receiver reads once per datagram long enough to be
 * a reset. A token held twice (two IDs of one peer giving the same token) counts its holders.
 */
internal class ResetTokenIndex(
    random: Random,
) {
    private val k0 = random.nextLong()
    private val k1 = random.nextLong()
    private val lock = SpinLock()

    // slot state: 0 empty, -1 removed, > 0 the holders of the token in that slot
    private var tokens = ByteArray(INITIAL * TOKEN)
    private var loops = IntArray(INITIAL)
    private var state = IntArray(INITIAL)
    private var used = 0 // live and removed slots
    private val live = AtomicInt(0)

    /** Tokens held now (tests). */
    val size: Int get() = live.load()

    fun add(
        token: ByteArray,
        loop: Int,
    ) {
        if (token.size != TOKEN || token.all { it == 0.toByte() }) return // a zero token never matches (StatelessReset.matches)
        lock.locked {
            val h = SipHash.hash24(k0, k1, token)
            val at = find(h) { i -> same(i, token, 0) }
            if (at >= 0) {
                state[at]++
                loops[at] = loop
                return@locked
            }
            if ((used + 1) * 2 > state.size) rehash()
            put(h, token, loop)
            live.store(live.load() + 1)
        }
    }

    fun remove(token: ByteArray) {
        if (token.size != TOKEN) return
        lock.locked {
            val at = find(SipHash.hash24(k0, k1, token)) { i -> same(i, token, 0) }
            if (at < 0) return@locked
            if (--state[at] == 0) {
                state[at] = -1
                live.store(live.load() - 1)
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
        return lock.locked {
            val at = find(h) { i -> same(i, buf, off) }
            if (at >= 0) loops[at] else -1
        }
    }

    private inline fun find(
        h: Long,
        eq: (Int) -> Boolean,
    ): Int {
        val mask = state.size - 1
        var i = (h xor (h ushr 32)).toInt() and mask
        while (true) {
            val s = state[i]
            if (s == 0) return -1
            if (s > 0 && eq(i)) return i
            i = (i + 1) and mask
        }
    }

    private fun put(
        h: Long,
        token: ByteArray,
        loop: Int,
    ) {
        val mask = state.size - 1
        var i = (h xor (h ushr 32)).toInt() and mask
        while (state[i] > 0) i = (i + 1) and mask
        if (state[i] == 0) used++
        token.copyInto(tokens, i * TOKEN)
        loops[i] = loop
        state[i] = 1
    }

    /** A table twice the live tokens' need (never below [INITIAL]), without the removed slots. */
    private fun rehash() {
        val oldTokens = tokens
        val oldLoops = loops
        val oldState = state
        var cap = INITIAL
        while (cap < (live.load() + 1) * 4) cap *= 2
        tokens = ByteArray(cap * TOKEN)
        loops = IntArray(cap)
        state = IntArray(cap)
        used = 0
        val t = ByteArray(TOKEN)
        for (i in oldState.indices) {
            if (oldState[i] <= 0) continue
            oldTokens.copyInto(t, 0, i * TOKEN, (i + 1) * TOKEN)
            put(SipHash.hash24(k0, k1, t), t, oldLoops[i])
            val j = find(SipHash.hash24(k0, k1, t)) { s -> same(s, t, 0) }
            state[j] = oldState[i]
        }
    }

    private fun same(
        slot: Int,
        token: ByteArray,
        off: Int,
    ): Boolean {
        val base = slot * TOKEN
        for (k in 0 until TOKEN) if (tokens[base + k] != token[off + k]) return false
        return true
    }

    private fun same(
        slot: Int,
        buf: PacketBuffer,
        off: Int,
    ): Boolean {
        val base = slot * TOKEN
        for (k in 0 until TOKEN) if (tokens[base + k] != buf[off + k]) return false
        return true
    }

    private companion object {
        const val TOKEN = 16
        const val INITIAL = 64
    }
}
