// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class)

package io.kuicksilver.quic.endpoint

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.wire.ConnectionId
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicIntArray
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.decrementAndFetchAt
import kotlin.concurrent.atomics.fetchAndDecrement
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetchAt

/**
 * QUIC-LB connection IDs issued by another loop than the one they hash to (its pool was full), and their real owner. The
 * datagram path ([ownerOf]) allocates nothing and takes no global lock: a per-bucket counter, indexed by the SipHash the
 * caller already computed, answers "none here" for almost every ID; only a bucket that holds an exception takes its shard's
 * lock and compares the bytes in place. At most [capacity] entries live; past that the oldest is dropped (its ID then
 * routes by hash again, which only matters for a datagram that lands on another loop). Entries leave with [release].
 */
internal class OwnerExceptions(
    private val capacity: Int,
) {
    private class Entry(
        val hash: Long,
        val bytes: ByteArray,
        val loop: Int,
    ) {
        var live = true
    }

    private class Shard {
        val lock = SpinLock()
        val entries = ArrayList<Entry>(2)
    }

    private val buckets = AtomicIntArray(BUCKETS)
    private val shards = Array(SHARDS) { Shard() }
    private val orderLock = SpinLock()
    private val order = ArrayDeque<Entry>() // insertion order, for the oldest-first drop; released entries leave lazily
    private val liveCount = AtomicInt(0)

    /** Live entries. */
    val size: Int get() = liveCount.load()

    private fun bucket(hash: Long) = (hash ushr 40).toInt() and (BUCKETS - 1)

    private fun shardOf(hash: Long) = shards[bucket(hash) and (SHARDS - 1)]

    fun add(
        hash: Long,
        cid: ByteArray,
        loop: Int,
    ) {
        val e = Entry(hash, cid.copyOf(), loop)
        val s = shardOf(hash)
        s.lock.locked { s.entries += e }
        buckets.incrementAndFetchAt(bucket(hash))
        liveCount.incrementAndFetch()
        val evict =
            orderLock.locked {
                order.addLast(e)
                var out: Entry? = null
                if (liveCount.load() > capacity) {
                    while (order.isNotEmpty()) {
                        val o = order.removeFirst()
                        if (o.live) {
                            out = o
                            break
                        }
                    }
                }
                if (order.size > 2 * capacity + 16) order.removeAll { !it.live } // released entries, compacted
                out
            }
        evict?.let { remove(it) }
    }

    private fun remove(e: Entry) {
        val s = shardOf(e.hash)
        val removed = s.lock.locked { if (e.live) s.entries.remove(e).also { e.live = false } else false }
        if (removed) {
            buckets.decrementAndFetchAt(bucket(e.hash))
            liveCount.fetchAndDecrement()
        }
    }

    /** The recorded owner of the ID at `buf[off, +len)` whose SipHash is [hash], or -1. */
    fun ownerOf(
        hash: Long,
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): Int {
        if (buckets.loadAt(bucket(hash)) == 0) return -1
        val s = shardOf(hash)
        return s.lock.locked {
            for (i in s.entries.indices) {
                val e = s.entries[i]
                if (e.hash != hash || e.bytes.size != len) continue
                var same = true
                for (k in 0 until len) {
                    if (e.bytes[k] != buf[off + k]) {
                        same = false
                        break
                    }
                }
                if (same) return@locked e.loop
            }
            -1
        }
    }

    /** Drops the entry of [cid] (hashed to [hash]), if any. */
    fun release(
        hash: Long,
        cid: ConnectionId,
    ) {
        if (buckets.loadAt(bucket(hash)) == 0) return
        val s = shardOf(hash)
        val e = s.lock.locked { s.entries.firstOrNull { it.hash == hash && cid.contentEqualsArray(it.bytes) } } ?: return
        remove(e)
    }

    fun clear() {
        for (s in shards) {
            s.lock.locked {
                for (e in s.entries) e.live = false
                s.entries.clear()
            }
        }
        for (i in 0 until BUCKETS) buckets.storeAt(i, 0)
        liveCount.store(0)
        orderLock.locked { order.clear() }
    }

    private fun ConnectionId.contentEqualsArray(b: ByteArray): Boolean {
        if (length != b.size) return false
        for (i in b.indices) if (this[i] != b[i]) return false
        return true
    }

    private companion object {
        const val BUCKETS = 1 shl 14
        const val SHARDS = 64
    }
}
