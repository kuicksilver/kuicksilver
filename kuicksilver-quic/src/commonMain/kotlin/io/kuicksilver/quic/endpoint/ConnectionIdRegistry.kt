// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.core.CidRegistrar
import io.kuicksilver.quic.wire.ConnectionId

/**
 * Connection ID → core, keyed by SipHash. The table is open-addressed on the hash itself (a primitive long), so a lookup per
 * received datagram allocates nothing: a `HashMap<Long, …>` boxed the key on every lookup.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal class ConnectionIdRegistry(
    private val k0: Long,
    private val k1: Long,
    // tests: a mask over the 64-bit key, so IDs share keys as SipHash collisions would (the default keeps every bit)
    private val keyMask: Long = -1L,
) : CidRegistrar {
    private class Entry(
        val cid: ConnectionId,
        val core: ConnectionCore,
    )

    // linear probing; a slot is taken when its list is non-null; at most half the slots taken
    private var keys = LongArray(MIN_SLOTS)
    private var lists = arrayOfNulls<ArrayList<Entry>>(MIN_SLOTS)
    private var used = 0

    // a heap array: nothing closes the registry, so a native buffer would leak
    private val scratch = ByteArray(20)
    var size: Int = 0
        private set

    private fun key(cid: ConnectionId): Long {
        cid.copyToArray(scratch, 0)
        return SipHash.hash24(k0, k1, scratch, 0, cid.length) and keyMask
    }

    private fun home(
        k: Long,
        mask: Int,
    ): Int = (k xor (k ushr 32)).toInt() and mask

    /** The slot holding [k], or -1. */
    private fun find(k: Long): Int {
        val mask = keys.size - 1
        var i = home(k, mask)
        while (true) {
            lists[i] ?: return -1
            if (keys[i] == k) return i
            i = (i + 1) and mask
        }
    }

    private fun bucket(k: Long): ArrayList<Entry> {
        val at = find(k)
        if (at >= 0) return lists[at]!!
        if ((used + 1) * 2 > keys.size) resize(keys.size * 2)
        val mask = keys.size - 1
        var i = home(k, mask)
        while (lists[i] != null) i = (i + 1) and mask
        val l = ArrayList<Entry>(1)
        keys[i] = k
        lists[i] = l
        used++
        return l
    }

    private fun resize(slots: Int) {
        val oldKeys = keys
        val oldLists = lists
        keys = LongArray(slots)
        lists = arrayOfNulls(slots)
        val mask = slots - 1
        for (j in oldKeys.indices) {
            val l = oldLists[j] ?: continue
            var i = home(oldKeys[j], mask)
            while (lists[i] != null) i = (i + 1) and mask
            keys[i] = oldKeys[j]
            lists[i] = l
        }
    }

    /** Empties slot [at], moving later entries of its probe run back (no tombstones). */
    private fun removeSlot(at: Int) {
        val mask = keys.size - 1
        var hole = at
        lists[hole] = null
        used--
        var i = (hole + 1) and mask
        while (true) {
            val l = lists[i] ?: return
            val h = home(keys[i], mask)
            // the entry at i may move into the hole if its home is not in (hole, i] cyclically
            val stays = if (hole <= i) h in (hole + 1)..i else h > hole || h <= i
            if (!stays) {
                keys[hole] = keys[i]
                lists[hole] = l
                lists[i] = null
                hole = i
            }
            i = (i + 1) and mask
        }
    }

    override fun add(
        cid: ConnectionId,
        core: ConnectionCore,
    ) {
        val l = bucket(key(cid))
        if (l.none {
                it.cid ==
                    cid
            }
        ) {
            l += Entry(cid, core)
            size++
        }
    }

    override fun remove(cid: ConnectionId) {
        val at = find(key(cid))
        if (at < 0) return
        val l = lists[at]!!
        if (l.removeAll { it.cid == cid }) size--
        if (l.isEmpty()) removeSlot(at)
    }

    fun lookup(
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): ConnectionCore? {
        val at = find(SipHash.hash24(k0, k1, buf, off, len) and keyMask)
        if (at < 0) return null
        val l = lists[at]!!
        for (i in 0 until l.size) {
            val e = l[i]
            if (e.cid.contentEquals(buf, off, len)) return e.core
        }
        return null
    }

    fun clear() {
        keys = LongArray(MIN_SLOTS)
        lists = arrayOfNulls(MIN_SLOTS)
        used = 0
        size = 0
    }

    /** Keys whose bucket [removeAll] emptied; kept between calls, so a close allocates nothing once it is large enough. */
    private var emptiedKeys = LongArray(8)

    /**
     * Drops every ID of [core] (a closed connection: its IDs are still registered). One walk over the slots, entries removed
     * by index; the buckets it emptied are then removed by key, each with its probe run shifted back. No rebuild: a rebuild
     * per close was the whole table again (hundreds of KB per close with many connections), and closes are peer-driven.
     */
    fun removeAll(core: ConnectionCore) {
        var emptied = 0
        val ls = lists
        for (j in ls.indices) {
            val l = ls[j] ?: continue
            var w = 0
            for (i in 0 until l.size) {
                val e = l[i]
                if (e.core !== core) l[w++] = e
            }
            if (w == l.size) continue
            size -= l.size - w
            while (l.size > w) l.removeAt(l.size - 1)
            if (w == 0) {
                if (emptied == emptiedKeys.size) emptiedKeys = emptiedKeys.copyOf(emptied * 2)
                emptiedKeys[emptied++] = keys[j]
            }
        }
        // after the walk: removing a slot moves later entries of its run back, which the walk could have passed over or met twice
        for (i in 0 until emptied) {
            val at = find(emptiedKeys[i])
            if (at >= 0 && lists[at]!!.isEmpty()) removeSlot(at)
        }
    }

    private companion object {
        const val MIN_SLOTS = 16
    }
}
