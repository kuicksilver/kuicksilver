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
        if (l.none { it.cid == cid }) {
            l += Entry(cid, core)
            core.registeredCids += cid
            size++
        }
    }

    override fun remove(cid: ConnectionId) {
        val at = find(key(cid))
        if (at < 0) return
        removeAt(at, cid)
        shrinkIfSparse()
    }

    /** Drops [cid] from the bucket at slot [at] (and from its connection's list); empties the slot when it was the last. */
    private fun removeAt(
        at: Int,
        cid: ConnectionId,
    ) {
        val l = lists[at]!!
        for (i in 0 until l.size) {
            val e = l[i]
            if (e.cid != cid) continue
            l.removeAt(i)
            e.core.registeredCids.remove(cid)
            size--
            break
        }
        if (l.isEmpty()) removeSlot(at)
    }

    /** Halves the table once at most an eighth of it is taken, so a peak of connections does not cost every later lookup and close. */
    private fun shrinkIfSparse() {
        var slots = keys.size
        while (slots > MIN_SLOTS && used * 8 < slots) slots /= 2
        if (slots != keys.size) resize(slots)
    }

    override fun contains(cid: ConnectionId): Boolean {
        val at = find(key(cid))
        if (at < 0) return false
        val l = lists[at]!!
        for (i in 0 until l.size) if (l[i].cid == cid) return true
        return false
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
        for (l in lists) l?.forEach { it.core.registeredCids.clear() }
        keys = LongArray(MIN_SLOTS)
        lists = arrayOfNulls(MIN_SLOTS)
        used = 0
        size = 0
    }

    /** Slots in the table (tests). */
    internal val slotsForTest: Int get() = keys.size

    /**
     * Drops every ID of [core] (a closed connection: its IDs are still registered), by key: the walk is over the connection's own
     * IDs, not the table. A walk over every slot made each forged Initial (a connection created and removed at once) cost the
     * whole table, and the table only grew.
     */
    fun removeAll(core: ConnectionCore) {
        val own = core.registeredCids
        while (own.isNotEmpty()) {
            val n = own.size
            val cid = own[n - 1]
            val at = find(key(cid))
            if (at >= 0) removeAt(at, cid)
            if (own.size == n) own.removeAt(n - 1) // not in the table (cannot happen: every removal updates the list)
        }
        shrinkIfSparse()
    }

    private companion object {
        const val MIN_SLOTS = 16
    }
}
