// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.wire.ConnectionId

/**
 * The IDs of server connections that moved to the preferred-address socket (RFC 9000 section 9.6.2), kept after they stopped
 * routing, each until a deadline: an unknown short header on the original address that carries one gets no Stateless Reset
 * there (EndpointCore).
 *
 * Bounded: at most [capacity] IDs in all, and at most the cap [add] is given for one connection (the IDs it held when it moved),
 * so one connection cannot push out the others'. When one has to go, an expired ID goes first, then the oldest that is not
 * its connection's primary (the ID the client used on the original address at the move, the one most likely to arrive
 * there late), and a primary last. A connection is named by an opaque token ([add]'s `owner`), never by the connection itself,
 * which would stay reachable for the whole lifetime of its IDs. A lookup ([contains]) allocates nothing, as it runs for every
 * unknown short header, which anyone can send.
 */
internal class LeftAddressIds(
    private val capacity: Int,
) {
    /** An ID's bytes; [len] of [bytes] count (the probe reuses one array for every lookup). */
    private class Key(
        val bytes: ByteArray,
        var len: Int,
    ) {
        // the same as ByteArray.contentHashCode over the ID
        override fun hashCode(): Int {
            var h = 1
            for (i in 0 until len) h = 31 * h + bytes[i]
            return h
        }

        override fun equals(other: Any?): Boolean {
            if (other !is Key || other.len != len) return false
            for (i in 0 until len) if (other.bytes[i] != bytes[i]) return false
            return true
        }
    }

    private class Entry(
        val owner: Long,
        val until: TimeMark,
        val primary: Boolean,
    )

    private val ids = LinkedHashMap<Key, Entry>()
    private val perOwner = HashMap<Long, Int>()
    private val probe = Key(ByteArray(MAX_CID_LENGTH), 0)

    val size: Int get() = ids.size

    /**
     * Remembers [cid] of the connection [owner] (an opaque token) until [until]; [ownerCap] is the most that connection keeps,
     * [primary] marks the ID it used on the original address at the move. [now] drops the IDs that expired.
     */
    fun add(
        cid: ConnectionId,
        owner: Long,
        ownerCap: Int,
        primary: Boolean,
        until: TimeMark,
        now: TimeMark,
    ) {
        if (cid.length > MAX_CID_LENGTH) return
        expireOldest(now)
        val k = Key(cid.toByteArray(), cid.length)
        ids.remove(k)?.let { forget(it.owner) }
        if ((perOwner[owner] ?: 0) >= ownerCap) evict(owner)
        ids[k] = Entry(owner, until, primary)
        perOwner[owner] = (perOwner[owner] ?: 0) + 1
        if (ids.size > capacity) {
            expireAll(now) // lifetimes differ by connection: an expired ID may sit behind a live one
            if (ids.size > capacity) evict(null)
        }
    }

    /** True when the ID at [off] in [buf] ([len] bytes) is remembered at [now]; an expired one is forgotten. */
    fun contains(
        buf: PacketBuffer,
        off: Int,
        len: Int,
        now: TimeMark,
    ): Boolean {
        if (ids.isEmpty() || len > probe.bytes.size) return false
        buf.copyTo(probe.bytes, off, 0, len)
        probe.len = len
        val e = ids[probe] ?: return false
        if (e.until > now) return true
        ids.remove(probe)
        forget(e.owner)
        return false
    }

    /** Drops expired IDs from the oldest on, up to the first live one (cheap, on every add). */
    private fun expireOldest(now: TimeMark) {
        val it = ids.entries.iterator()
        while (it.hasNext()) {
            val e = it.next().value // read before the removal: an entry is a view of the map (Kotlin/Native throws once it changed)
            if (e.until > now) break
            it.remove()
            forget(e.owner)
        }
    }

    /** Drops every expired ID (only when the memory is full). */
    private fun expireAll(now: TimeMark) {
        val it = ids.entries.iterator()
        while (it.hasNext()) {
            val e = it.next().value
            if (e.until > now) continue
            it.remove()
            forget(e.owner)
        }
    }

    /** Drops the oldest ID of [owner] (of anyone when null) that is not a primary, or the oldest primary when there is no other. */
    private fun evict(owner: Long?) {
        var victim: Key? = null
        var victimOwner = 0L
        for (pass in 0..1) {
            for ((k, e) in ids) {
                if (owner != null && e.owner != owner) continue
                if (pass == 0 && e.primary) continue
                victim = k
                victimOwner = e.owner
                break
            }
            if (victim != null) break
        }
        if (victim == null) return
        ids.remove(victim)
        forget(victimOwner)
    }

    private fun forget(owner: Long) {
        val n = (perOwner[owner] ?: return) - 1
        if (n <= 0) perOwner.remove(owner) else perOwner[owner] = n
    }

    private companion object {
        /** RFC 9000 section 17.2: a connection ID is at most 20 bytes. */
        const val MAX_CID_LENGTH = 20
    }
}
