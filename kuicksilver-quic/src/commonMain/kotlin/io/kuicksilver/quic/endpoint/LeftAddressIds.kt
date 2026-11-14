// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.wire.ConnectionId

/**
 * The IDs of server connections that moved to the preferred-address socket (RFC 9000 section 9.6.2), kept after they stopped
 * routing, each until a deadline: an unknown short header on the original address that carries one gets no Stateless Reset
 * there (EndpointCore). Bounded: at most [capacity] IDs, the oldest dropped first, and at most [perConnection] of one
 * connection, its oldest dropped first, so one connection cannot push out the others'. Expired IDs go when one is added; a
 * lookup ([contains]) allocates nothing, as it runs for every unknown short header, which anyone can send.
 */
internal class LeftAddressIds(
    private val capacity: Int,
    private val perConnection: Int,
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
        val owner: Any,
        val until: TimeMark,
    )

    private val ids = LinkedHashMap<Key, Entry>()
    private val perOwner = HashMap<Any, Int>()
    private val probe = Key(ByteArray(MAX_CID_LENGTH), 0)

    val size: Int get() = ids.size

    /** Remembers [cid] of [owner] until [until]; [now] drops the IDs that expired. */
    fun add(
        cid: ConnectionId,
        owner: Any,
        until: TimeMark,
        now: TimeMark,
    ) {
        expire(now)
        val k = Key(cid.toByteArray(), cid.length)
        ids.remove(k)?.let { forget(it.owner) }
        if ((perOwner[owner] ?: 0) >= perConnection) {
            val oldest = ids.entries.first { it.value.owner === owner }.key
            ids.remove(oldest)
            forget(owner)
        }
        ids[k] = Entry(owner, until)
        perOwner[owner] = (perOwner[owner] ?: 0) + 1
        if (ids.size > capacity) {
            // key and owner read before the removal: an entry is a view of the map (Kotlin/Native throws once the map changed)
            val first = ids.entries.first()
            val key = first.key
            val firstOwner = first.value.owner
            ids.remove(key)
            forget(firstOwner)
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

    private fun expire(now: TimeMark) {
        val it = ids.entries.iterator()
        while (it.hasNext()) {
            val e = it.next().value
            if (e.until > now) break // in the order added: one alive ends the scan (a later expired one goes on lookup)
            it.remove()
            forget(e.owner)
        }
    }

    private companion object {
        /** RFC 9000 section 17.2: a connection ID is at most 20 bytes. */
        const val MAX_CID_LENGTH = 20
    }

    private fun forget(owner: Any) {
        val n = (perOwner[owner] ?: return) - 1
        if (n <= 0) perOwner.remove(owner) else perOwner[owner] = n
    }
}
