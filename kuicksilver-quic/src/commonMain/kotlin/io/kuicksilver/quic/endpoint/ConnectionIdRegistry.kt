// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.core.CidRegistrar
import io.kuicksilver.quic.wire.ConnectionId

/** Connection ID → core, keyed by SipHash so lookups never allocate a key object. */
@OptIn(ExperimentalKuicksilverApi::class)
internal class ConnectionIdRegistry(
    private val k0: Long,
    private val k1: Long,
) : CidRegistrar {
    private class Entry(
        val cid: ConnectionId,
        val core: ConnectionCore,
    )

    private val buckets = HashMap<Long, ArrayList<Entry>>()
    private val scratch = PacketBuffer.allocate(20)
    var size: Int = 0
        private set

    private fun key(cid: ConnectionId): Long {
        cid.copyTo(scratch, 0)
        return SipHash.hash24(k0, k1, scratch, 0, cid.length)
    }

    override fun add(
        cid: ConnectionId,
        core: ConnectionCore,
    ) {
        val l = buckets.getOrPut(key(cid)) { ArrayList(1) }
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
        val k = key(cid)
        val l =
            buckets[k] ?: return
        if (l.removeAll { it.cid == cid }) size--
        if (l.isEmpty()) buckets.remove(k)
    }

    fun lookup(
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): ConnectionCore? {
        val l =
            buckets[SipHash.hash24(k0, k1, buf, off, len)] ?: return null
        for (e in l) if (e.cid.contentEquals(buf, off, len)) return e.core
        return null
    }

    fun clear() {
        buckets.clear()
        size = 0
    }

    fun removeAll(core: ConnectionCore) {
        val it = buckets.values.iterator()
        while (it.hasNext()) {
            val l = it.next()
            val before = l.size
            l.removeAll { e ->
                e.core ===
                    core
            }
            size -= before - l.size
            if (l.isEmpty()) it.remove()
        }
    }
}
