// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.qpack

import io.kuicksilver.http3.Http3ErrorCode

/**
 * QPACK encoder (RFC 9204 sections 2.1, 4.3, 4.5, 7.1). Until [onPeerSettings] it uses the static table only. Its own table
 * never exceeds [maxCapacity] (`encoderMaxTableCapacity`) whatever the peer allows; it blocks at most
 * min(peer, 100) streams; sensitive fields are never indexed.
 */
internal class QpackEncoder(
    val maxCapacity: Long = 4096,
    private val limits: QpackLimits = QpackLimits(),
) {
    private val table = DynamicTable(0)
    private val enc = QpackWriter()
    private var peerMaxTableCapacity = 0L
    var capacity: Long = 0
        private set
    var maxBlockedStreams: Int = 0
        private set
    private var knownReceived = 0L
    private val refs = HashMap<Long, Int>() // absolute index -> references in unacknowledged sections
    private val sections = HashMap<Long, ArrayDeque<Section>>() // per stream, in order
    private var pendingInput = ByteArray(0)

    /** Field lines sent with the never-index bit in the last [encode]. */
    var lastNeverIndexed: Int = 0
        private set

    private class Section(
        val ric: Long,
        val refs: List<Long>,
    )

    val insertCount: Long get() = table.insertCount

    /** Sections sent with dynamic references and not yet acknowledged or cancelled by the peer. */
    var outstandingSections: Int = 0
        private set

    fun onPeerSettings(
        peerMaxTableCapacity: Long,
        peerBlockedStreams: Long,
    ) {
        this.peerMaxTableCapacity = peerMaxTableCapacity
        maxBlockedStreams = minOf(peerBlockedStreams, 100L).toInt()
        capacity = minOf(peerMaxTableCapacity, maxCapacity)
        if (capacity > 0) {
            table.setCapacity(capacity)
            enc.writeInt(0x20, 5, capacity)
        } // Set Dynamic Table Capacity
    }

    fun drainEncoderStream(): ByteArray {
        val b = enc.toByteArray()
        enc.reset()
        return b
    }

    /** Streams with a section the decoder has not caught up with; recounted only after the set or knownReceived changed. */
    private var blockingCache = -1

    private fun blockingStreams(): Int {
        if (blockingCache <
            0
        ) {
            blockingCache = sections.count { (_, q) -> q.any { it.ric > knownReceived } }
        }
        return blockingCache
    }

    private fun isBlocking(stream: Long): Boolean = sections[stream]?.any { it.ric > knownReceived } == true

    private fun evictable(needed: Long): Boolean {
        val boundary = table.evictionBoundary(needed)
        if (boundary == Long.MAX_VALUE) return false
        for (abs in table.dropped until boundary) if (abs >= knownReceived || (refs[abs] ?: 0) > 0) return false
        return true
    }

    fun encode(
        streamId: Long,
        fields: List<Pair<String, String>>,
    ): ByteArray {
        val body = QpackWriter()
        val used = ArrayList<Long>()
        var neverIndexed = 0
        // may this section reference entries the decoder has not acknowledged yet (and so block)?
        val mayBlock = capacity > 0 && (isBlocking(streamId) || blockingStreams() < maxBlockedStreams)
        // a peer that never acknowledges sections would grow per-stream state without bound: above the cap every section is static or literal
        val mayReference = outstandingSections < MAX_OUTSTANDING_SECTIONS

        fun usable(abs: Long) = mayReference && abs >= 0 && table.absolute(abs) != null && (abs < knownReceived || mayBlock)
        val base =
            run {
                // first pass: insertions happen before the section, so Base = Insert Count after them
                for ((name, value) in fields) {
                    if (capacity == 0L || sensitive(name, value) || StaticTable.find(name, value) >= 0 ||
                        table.findExact(name, value) >= 0
                    ) {
                        continue // without a blocking budget the insert is speculative: referenced once acknowledged
                    }
                    val size = entrySize(name, value)
                    if (size > capacity / 2 || !evictable(size)) continue
                    val sIdx = StaticTable.findName(name)
                    val dIdx = table.findName(name)
                    when {
                        sIdx >= 0 -> {
                            enc.writeInt(0xc0, 6, sIdx.toLong())
                            enc.writeStringAuto(0, 7, value)
                        }

                        dIdx >= 0 && dIdx >= table.evictionBoundary(size) -> {
                            enc.writeInt(0x80, 6, table.insertCount - dIdx - 1)
                            enc.writeStringAuto(0, 7, value)
                        }

                        else -> {
                            enc.writeStringAuto(0x40, 5, name)
                            enc.writeStringAuto(0, 7, value)
                        }
                    }
                    table.insert(name, value)
                }
                table.insertCount
            }
        for ((name, value) in fields) {
            val never = sensitive(name, value) && name in NEVER_INDEX
            if (never) neverIndexed++
            val st = StaticTable.find(name, value)
            val dyn = if (sensitive(name, value)) -1L else table.findExact(name, value)
            when {
                st >= 0 && !never -> {
                    body.writeInt(0xc0, 6, st.toLong())
                }

                // indexed, static
                dyn >= 0 && usable(dyn) -> {
                    body.writeInt(0x80, 6, base - dyn - 1)
                    used += dyn
                }

                // indexed, dynamic (relative to Base)
                else -> {
                    val n = if (never) 0x20 else 0
                    val sn = StaticTable.findName(name)
                    val dn = if (sn < 0) table.findName(name) else -1
                    when {
                        sn >= 0 -> {
                            body.writeInt(0x50 or n, 4, sn.toLong())
                        }

                        // literal, static name reference
                        dn >= 0 && usable(dn) -> {
                            body.writeInt(0x40 or n, 4, base - dn - 1)
                            used += dn
                        }

                        // literal, dynamic name reference
                        else -> {
                            body.writeStringAuto(0x20 or (if (never) 0x10 else 0), 3, name)
                        } // literal name: 001N H len(3)
                    }
                    body.writeStringAuto(0, 7, value)
                }
            }
        }
        lastNeverIndexed = neverIndexed
        val ric = if (used.isEmpty()) 0L else used.max() + 1
        val out = QpackWriter(body.size + 4)
        if (ric == 0L) {
            out.writeByte(0)
            out.writeByte(0)
        } else {
            val maxEntries = peerMaxTableCapacity / 32
            out.writeInt(0, 8, ric % (2 * maxEntries) + 1)
            out.writeInt(0, 7, base - ric) // sign 0: Base >= RIC
            for (abs in used) refs[abs] = (refs[abs] ?: 0) + 1
            sections.getOrPut(streamId) { ArrayDeque() }.addLast(Section(ric, used))
            outstandingSections++
            if (ric >
                knownReceived
            ) {
                blockingCache = -1
            }
        }
        out.writeBytes(body.toByteArray())
        return out.toByteArray()
    }

    /** Decoder-stream instructions from the peer (RFC 9204 section 4.4). */
    fun onDecoderStream(
        bytes: ByteArray,
        off: Int,
        len: Int,
    ) {
        val joined = pendingInput.isNotEmpty()
        val buf = if (joined) pendingInput + bytes.copyOfRange(off, off + len) else bytes
        val end = if (joined) buf.size else off + len
        val r = QpackReader(buf, if (joined) 0 else off, end, Http3ErrorCode.QPACK_DECODER_STREAM_ERROR)
        while (r.remaining > 0) {
            val mark = r.pos
            try {
                val b = r.peek()
                when {
                    b and 0x80 != 0 -> { // Section Acknowledgment
                        val id = r.readInt(7, limits)
                        val q = sections[id]
                        val s =
                            q?.removeFirstOrNull() ?: r.fail("acknowledgment for stream $id without an outstanding section")
                        if (q.isEmpty()) sections.remove(id)
                        outstandingSections--
                        release(s)
                        if (s.ric > knownReceived) knownReceived = s.ric
                        blockingCache = -1
                    }

                    b and 0x40 != 0 -> {
                        val id = r.readInt(6, limits)
                        sections.remove(id)?.forEach {
                            release(it)
                            outstandingSections--
                        }
                        blockingCache =
                            -1
                    }

                    // Stream Cancellation
                    else -> { // Insert Count Increment
                        val inc = r.readInt(6, limits)
                        if (inc == 0L ||
                            knownReceived + inc > table.insertCount
                        ) {
                            r.fail("insert count increment $inc beyond ${table.insertCount}")
                        }
                        knownReceived += inc
                        blockingCache = -1
                    }
                }
            } catch (t: QpackTruncated) {
                pendingInput = buf.copyOfRange(mark, end)
                return
            }
        }
        pendingInput = ByteArray(0)
    }

    private fun release(s: Section) {
        for (abs in s.refs) {
            val n =
                (refs[abs] ?: 1) - 1
            if (n == 0) refs.remove(abs) else refs[abs] = n
        }
    }

    private fun sensitive(
        name: String,
        value: String,
    ): Boolean = name in NEVER_INDEX || (capacity > 0 && value.length > capacity / 4)

    companion object {
        /** Fields whose values are secrets (CRIME-style attacks, RFC 9204 section 7.1): never in the table, N bit set. */
        val NEVER_INDEX: Set<String> = setOf("authorization", "cookie", "set-cookie", "proxy-authorization")

        /** Cap on unacknowledged sections: above it sections carry no dynamic references until the peer catches up. */
        const val MAX_OUTSTANDING_SECTIONS: Int = 1000
    }
}
