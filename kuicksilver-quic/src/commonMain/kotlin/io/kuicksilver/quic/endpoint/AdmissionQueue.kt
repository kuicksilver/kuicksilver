// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.TimeMark

/**
 * The bounded queue of client Initials waiting for `ConnectionAdmission` (1024 by default, overflow is a drop).
 * Buffers are pooled: at most [capacity] are ever allocated, each [segmentSize] bytes, and a datagram longer than a segment
 * is refused like an overflow. Nothing here is thread-safe; the endpoint loop owns it.
 */
internal class AdmissionQueue(
    val capacity: Int,
    private val segmentSize: Int = 2048,
) : AutoCloseable {
    class Entry(
        val buffer: PacketBuffer,
    ) {
        var length: Int = 0
        lateinit var from: InetSocketAddress
        var ecn: Ecn = Ecn.NotEct
        var receivedAt: TimeMark = TimeMark(0)
    }

    private val pending = ArrayDeque<Entry>(16)
    private val free = ArrayDeque<Entry>(16)
    private var allocated = 0
    private val scratch = ByteArray(segmentSize)

    val size: Int get() = pending.size

    /** Copies the datagram in; false when the queue is full or the datagram does not fit a segment. */
    fun offer(
        data: PacketBuffer,
        length: Int,
        from: InetSocketAddress,
        ecn: Ecn,
        now: TimeMark,
    ): Boolean {
        if (length > segmentSize || pending.size >= capacity) return false
        val e =
            free.removeLastOrNull()
                ?: if (allocated < capacity) {
                    allocated++
                    Entry(PacketBuffer.allocate(segmentSize))
                } else {
                    return false
                }
        data.copyTo(scratch, 0, 0, length)
        e.buffer.copyFrom(scratch, 0, 0, length)
        e.length = length
        e.from = from
        e.ecn = ecn
        e.receivedAt = now
        pending.addLast(e)
        return true
    }

    /** The oldest waiting Initial; the caller returns it with [recycle] once processed. */
    fun poll(): Entry? = pending.removeFirstOrNull()

    fun recycle(e: Entry) {
        free.addLast(e)
    }

    override fun close() {
        for (e in pending) e.buffer.close()
        for (e in free) e.buffer.close()
        pending.clear()
        free.clear()
        allocated =
            0
    }
}
