// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.quic.StreamPriority

internal enum class SendState { Ready, Send, DataSent, ResetSent, DataRecvd, ResetRecvd }

/**
 * The sending half of a stream (RFC 9000 section 3.1): bytes are kept in chunks until acknowledged; lost ranges are
 * re-queued ahead of new data. Flow control and the global send buffer are enforced by the manager.
 */
internal class SendStream(
    val id: Long,
    var priority: StreamPriority,
) {
    var state: SendState = SendState.Ready

    /** [StreamScheduler] bookkeeping: the queue holding this stream (-1 when unscheduled), its heap slot or list neighbours. */
    internal var schedQueue = -1
    internal var schedIndex = 0
    internal var schedPrev: SendStream? = null
    internal var schedNext: SendStream? = null

    /** Queued in [StreamManager]'s list of streams waiting for connection-level credit. */
    internal var connBlocked = false

    /** In the manager's list of streams blocked at their own flow-control limit (STREAM_DATA_BLOCKED reported). */
    internal var streamBlockedListed = false

    /** Queued in [StreamManager]'s list of streams whose last write did not fit the send buffer. */
    internal var writeRefused = false

    /** Unacknowledged bytes in a ring buffer: [head] is the ring index of stream offset [releasedUpTo]; it grows to the high-water mark once and then never allocates. */
    private var ring = ByteArray(4096)
    private var head = 0

    /** Total bytes handed to this stream (the next write offset). */
    var written: Long = 0
        private set

    /** New data below this offset has been sent at least once. */
    var sentEnd: Long = 0
        private set
    private var ackedRanges = LongArray(16)
    private var ackedCount = 0
    private var lost = LongArray(8)
    private var lostCount = 0 // (start, end) pairs ascending
    var finQueued: Boolean = false
        private set
    var finSent: Boolean = false
        private set
    var finAcked: Boolean = false
        private set

    /** Bytes still buffered (not yet released by acknowledgement). */
    var buffered: Long = 0
        private set

    val hasRetransmit: Boolean get() = lostCount > 0

    /** Offset of the next range [nextRange] would pick (for sizing the frame header). */
    val nextOffset: Long get() = if (lostCount > 0) lost[0] else sentEnd
    private var releasedUpTo: Long = 0
    val hasPending: Boolean get() {
        if (state == SendState.ResetSent ||
            state == SendState.ResetRecvd
        ) {
            return false
        }
        pruneLost()
        return lostCount > 0 || sentEnd < written || (finQueued && !finSent)
    }

    fun enqueue(
        data: ByteArray,
        off: Int,
        len: Int,
        fin: Boolean,
    ) {
        check(!finQueued) { "stream $id already closed for writing" }
        if (len >
            0
        ) {
            reserve(len)
            val tail = ((head + buffered) % ring.size).toInt()
            val first = minOf(len, ring.size - tail)
            data.copyInto(
                ring,
                tail,
                off,
                off + first,
            )
            if (first < len) data.copyInto(ring, 0, off + first, off + len)
            written += len
            buffered += len
        }
        if (fin) finQueued = true
        if (state == SendState.Ready) state = SendState.Send
    }

    /** Picks the next range to send (lost first), at most [max] bytes; returns false when nothing fits. */
    fun nextRange(
        max: Int,
        out: SendRange,
    ): Boolean {
        pruneLost()
        if (lostCount >
            0
        ) {
            val s = lost[0]
            val e = minOf(lost[1], s + max)
            out.offset = s
            out.length = (e - s).toInt()
            // a resent range never carries the FIN: one still in flight needs no copy, a lost one goes as an empty frame of
            // its own. quiche's receiver takes the final size from a frame whose bytes it already read, drops the frame as a
            // duplicate and never wakes the application for the FIN (interop run 20261015-170940, kuicksilver->quiche:handshakeloss)
            out.fin = false
            return out.length > 0
        }
        if (sentEnd <
            written
        ) {
            val e = minOf(written, sentEnd + max)
            out.offset = sentEnd
            out.length = (e - sentEnd).toInt()
            out.fin =
                finQueued && e == written
            return out.length > 0
        }
        if (finQueued && !finSent) {
            out.offset = written
            out.length = 0
            out.fin = true
            return true
        }
        return false
    }

    /** Copies [len] bytes from stream offset [offset] (not below the released prefix) into [into]. */
    fun copy(
        offset: Long,
        into: ByteArray,
        intoOff: Int,
        len: Int,
    ) {
        require(offset >= releasedUpTo && offset + len <= written) { "copy $offset+$len outside [$releasedUpTo, $written)" }
        val idx = ((head + (offset - releasedUpTo)) % ring.size).toInt()
        val first = minOf(len, ring.size - idx)
        ring.copyInto(into, intoOff, idx, idx + first)
        if (first < len) ring.copyInto(into, intoOff + first, 0, len - first)
    }

    private fun reserve(extra: Int) {
        val needed = buffered + extra
        if (needed <= ring.size) return
        var size = ring.size.toLong()
        while (size < needed) size *= 2
        val grown = ByteArray(size.toInt())
        val count = buffered.toInt()
        val first = minOf(count, ring.size - head)
        ring.copyInto(grown, 0, head, head + first)
        if (first <
            count
        ) {
            ring.copyInto(grown, first, 0, count - first)
        }
        ring = grown
        head = 0
    }

    fun markSent(
        offset: Long,
        len: Int,
        fin: Boolean = false,
    ) {
        val end = offset + len
        if (lostCount > 0 && lost[0] == offset) {
            if (end >= lost[1]) removeLost(0) else lost[0] = end
        }
        if (end > sentEnd) sentEnd = end
        if (fin) {
            finSent = true
            if (state == SendState.Send) state = SendState.DataSent
        }
    }

    /** Drops queued retransmissions that were acknowledged (or released) in the meantime. */
    private fun pruneLost() {
        var i = 0
        while (i < lostCount) {
            if (lost[2 * i] < releasedUpTo) lost[2 * i] = releasedUpTo
            if (lost[2 * i + 1] <= lost[2 * i] || isAcked(lost[2 * i], lost[2 * i + 1])) removeLost(i) else i++
        }
    }

    private fun removeLost(i: Int) {
        for (k in i until lostCount - 1) {
            lost[2 * k] = lost[2 * (k + 1)]
            lost[2 * k + 1] =
                lost[2 * (k + 1) + 1]
        }
        lostCount--
    }

    fun onLost(
        offset: Long,
        len: Int,
        fin: Boolean = false,
    ) {
        if (state == SendState.ResetSent || state == SendState.ResetRecvd) return
        if (len > 0 && !isAcked(offset, offset + len)) {
            // the same range can be declared lost twice (an original and its PTO probe): keep the queue a set of disjoint
            // ranges, or one packet would carry the bytes twice and a peer like quiche fails the handshake on the duplicate
            var start = offset
            var end = offset + len
            var i = 0
            while (i < lostCount && lost[2 * i + 1] < start) i++
            while (i < lostCount &&
                lost[2 * i] <= end
            ) {
                start = minOf(start, lost[2 * i])
                end = maxOf(end, lost[2 * i + 1])
                removeLost(i)
            }
            if (2 * lostCount + 2 > lost.size) lost = lost.copyOf(lost.size * 2)
            for (k in lostCount downTo i + 1) {
                lost[2 * k] = lost[2 * (k - 1)]
                lost[2 * k + 1] = lost[2 * (k - 1) + 1]
            }
            lost[2 * i] = start
            lost[2 * i + 1] = end
            lostCount++
        }
        if (fin && !finAcked) {
            finSent = false
            if (state == SendState.DataSent) state = SendState.Send
        }
    }

    private fun isAcked(
        start: Long,
        end: Long,
    ): Boolean {
        for (i in 0 until ackedCount) {
            if (ackedRanges[2 * i] <= start &&
                ackedRanges[2 * i + 1] >= end
            ) {
                return true
            }
        }
        return false
    }

    /** Returns the number of buffered bytes released. */
    fun onAcked(
        offset: Long,
        len: Int,
        fin: Boolean = false,
    ): Long {
        if (fin) finAcked = true
        if (len > 0) addAcked(offset, offset + len)
        var released = 0L
        if (ackedCount > 0 && ackedRanges[0] <= releasedUpTo &&
            ackedRanges[1] > releasedUpTo
        ) {
            released = ackedRanges[1] - releasedUpTo
            releasedUpTo = ackedRanges[1]
        }
        if (released > 0) head = ((head + released) % ring.size).toInt()
        buffered -= released
        if (finAcked && buffered == 0L && finQueued) state = SendState.DataRecvd
        return released
    }

    private fun addAcked(
        start: Long,
        end: Long,
    ) {
        if (2 * ackedCount + 2 > ackedRanges.size) ackedRanges = ackedRanges.copyOf(ackedRanges.size * 2)
        var i = 0
        while (i < ackedCount && ackedRanges[2 * i + 1] < start) i++
        if (i < ackedCount && ackedRanges[2 * i] <= end) {
            var s = minOf(start, ackedRanges[2 * i])
            var e = maxOf(end, ackedRanges[2 * i + 1])
            var j = i + 1
            while (j < ackedCount && ackedRanges[2 * j] <= e) {
                e = maxOf(e, ackedRanges[2 * j + 1])
                j++
            }
            val removed = j - i - 1
            ackedRanges[2 * i] = s
            ackedRanges[2 * i + 1] = e
            for (k in i + 1 until ackedCount - removed) {
                ackedRanges[2 * k] = ackedRanges[2 * (k + removed)]
                ackedRanges[2 * k + 1] =
                    ackedRanges[2 * (k + removed) + 1]
            }
            ackedCount -= removed
            return
        }
        for (k in ackedCount downTo i + 1) {
            ackedRanges[2 * k] = ackedRanges[2 * (k - 1)]
            ackedRanges[2 * k + 1] =
                ackedRanges[2 * (k - 1) + 1]
        }
        ackedRanges[2 * i] = start
        ackedRanges[2 * i + 1] = end
        ackedCount++
    }

    /** Abandons the stream (RESET_STREAM): pending data is dropped; returns the buffered bytes released. */
    fun reset(): Long {
        val released = buffered
        head = 0
        buffered = 0
        lostCount = 0
        state = SendState.ResetSent
        return released
    }
}

/** A range of stream data picked for sending. */
internal class SendRange {
    var offset: Long = 0
    var length: Int = 0
    var fin: Boolean = false
}
