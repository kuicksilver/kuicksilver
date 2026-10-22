// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.quic.StreamPriority

/**
 * RFC 9000 section 3.1, plus [ResetAt]: RESET_STREAM_AT was sent (draft-ietf-quic-reliable-stream-reset section 3) and the
 * bytes below the reliable size are still being delivered; once they are acknowledged the stream is [ResetSent].
 */
internal enum class SendState { Ready, Send, DataSent, ResetAt, ResetSent, DataRecvd, ResetRecvd }

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

    /** Acknowledged bytes above the released prefix: disjoint, non-adjacent (start, end) pairs, ascending. */
    private var ackedRanges = LongArray(16)
    private var ackedCount = 0

    /**
     * Bytes to retransmit: disjoint (start, end) pairs, ascending, none of them acknowledged. [onAcked] takes acknowledged bytes
     * out at once and [onLost] queues only unacknowledged ones, so [hasPending] and [nextRange] need no pass over the queue: a
     * receiver that acknowledges every other packet leaves thousands of ranges on each side, and a pass per MAX_STREAM_DATA cost
     * O(lost x acknowledged) per frame (0.2.1 review; quic-go likewise drops acknowledged frames from its retransmission queue
     * when the ACK arrives).
     */
    private var lost = LongArray(8)
    private var lostCount = 0
    var finQueued: Boolean = false
        private set
    var finSent: Boolean = false
        private set
    var finAcked: Boolean = false
        private set

    /** Bytes still buffered (not yet released by acknowledgement). */
    var buffered: Long = 0
        private set

    /** Test hook: range comparisons made by the lost/acknowledged bookkeeping, to prove its cost per call stays bounded. */
    internal var rangeStepsForTest: Long = 0
        private set

    val hasRetransmit: Boolean get() = lostCount > 0

    /** Offset of the next range [nextRange] would pick (for sizing the frame header). */
    val nextOffset: Long get() = if (lostCount > 0) lost[0] else sentEnd

    /** The acknowledged prefix: bytes below it are released. */
    var releasedUpTo: Long = 0
        private set

    /** RESET_STREAM_AT: the bytes below this still go out and are retransmitted; -1 without one. */
    var reliableSize: Long = -1
        private set

    /** The final size a RESET_STREAM_AT announced; -1 before one was. */
    private var resetAtFinalSize: Long = -1

    /** The application error code of the RESET_STREAM_AT, sent once [resetAtDue]. */
    var resetAtCode: Long = 0
        private set

    /**
     * RESET_STREAM_AT waits until every reliable byte was sent once (draft-ietf-quic-reliable-stream-reset-11 section 4: its
     * final size must stay within the peer's flow-control limits, and the bytes up to [sentEnd] already are).
     */
    val resetAtDue: Boolean get() = state == SendState.ResetAt && resetAtFinalSize < 0 && sentEnd >= reliableSize

    /** The RESET_STREAM_AT goes out now: its final size is what was sent. */
    fun announceResetAt(): Long {
        resetAtFinalSize = sentEnd
        return sentEnd
    }

    /** The final size of a reset (RFC 9000 section 4.5): what was sent, or what an earlier RESET_STREAM_AT announced. */
    val finalSizeForReset: Long get() = maxOf(sentEnd, resetAtFinalSize)

    val hasPending: Boolean get() {
        if (state == SendState.ResetSent ||
            state == SendState.ResetRecvd
        ) {
            return false
        }
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

    private fun removeLost(i: Int) = removeLost(i, i + 1)

    /** Removes the pairs [from] until [to] of [lost]. */
    private fun removeLost(
        from: Int,
        to: Int,
    ) {
        if (to <= from) return
        lost.copyInto(lost, 2 * from, 2 * to, 2 * lostCount)
        lostCount -= to - from
    }

    private fun insertLost(
        i: Int,
        start: Long,
        end: Long,
    ) {
        if (2 * lostCount + 2 > lost.size) lost = lost.copyOf(lost.size * 2)
        lost.copyInto(lost, 2 * i + 2, 2 * i, 2 * lostCount)
        lost[2 * i] = start
        lost[2 * i + 1] = end
        lostCount++
    }

    /** The index of the first of [count] ascending (start, end) pairs in [ranges] that ends above [pos]; [count] when none does. */
    private fun firstEndingAbove(
        ranges: LongArray,
        count: Int,
        pos: Long,
    ): Int {
        var lo = 0
        var hi = count
        while (lo < hi) {
            rangeStepsForTest++
            val mid = (lo + hi) ushr 1
            if (ranges[2 * mid + 1] > pos) hi = mid else lo = mid + 1
        }
        return lo
    }

    fun onLost(
        offset: Long,
        len: Int,
        fin: Boolean = false,
    ) {
        if (state == SendState.ResetSent || state == SendState.ResetRecvd) return
        // queue only what is not acknowledged: the gaps between the acknowledged ranges inside [offset, offset + len)
        var start = maxOf(offset, releasedUpTo)
        // after RESET_STREAM_AT only the bytes below the reliable size are delivered
        val end = if (state == SendState.ResetAt) minOf(offset + len, reliableSize) else offset + len
        var a = firstEndingAbove(ackedRanges, ackedCount, start)
        while (start < end) {
            rangeStepsForTest++
            if (a < ackedCount && ackedRanges[2 * a] <= start) {
                start = ackedRanges[2 * a + 1]
                a++
                continue
            }
            val gapEnd = if (a < ackedCount) minOf(end, ackedRanges[2 * a]) else end
            addLost(start, gapEnd)
            start = gapEnd
        }
        if (fin && !finAcked && state != SendState.ResetAt) {
            finSent = false
            if (state == SendState.DataSent) state = SendState.Send
        }
    }

    /**
     * Queues [start, end) for retransmission, merged with the ranges it overlaps or touches. The same range can be declared lost
     * twice (an original and its PTO probe): the queue stays a set of disjoint ranges, or one packet would carry the bytes twice
     * and a peer like quiche fails the handshake on the duplicate.
     */
    private fun addLost(
        start: Long,
        end: Long,
    ) {
        var s = start
        var e = end
        val i = firstEndingAbove(lost, lostCount, s - 1) // the first range ending at or after s
        var j = i
        while (j < lostCount && lost[2 * j] <= e) {
            rangeStepsForTest++
            s = minOf(s, lost[2 * j])
            e = maxOf(e, lost[2 * j + 1])
            j++
        }
        if (j == i) {
            insertLost(i, s, e)
            return
        }
        lost[2 * i] = s
        lost[2 * i + 1] = e
        removeLost(i + 1, j)
    }

    /** Takes the acknowledged [start, end) out of the retransmission queue: what was lost and then acknowledged is not resent. */
    private fun removeAckedFromLost(
        start: Long,
        end: Long,
    ) {
        var i = firstEndingAbove(lost, lostCount, start)
        if (i < lostCount && lost[2 * i] < start) {
            if (lost[2 * i + 1] > end) { // the acknowledged bytes are inside this range: split it
                insertLost(i + 1, end, lost[2 * i + 1])
                lost[2 * i + 1] = start
                return
            }
            lost[2 * i + 1] = start
            i++
        }
        var j = i
        while (j < lostCount && lost[2 * j + 1] <= end) {
            rangeStepsForTest++
            j++
        }
        removeLost(i, j)
        if (i < lostCount && lost[2 * i] < end) lost[2 * i] = end
    }

    /** Returns the number of buffered bytes released. */
    fun onAcked(
        offset: Long,
        len: Int,
        fin: Boolean = false,
    ): Long {
        if (fin) finAcked = true
        if (len > 0) {
            addAcked(offset, offset + len)
            if (lostCount > 0) removeAckedFromLost(offset, offset + len)
        }
        var released = 0L
        if (ackedCount > 0 && ackedRanges[0] <= releasedUpTo &&
            ackedRanges[1] > releasedUpTo
        ) {
            // bytes past [written] are not in the buffer: RESET_STREAM_AT dropped them after they were sent
            released = maxOf(0L, minOf(ackedRanges[1], written) - releasedUpTo)
            releasedUpTo = ackedRanges[1]
        }
        if (released > 0) head = ((head + released) % ring.size).toInt()
        buffered -= released
        if (finAcked && buffered == 0L && finQueued) state = SendState.DataRecvd
        // the reliable part arrived and the frame went out
        if (state == SendState.ResetAt && releasedUpTo >= reliableSize && resetAtFinalSize >= 0) state = SendState.ResetSent
        return released
    }

    private fun addAcked(
        start: Long,
        end: Long,
    ) {
        val i = firstEndingAbove(ackedRanges, ackedCount, start - 1) // the first range ending at or after start
        var j = i
        var s = start
        var e = end
        while (j < ackedCount && ackedRanges[2 * j] <= e) {
            rangeStepsForTest++
            s = minOf(s, ackedRanges[2 * j])
            e = maxOf(e, ackedRanges[2 * j + 1])
            j++
        }
        if (j == i) {
            if (2 * ackedCount + 2 > ackedRanges.size) ackedRanges = ackedRanges.copyOf(ackedRanges.size * 2)
            ackedRanges.copyInto(ackedRanges, 2 * i + 2, 2 * i, 2 * ackedCount)
            ackedCount++
        } else if (j > i + 1) {
            ackedRanges.copyInto(ackedRanges, 2 * i + 2, 2 * j, 2 * ackedCount)
            ackedCount -= j - i - 1
        }
        ackedRanges[2 * i] = s
        ackedRanges[2 * i + 1] = e
    }

    /**
     * RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset section 3): the bytes below [reliable] (at most [written]) keep
     * being sent and retransmitted, everything after them is dropped, and no FIN goes out. Returns the buffered bytes
     * released. The stream is [SendState.ResetSent] at once when those bytes were all acknowledged already.
     */
    fun resetAt(
        reliable: Long,
        code: Long,
    ): Long {
        require(reliable in 0..written) { "reliable size $reliable outside 0..$written" }
        resetAtCode = code
        reliableSize = reliable
        finQueued = false
        finSent = false
        val keep = maxOf(reliable, releasedUpTo)
        val released = written - keep
        written = keep
        buffered -= released
        // retransmissions only below the reliable size
        var i = 0
        while (i < lostCount) {
            if (lost[2 * i] >= reliable) {
                lostCount = i
                break
            }
            if (lost[2 * i + 1] > reliable) lost[2 * i + 1] = reliable
            i++
        }
        state = SendState.ResetAt // ResetSent once the reliable bytes are acknowledged ([onAcked]) and the frame went out
        return released
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
