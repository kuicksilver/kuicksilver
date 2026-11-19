// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.native.PacketBuffer

/**
 * Buffering a frame would exceed the range limits. Not a protocol error: a peer that stayed within flow control gets
 * there through ordinary loss (every other packet lost within one round trip leaves one hole each), so the packet is
 * dropped unacknowledged instead (the peer resends it; data that fills a hole always merges and is always taken), and
 * memory stays bounded by the limits (RFC 9000 section 21.7).
 */
internal object ReassemblyFull : RuntimeException("too many reassembly ranges")

/**
 * Connection-wide count of reassembly ranges (4096 per connection), and of the bytes the reassembly buffers hold allocated,
 * read or not ([bytes]). Flow control bounds the bytes that are unread at any one time, not what stays allocated once they were
 * read (picoquic #2333 class): above [maxBytes] (the connection window) a read leaves its stream's buffer no larger than twice
 * what is still buffered in it, and a drained one is let go. The allocation is then at most [maxBytes] plus, per stream, twice
 * the span it still buffers or twice [Reassembler.MIN_WINDOW], whichever is more (a buffer grows by doubling).
 */
internal class RangeBudget(
    val max: Int,
    val maxBytes: Long = Long.MAX_VALUE,
) {
    var used: Int = 0
    var bytes: Long = 0
}

/**
 * Orders stream data (RFC 9000 section 2.2): bytes land in a window starting at the read offset, gaps are tracked as
 * sorted (start, end) ranges — at most [maxRanges] gaps per stream and the connection [budget] (plus, per stream, the range at the
 * read offset, which is always taken) — and only the contiguous prefix is readable. Refusal ([ReassemblyFull]) happens before
 * copying.
 */
internal class Reassembler(
    private val maxRanges: Int,
    private val budget: RangeBudget,
) {
    private var window = ByteArray(0)
    private var head = 0 // window index of stream offset [base]; reads advance it instead of shifting bytes
    private var base: Long = 0 // stream offset of window[head]

    /** Test hook: bytes copied inside the window (compactions), to prove reads do not shift the whole buffer. */
    internal var bytesMovedForTest: Long = 0
        private set
    internal val capacityForTest: Int get() = window.size
    private var ranges = LongArray(16) // (start, end) pairs, ascending, end exclusive, relative to the stream
    private var count = 0

    val rangeCount: Int get() = count

    /** Contiguous bytes available from the read offset. */
    val readable: Int get() = if (count > 0 && ranges[0] == base) (ranges[1] - base).toInt() else 0
    val readOffset: Long get() = base

    /** Bytes held between the read offset and the highest buffered byte (holes included: the window they occupy). */
    val bufferedBytes: Int get() = if (count > 0) (ranges[2 * (count - 1) + 1] - base).toInt() else 0

    /** Buffers [len] bytes at [offset]; false when every byte was already read or buffered (a duplicate). */
    fun insert(
        offset: Long,
        data: PacketBuffer,
        off: Int,
        len: Int,
    ): Boolean {
        if (len == 0) return false
        var start = offset
        var end = offset + len
        var srcOff = off
        if (end <= base) return false
        if (start < base) {
            srcOff += (base - start).toInt()
            start = base
        }
        // find the first range ending at or after start (ranges are sorted)
        var i = 0
        while (i < count && ranges[2 * i + 1] < start) i++
        val mergesIntoExisting = i < count && ranges[2 * i] <= end
        // wholly inside one buffered range: nothing new
        if (mergesIntoExisting && ranges[2 * i] <= start && ranges[2 * i + 1] >= end) return false
        // a frame at the read offset opens no gap and makes data readable, which is what frees ranges: it is always taken, or a
        // stream at its limit with nothing readable would refuse the peer's retransmissions of it until the idle timeout. The
        // limit counts gaps: at most one range more (the readable one at the read offset) per stream
        if (!mergesIntoExisting && start != base &&
            (count >= maxRanges || budget.used >= budget.max)
        ) {
            throw ReassemblyFull
        }
        ensureCapacity(end)
        data.copyTo(window, srcOff, head + (start - base).toInt(), (end - start).toInt())
        if (!mergesIntoExisting) {
            insertRange(i, start, end)
            budget.used++
            return true
        }
        // merge with every overlapping/adjacent range
        var s = minOf(start, ranges[2 * i])
        var e = maxOf(end, ranges[2 * i + 1])
        var j = i + 1
        while (j < count && ranges[2 * j] <= e) {
            e = maxOf(e, ranges[2 * j + 1])
            j++
        }
        val removed = j - i - 1
        ranges[2 * i] = s
        ranges[2 * i + 1] = e
        if (removed >
            0
        ) {
            for (k in i + 1 until count - removed) {
                ranges[2 * k] = ranges[2 * (k + removed)]
                ranges[2 * k + 1] =
                    ranges[2 * (k + removed) + 1]
            }
            count -= removed
            budget.used -= removed
        }
        return true
    }

    private fun insertRange(
        i: Int,
        start: Long,
        end: Long,
    ) {
        if (2 * count + 2 > ranges.size) ranges = ranges.copyOf(ranges.size * 2)
        for (k in count downTo i + 1) {
            ranges[2 * k] = ranges[2 * (k - 1)]
            ranges[2 * k + 1] = ranges[2 * (k - 1) + 1]
        }
        ranges[2 * i] = start
        ranges[2 * i + 1] = end
        count++
    }

    /** Replaces the buffer, keeping the connection's allocated-bytes count ([RangeBudget.bytes]) exact. */
    private fun setWindow(w: ByteArray) {
        budget.bytes += w.size.toLong() - window.size
        window = w
    }

    /**
     * Over the connection's allocation budget: shrinks the buffer to twice what it still holds (gaps included), as one copy, and
     * only when it is larger than that. Twice, not exactly: a stream read a little behind its window would otherwise shrink on
     * every read and double on the next frame, copying its whole backlog each time; with the factor a shrink or a growth needs
     * the held bytes to halve or double first, so the copies stay linear in the bytes delivered.
     */
    private fun shrinkToFit() {
        val buffered = bufferedBytes
        val target = 2 * maxOf(buffered, MIN_WINDOW)
        if (window.size <= target) return
        val w = ByteArray(target)
        window.copyInto(w, 0, head, head + buffered)
        bytesMovedForTest += buffered
        head = 0
        setWindow(w)
    }

    private fun ensureCapacity(end: Long) {
        val need = (end - base).toInt()
        if (head + need <= window.size) return
        val buffered = if (count > 0) (ranges[2 * (count - 1) + 1] - base).toInt() else 0
        if (need <= window.size) {
            window.copyInto(window, 0, head, head + buffered)
            bytesMovedForTest += buffered
            head = 0
            return
        } // compact in place: amortised, never per read
        // at least MIN_WINDOW: a stream that only ever carries a few bytes (HTTP/3's control and QPACK streams) keeps a small
        // window for the life of the connection, a larger one doubles to its working size within a few frames
        val grown = ByteArray(maxOf(need, window.size * 2, MIN_WINDOW))
        window.copyInto(grown, 0, head, head + buffered)
        bytesMovedForTest +=
            buffered
        setWindow(grown)
        head = 0
    }

    /** Copies up to [len] contiguous bytes; returns the count (0 when nothing contiguous is available). */
    fun read(
        into: ByteArray,
        off: Int,
        len: Int,
    ): Int {
        val n = minOf(len, readable)
        if (n == 0) return 0
        window.copyInto(into, off, head, head + n)
        base += n
        head += n
        if (ranges[1] ==
            base
        ) {
            for (k in 0 until count - 1) {
                ranges[2 * k] = ranges[2 * (k + 1)]
                ranges[2 * k + 1] = ranges[2 * (k + 1) + 1]
            }
            count--
            budget.used--
        } else {
            ranges[0] =
                base
        }
        if (count == 0) {
            head = 0
            // drained: a large window is not kept for the life of the stream, nor any window while the connection's buffers are over
            // their budget (each stream the peer filled once would otherwise keep its window: max_streams x the stream window)
            if (window.size > SHRINK_ABOVE || budget.bytes > budget.maxBytes) setWindow(EMPTY)
        } else if (budget.bytes > budget.maxBytes) {
            shrinkToFit() // a stream left with a gap and nothing readable is never read again: its large window goes now
        }
        return n
    }

    /** Drops everything (stream reset, or a stream that is done): its ranges and its allocation leave the connection's counts. */
    fun clear() {
        budget.used -= count
        count = 0
        head = 0
        setWindow(EMPTY)
    }

    internal companion object {
        const val SHRINK_ABOVE = 1 shl 20
        const val MIN_WINDOW = 512
        private val EMPTY = ByteArray(0)
    }
}
