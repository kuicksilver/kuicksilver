// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

/**
 * Chooses the next stream to send from (RFC 9218 at the transport): strict urgency order; within a level
 * retransmissions first, then non-incremental streams by ascending id, then incremental streams round-robin.
 *
 * The peer's stream limit decides how many streams can be live (RFC 9000 section 21.6), so nothing here walks them all: every
 * (urgency, retransmission, incremental) pair is a queue of its own — a binary min-heap by id for non-incremental streams, an
 * intrusive FIFO list for incremental ones — and a bit mask finds the first non-empty queue. A stream records its queue and slot,
 * so membership is O(1), [add] and [remove] O(log n), [rotate] O(1). A stream whose state changed while queued (its retransmissions
 * were acknowledged, its data ran out) is refiled or dropped when it reaches the front in [next]. quiche keeps the same order in an
 * intrusive red-black tree, quic-go per-urgency ring buffers of incremental streams.
 */
internal class StreamScheduler {
    private val heaps = arrayOfNulls<ArrayList<SendStream>>(QUEUES)
    private val heads = arrayOfNulls<SendStream>(QUEUES)
    private val tails = arrayOfNulls<SendStream>(QUEUES)

    /** Bit `q` is set while queue `q` is non-empty. */
    private var nonEmpty = 0

    /** Stream comparisons made by the heaps, for the complexity tests. */
    internal var comparisonsForTest = 0L

    /** Calls of [add], for the complexity tests. */
    internal var addsForTest = 0L

    /** Schedules [s]; a no-op when it already is. */
    fun add(s: SendStream) {
        addsForTest++
        if (s.schedQueue < 0) insert(s, queueOf(s))
    }

    fun remove(s: SendStream) {
        if (s.schedQueue >= 0) detach(s)
    }

    /** Files [s] again after its priority or retransmission state changed (or schedules it). */
    fun reschedule(s: SendStream) {
        val q = queueOf(s)
        if (s.schedQueue == q) return
        if (s.schedQueue >= 0) detach(s)
        insert(s, q)
    }

    val isEmpty: Boolean get() = nonEmpty == 0

    fun next(): SendStream? {
        while (nonEmpty != 0) {
            val q = nonEmpty.countTrailingZeroBits()
            val s = if (q and 1 == 0) heaps[q]!![0] else heads[q]!!
            if (!s.hasPending) {
                detach(s)
                continue
            }
            val want = queueOf(s)
            if (want != q) {
                detach(s)
                insert(s, want)
                continue
            }
            return s
        }
        return null
    }

    /** Moves an incremental stream to the back of its queue after it sent a frame. */
    fun rotate(s: SendStream) {
        if (s.schedQueue < 0) return
        detach(s)
        insert(s, queueOf(s))
    }

    private fun queueOf(s: SendStream): Int =
        s.priority.urgency * 4 + (if (s.hasRetransmit) 0 else 2) + (if (s.priority.incremental) 1 else 0)

    private fun insert(
        s: SendStream,
        q: Int,
    ) {
        s.schedQueue = q
        if (q and 1 == 0) {
            val h = heaps[q] ?: ArrayList<SendStream>().also { heaps[q] = it }
            h += s
            siftUp(h, h.size - 1)
        } else {
            s.schedPrev = tails[q]
            s.schedNext = null
            tails[q]?.schedNext = s
            tails[q] = s
            if (heads[q] == null) heads[q] = s
        }
        nonEmpty = nonEmpty or (1 shl q)
    }

    private fun detach(s: SendStream) {
        val q = s.schedQueue
        s.schedQueue = -1
        if (q and 1 == 0) {
            val h = heaps[q]!!
            val i = s.schedIndex
            val last = h.removeAt(h.size - 1)
            if (i < h.size) {
                h[i] = last
                last.schedIndex = i
                siftDown(h, i)
                siftUp(h, last.schedIndex)
            }
            if (h.isEmpty()) nonEmpty = nonEmpty and (1 shl q).inv()
        } else {
            val p = s.schedPrev
            val n = s.schedNext
            if (p == null) heads[q] = n else p.schedNext = n
            if (n == null) tails[q] = p else n.schedPrev = p
            s.schedPrev = null
            s.schedNext = null
            if (heads[q] == null) nonEmpty = nonEmpty and (1 shl q).inv()
        }
    }

    private fun siftUp(
        h: ArrayList<SendStream>,
        from: Int,
    ) {
        var i = from
        val s = h[i]
        while (i > 0) {
            val parent = (i - 1) / 2
            comparisonsForTest++
            if (h[parent].id <= s.id) break
            h[i] = h[parent]
            h[i].schedIndex = i
            i = parent
        }
        h[i] = s
        s.schedIndex = i
    }

    private fun siftDown(
        h: ArrayList<SendStream>,
        from: Int,
    ) {
        var i = from
        val s = h[i]
        while (true) {
            var c = 2 * i + 1
            if (c >= h.size) break
            comparisonsForTest++
            if (c + 1 < h.size && h[c + 1].id < h[c].id) c++
            comparisonsForTest++
            if (s.id <= h[c].id) break
            h[i] = h[c]
            h[i].schedIndex = i
            i = c
        }
        h[i] = s
        s.schedIndex = i
    }

    private companion object {
        /** Eight urgencies times (retransmission, incremental). */
        const val QUEUES = 32
    }
}
