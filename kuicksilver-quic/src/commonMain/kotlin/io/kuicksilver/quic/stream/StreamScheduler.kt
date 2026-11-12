// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.quic.StreamPriority

/**
 * Chooses the next stream to send from (RFC 9218 at the transport): streams opened with [StreamPriority.Critical] first
 * (retransmissions, then by ascending id), then strict urgency order; within a level retransmissions first, then new data,
 * where non-incremental streams go by ascending id (section 10: "in ascending order of the stream ID") and incremental
 * streams round-robin (section 10: "sharing bandwidth among them").
 *
 * Two exceptions keep a stream from starving. Within one level the incremental and the non-incremental streams take turns,
 * frame by frame, as quic-go does: section 10 warns that "early non-incremental responses might prevent the serving of
 * incremental responses issued later" and recommends that servers "avoid such starvation". And a stream marked as a
 * [tunnel][SendStream.tunnel] gets one frame in [TUNNEL_TURN] whatever its urgency, once no critical stream has data
 * (section 10.1: "servers SHOULD allocate some amount of bandwidths to streams acting as tunnels"); tunnels take that
 * turn round-robin.
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
    private var nonEmpty = 0L

    /** Bit `p` is set when the last frame sent from the queue pair `2p`, `2p + 1` came from its incremental queue. */
    private var lastIncremental = 0

    /** The scheduled [tunnel][SendStream.tunnel] streams, in the order of their tunnel turns. */
    private var tunnelHead: SendStream? = null
    private var tunnelTail: SendStream? = null

    /** Frames sent from other streams since a tunnel last sent one while a tunnel was scheduled. */
    private var sinceTunnel = 0

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

    val isEmpty: Boolean get() = nonEmpty == 0L

    fun next(): SendStream? {
        while (nonEmpty != 0L) {
            var q = nonEmpty.countTrailingZeroBits()
            val tunnel = tunnelHead
            val s =
                if (q >= CRITICAL_QUEUES && tunnel != null && sinceTunnel >= TUNNEL_TURN - 1) {
                    q = tunnel.schedQueue
                    tunnel
                } else {
                    // a level's incremental queue takes every other frame while its non-incremental one has data
                    if (q and 1 == 0 && nonEmpty and (1L shl (q + 1)) != 0L && lastIncremental and (1 shl (q shr 1)) == 0) q++
                    if (q and 1 == 0) heaps[q]!![0] else heads[q]!!
                }
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

    /**
     * [s], the stream [next] chose, sent a frame: it leaves when it has nothing more to send, an incremental stream goes to
     * the back of its queue, and the turns between incremental and non-incremental streams and of the tunnels advance.
     */
    fun onSent(s: SendStream) {
        val q = s.schedQueue
        if (q < 0) return
        lastIncremental = if (q and 1 != 0) lastIncremental or (1 shl (q shr 1)) else lastIncremental and (1 shl (q shr 1)).inv()
        if (s.tunnel) {
            sinceTunnel = 0
            if (s !== tunnelTail) {
                unlinkTunnel(s)
                linkTunnel(s)
            }
        } else if (tunnelHead != null) {
            sinceTunnel++
        }
        if (!s.hasPending) {
            detach(s)
        } else if (q and 1 != 0) {
            rotate(s)
        }
    }

    /** Marks [s] as a [tunnel][SendStream.tunnel] (RFC 9218 section 10.1); it keeps its place in its queue. */
    fun markTunnel(s: SendStream) {
        if (s.tunnel) return
        s.tunnel = true
        if (s.schedQueue >= 0) linkTunnel(s)
    }

    /** Queues 0 and 2 (heaps) hold the critical streams; the eight urgencies follow from 4, four queues each. */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    private fun queueOf(s: SendStream): Int =
        if (s.priority === StreamPriority.Critical) {
            if (s.hasRetransmit) 0 else 2
        } else {
            CRITICAL_QUEUES + s.priority.urgency * 4 + (if (s.hasRetransmit) 0 else 2) + (if (s.priority.incremental) 1 else 0)
        }

    private fun insert(
        s: SendStream,
        q: Int,
    ) {
        s.schedQueue = q
        if (s.tunnel) linkTunnel(s)
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
        nonEmpty = nonEmpty or (1L shl q)
    }

    private fun detach(s: SendStream) {
        val q = s.schedQueue
        s.schedQueue = -1
        if (s.tunnel) unlinkTunnel(s)
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
            if (h.isEmpty()) nonEmpty = nonEmpty and (1L shl q).inv()
        } else {
            val p = s.schedPrev
            val n = s.schedNext
            if (p == null) heads[q] = n else p.schedNext = n
            if (n == null) tails[q] = p else n.schedPrev = p
            s.schedPrev = null
            s.schedNext = null
            if (heads[q] == null) nonEmpty = nonEmpty and (1L shl q).inv()
        }
    }

    private fun linkTunnel(s: SendStream) {
        s.tunnelPrev = tunnelTail
        s.tunnelNext = null
        tunnelTail?.tunnelNext = s
        tunnelTail = s
        if (tunnelHead == null) tunnelHead = s
    }

    private fun unlinkTunnel(s: SendStream) {
        val p = s.tunnelPrev
        val n = s.tunnelNext
        if (p == null) tunnelHead = n else p.tunnelNext = n
        if (n == null) tunnelTail = p else n.tunnelPrev = p
        s.tunnelPrev = null
        s.tunnelNext = null
        if (tunnelHead == null) sinceTunnel = 0
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

    internal companion object {
        /** The critical streams' (retransmission, new data) heaps, with the two list slots between them unused. */
        private const val CRITICAL_QUEUES = 4

        /** The critical queues, then eight urgencies times (retransmission, incremental); fits the Long mask. */
        private const val QUEUES = CRITICAL_QUEUES + 32

        /**
         * A scheduled tunnel sends at least one frame in this many (about 6 %) while no critical stream has data, however
         * urgent the other streams are: "some amount of bandwidths" (RFC 9218 section 10.1) that leaves urgency in charge.
         */
        const val TUNNEL_TURN = 16
    }
}
