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
 * Streams of a [scheduling group][SchedGroup] (a WebTransport session's) are taken as one participant of their level's
 * incremental round robin: the group's turn sends a frame of its own next stream (non-incremental members by ascending
 * id, incremental ones in turn, the two kinds taking turns), then the group goes to the back. Sessions of the same
 * urgency thus share the bandwidth whatever their streams' ids, while RFC 9218's order holds within each session. Between
 * sessions this is a chosen resolution of two SHOULDs: RFC 9218 section 10 orders non-incremental streams of one urgency
 * by ascending id, while draft-ietf-webtrans-http3-16 section 8 (unchanged in -17 per the project's notes) asks for "a
 * fairness scheme that ensures that each session that shares a transport connection gets a reasonable share", its section
 * 3.4 that "Endpoints that prioritize WebTransport sessions need to consider how they interact with other sessions", and
 * RFC 9218 section 10 itself that servers "avoid such starvation" (docs/spec/rfc/9218.md). A tunnel keeps its own turn
 * and never joins a group; a WebTransport session's CONNECT stream (a tunnel, carrying its small control capsules) is
 * therefore outside its session's group, so its flow-control capsules never wait for the session's data.
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

    /**
     * The group's token for the (urgency, retransmission) pair of queue [q]: one participant of that level's incremental list
     * whether its members there are incremental, non-incremental or both. Made once per pair and kept with the group.
     */
    private fun tokenOf(
        g: SchedGroup,
        q: Int,
    ): SendStream {
        val base = q and 1.inv()
        return g.tokens.getOrPut(base) {
            SendStream(-1, StreamPriority.Default).also {
                it.tokenFor = g
                it.tokenQ = base
            }
        }
    }

    /**
     * The stream a list entry stands for: itself, or the group's next member for the token's pair: its non-incremental
     * members by id and its incremental ones in turn, the two kinds taking turns as a level's do (RFC 9218 section 10).
     */
    private fun resolve(e: SendStream): SendStream {
        val g = e.tokenFor ?: return e
        val base = e.tokenQ
        val plain = g.heaps[base]?.takeIf { it.isNotEmpty() }
        val inc = g.heaps[base + 1]?.takeIf { it.isNotEmpty() }
        if (inc != null && (plain == null || g.lastIncremental and (1 shl (base shr 1)) == 0)) return inc[0]
        return plain!![0]
    }

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
                    if (q and 1 == 0) heaps[q]!![0] else resolve(heads[q]!!)
                }
            if (!s.hasPending) {
                detach(s)
                continue
            }
            val want = queueOf(s)
            if (want != s.schedQueue) {
                detach(s)
                insert(s, want)
                continue
            }
            return s
        }
        return null
    }

    /**
     * Like [next], restricted to the queues of streams with bytes queued for retransmission (a PTO probe repairs loss first, RFC
     * 9002 section 6.2.4); the tunnel turn is not taken here. Null when no stream has a retransmission queued.
     */
    fun nextRetransmit(): SendStream? {
        while (true) {
            val m = nonEmpty and RETRANSMIT_QUEUES
            if (m == 0L) return null
            var q = m.countTrailingZeroBits()
            if (q and 1 == 0 && m and (1L shl (q + 1)) != 0L && lastIncremental and (1 shl (q shr 1)) == 0) q++
            val s = if (q and 1 == 0) heaps[q]!![0] else resolve(heads[q]!!)
            if (!s.hasPending) {
                detach(s)
                continue
            }
            val want = queueOf(s)
            if (want != s.schedQueue) {
                detach(s)
                insert(s, want)
                continue
            }
            return s
        }
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
        val g = s.group
        if (g != null && q >= CRITICAL_QUEUES) {
            // the group's turn in its level's incremental list: it goes to the back, its member by its own order, and its
            // incremental and non-incremental members take turns within it
            lastIncremental = lastIncremental or (1 shl (q shr 1))
            g.lastIncremental =
                if (q and 1 != 0) g.lastIncremental or (1 shl (q shr 1)) else g.lastIncremental and (1 shl (q shr 1)).inv()
            if (!s.hasPending) {
                detach(s)
            } else if (q and 1 != 0) {
                detach(s)
                insert(s, q) // an incremental member goes behind the session's other ones
            }
            g.tokens[q and 1.inv()]?.let { t ->
                if (t.schedQueue >= 0) {
                    val list = t.schedQueue
                    unlinkList(t)
                    linkList(t, list)
                }
            }
            if (tunnelHead != null) sinceTunnel++
            return
        }
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
        val g = s.group
        // a tunnel keeps its own turn (RFC 9218 section 10.1): StreamManager never puts one into a group
        check(!(s.tunnel && g != null)) { "stream ${s.id} is a tunnel and in a scheduling group" }
        if (g != null && q >= CRITICAL_QUEUES) {
            // a member: into its group's heap for the queue (by id, or by turn for incremental members); the group's token
            // joins the level's incremental list when the group has its first member there
            val h = g.heaps.getOrPut(q) { ArrayList() }
            s.schedSeq = if (q and 1 != 0) ++g.seq else s.id
            h += s
            siftUp(h, h.size - 1)
            val t = tokenOf(g, q)
            if (t.schedQueue < 0) linkList(t, q or 1)
            return
        }
        if (s.tunnel) linkTunnel(s)
        if (q and 1 == 0) {
            val h = heaps[q] ?: ArrayList<SendStream>().also { heaps[q] = it }
            s.schedSeq = s.id
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
        val g = s.group
        if (g != null && q >= CRITICAL_QUEUES && s.tokenFor == null) {
            s.schedQueue = -1
            val h = g.heaps[q]!!
            val i = s.schedIndex
            val last = h.removeAt(h.size - 1)
            if (i < h.size) {
                h[i] = last
                last.schedIndex = i
                siftDown(h, i)
                siftUp(h, last.schedIndex)
            }
            // the token leaves the list when the pair has no member left; it stays with the group for the next one
            val base = q and 1.inv()
            if (g.heaps[base].isNullOrEmpty() && g.heaps[base + 1].isNullOrEmpty()) {
                g.tokens[base]?.let { t -> if (t.schedQueue >= 0) unlinkList(t) }
            }
            return
        }
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

    /** Appends [s] (a group's token) to the incremental list [q]. */
    private fun linkList(
        s: SendStream,
        q: Int,
    ) {
        s.schedQueue = q
        s.schedPrev = tails[q]
        s.schedNext = null
        tails[q]?.schedNext = s
        tails[q] = s
        if (heads[q] == null) heads[q] = s
        nonEmpty = nonEmpty or (1L shl q)
    }

    /** Takes [s] (a group's token) off its incremental list. */
    private fun unlinkList(s: SendStream) {
        val q = s.schedQueue
        s.schedQueue = -1
        val p = s.schedPrev
        val n = s.schedNext
        if (p == null) heads[q] = n else p.schedNext = n
        if (n == null) tails[q] = p else n.schedPrev = p
        s.schedPrev = null
        s.schedNext = null
        if (heads[q] == null) nonEmpty = nonEmpty and (1L shl q).inv()
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
            if (h[parent].schedSeq <= s.schedSeq) break
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
            if (c + 1 < h.size && h[c + 1].schedSeq < h[c].schedSeq) c++
            comparisonsForTest++
            if (s.schedSeq <= h[c].schedSeq) break
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

        /** The queues of streams with a retransmission queued: 0 (critical) and, per urgency, the first two of its four. */
        private const val RETRANSMIT_QUEUES = 0x333333333L
    }
}

/**
 * A scheduling group: the streams of one WebTransport session ([StreamManager.setGroup]). In each of its queues the group is
 * one token in the level's incremental list, and its members wait in a heap of their own (by id, or by turn for incremental
 * members), so the sessions of one urgency take turns and each keeps RFC 9218's order within ([StreamScheduler]).
 */
internal class SchedGroup(
    val id: Long,
) {
    /** The streams that belong to the group (the manager drops the group with its last one). */
    internal var members = 0

    /** Per queue: the members scheduled there. */
    internal val heaps = HashMap<Int, ArrayList<SendStream>>()

    /** Per (urgency, retransmission) pair, by its even queue: the token that stands for the group in the level's list. */
    internal val tokens = HashMap<Int, SendStream>()

    /** Bit `p` is set when the group's last frame in the queue pair `2p`, `2p + 1` came from an incremental member. */
    internal var lastIncremental = 0

    /** The turn counter of incremental members. */
    internal var seq = 0L
}
