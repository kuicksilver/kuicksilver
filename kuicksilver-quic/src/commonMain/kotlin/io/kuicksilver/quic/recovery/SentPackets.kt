// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

/**
 * The packets of one space still awaiting acknowledgement, in ascending packet number order (RFC 9002 appendix A.1).
 *
 * The peer decides what an ACK covers, so finding and removing packets must not cost a pass over everything in flight
 * (RFC 9000 section 21.6): [lowerBound] is a binary search over the packet numbers, a removal leaves a tombstone (the slot's
 * packet number stays, so the search still works), the front skips its tombstones, and the slots are compacted only when the
 * tombstones outnumber the live packets — each removal pays for O(1) compaction work. ngtcp2 keeps the same order in a skip list
 * (`ngtcp2_rtb`); a flat array keeps the hot path allocation-free.
 */
internal class SentPackets : Iterable<SentPacket> {
    private var pns = LongArray(16)
    private var slots = arrayOfNulls<SentPacket>(16)
    private var head = 0
    private var tail = 0

    /** Live packets. */
    var size: Int = 0
        private set

    /** Slots moved or skipped by [trim] and the growth of the array, for the complexity tests. */
    internal var workForTest = 0L

    fun isEmpty(): Boolean = size == 0

    /** First slot index (inclusive) of the occupied window. */
    val start: Int get() = head

    /** Slot index past the occupied window. */
    val end: Int get() = tail

    /** The packet number of slot [i] (kept for tombstones). */
    fun pnAt(i: Int): Long = pns[i]

    /** The packet in slot [i], or null for a tombstone. */
    fun at(i: Int): SentPacket? = slots[i]

    /** Appends [p]; packet numbers only grow within a space. */
    fun add(p: SentPacket) {
        if (tail == slots.size) makeRoom()
        pns[tail] = p.pn
        slots[tail++] = p
        size++
    }

    /** The first slot in `[start, end]` whose packet number is at least [pn] (binary search). */
    fun lowerBound(pn: Long): Int {
        var lo = head
        var hi = tail
        while (lo < hi) {
            val mid = (lo + hi) ushr 1
            if (pns[mid] < pn) lo = mid + 1 else hi = mid
        }
        return lo
    }

    /** Leaves a tombstone in slot [i]; call [trim] once the walk that removes packets is over. */
    fun removeAt(i: Int) {
        if (slots[i] == null) return
        slots[i] = null
        size--
    }

    /** Skips the tombstones at the front and compacts once they outnumber the live packets; returns the slots touched. */
    fun trim(): Int {
        var touched = 0
        while (head < tail && slots[head] == null) {
            head++
            touched++
        }
        if (head == tail) {
            head = 0
            tail = 0
        } else if (tail - head - size > size) {
            touched += compactTo(slots, pns)
        }
        workForTest += touched
        return touched
    }

    fun clear() {
        slots.fill(null, head, tail)
        head = 0
        tail = 0
        size = 0
    }

    override fun iterator(): Iterator<SentPacket> =
        object : Iterator<SentPacket> {
            private var i = skip(head)

            private fun skip(from: Int): Int {
                var k = from
                while (k < tail && slots[k] == null) k++
                return k
            }

            override fun hasNext(): Boolean = i < tail

            override fun next(): SentPacket {
                if (i >= tail) throw NoSuchElementException()
                val p = slots[i]!!
                i = skip(i + 1)
                return p
            }
        }

    private fun makeRoom() {
        if (size * 2 <= slots.size) {
            workForTest += compactTo(slots, pns)
        } else {
            val ns = arrayOfNulls<SentPacket>(slots.size * 2)
            val np = LongArray(slots.size * 2)
            workForTest += compactTo(ns, np)
            slots = ns
            pns = np
        }
    }

    /** Moves the live packets to the front of [ns]/[np] (which may be the current arrays) and makes those the window. */
    private fun compactTo(
        ns: Array<SentPacket?>,
        np: LongArray,
    ): Int {
        var w = 0
        for (k in head until tail) {
            val p = slots[k] ?: continue
            ns[w] = p
            np[w] = pns[k]
            w++
        }
        val moved = tail - head
        if (ns === slots) slots.fill(null, w, tail) else slots.fill(null)
        head = 0
        tail = w
        return moved
    }
}
