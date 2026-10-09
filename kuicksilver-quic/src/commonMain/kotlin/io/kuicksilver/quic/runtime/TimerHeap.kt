// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.TimeMark

/**
 * The loop's timers: a binary min-heap of connections keyed by `nextTimeoutOrNever()`, so the timer coroutine looks at the
 * head instead of rescanning every connection. A connection's deadline only changes when the loop flushes it
 * (a datagram, a timer, a command), so the heap is updated for the dirty connections after each flush.
 */
internal class TimerHeap {
    private var items = arrayOfNulls<ConnectionCore>(64)
    private var size = 0

    val isEmpty: Boolean get() = size == 0

    fun peek(): ConnectionCore? = if (size == 0) null else items[0]

    /** Sets [c]'s deadline (NEVER removes it). */
    fun update(
        c: ConnectionCore,
        deadline: TimeMark,
    ) {
        if (deadline == TimeMark.NEVER) {
            remove(c)
            return
        }
        if (c.heapIndex <
            0
        ) {
            if (size ==
                items.size
            ) {
                items = items.copyOf(size * 2)
            }
            items[size] = c
            c.heapIndex = size
            c.heapDeadline = deadline
            size++
            up(c.heapIndex)
            return
        }
        val old = c.heapDeadline
        c.heapDeadline = deadline
        if (deadline < old) up(c.heapIndex) else down(c.heapIndex)
    }

    fun remove(c: ConnectionCore) {
        val i = c.heapIndex
        if (i < 0) return
        val removed = c.heapDeadline
        size--
        val last = items[size]!!
        items[size] = null
        c.heapIndex = -1
        c.heapDeadline = TimeMark.NEVER
        if (last !==
            c
        ) {
            items[i] = last
            last.heapIndex = i
            if (last.heapDeadline <
                removed
            ) {
                up(i)
            } else {
                down(i)
            }
        } // compared against the hole's old key, never the reset one
    }

    private fun swap(
        a: Int,
        b: Int,
    ) {
        val x = items[a]!!
        val y = items[b]!!
        items[a] = y
        y.heapIndex = a
        items[b] = x
        x.heapIndex = b
    }

    private fun up(from: Int) {
        var i = from
        while (i >
            0
        ) {
            val p = (i - 1) / 2
            if (items[i]!!.heapDeadline < items[p]!!.heapDeadline) {
                swap(i, p)
                i = p
            } else {
                break
            }
        }
    }

    private fun down(from: Int) {
        var i = from
        while (true) {
            val l = 2 * i + 1
            val r = l + 1
            var m = i
            if (l < size && items[l]!!.heapDeadline < items[m]!!.heapDeadline) m = l
            if (r < size && items[r]!!.heapDeadline < items[m]!!.heapDeadline) m = r
            if (m == i) return
            swap(i, m)
            i = m
        }
    }
}
