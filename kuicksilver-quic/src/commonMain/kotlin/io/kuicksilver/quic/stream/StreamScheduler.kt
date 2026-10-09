// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

/**
 * Chooses the next stream to send from (RFC 9218 at the transport): strict urgency order; within a level
 * retransmissions first, then non-incremental streams by ascending id, then incremental streams round-robin.
 */
internal class StreamScheduler {
    private val active = ArrayList<SendStream>()

    fun add(s: SendStream) {
        if (!active.contains(s)) active += s
    }

    fun remove(s: SendStream) {
        active.remove(s)
    }

    fun contains(s: SendStream): Boolean = active.contains(s)

    val isEmpty: Boolean get() = active.isEmpty()

    fun next(): SendStream? {
        var best: SendStream? = null
        for (i in active.indices) {
            val s = active[i]
            if (!s.hasPending) continue
            if (best == null || better(s, best)) best = s
        }
        return best
    }

    private fun better(
        a: SendStream,
        b: SendStream,
    ): Boolean {
        if (a.priority.urgency != b.priority.urgency) return a.priority.urgency < b.priority.urgency
        if (a.hasRetransmit != b.hasRetransmit) return a.hasRetransmit
        if (a.priority.incremental != b.priority.incremental) return !a.priority.incremental
        return if (a.priority.incremental) false else a.id < b.id // incremental: keep list order (round-robin via rotate)
    }

    /** Moves an incremental stream to the back of its level after it sent a frame. */
    fun rotate(s: SendStream) {
        if (active.remove(s)) active += s
    }

    fun markRetransmit(s: SendStream) {
        add(s)
    }
}
