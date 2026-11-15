// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred

/**
 * One shared resource of a connection taken in turns by its WebTransport sessions: the fairness scheme of
 * draft-ietf-webtrans-http3-16 section 8, "WebTransport endpoints SHOULD implement a fairness scheme that ensures that each
 * session that shares a transport connection gets a reasonable share of controlled resources; this applies both to
 * sending data and to opening new streams".
 *
 * Deficit round robin: one user at a time; the sessions waiting at the most urgent level (section 3.4: a session's
 * streams go at its CONNECT stream's urgency, so a more urgent session goes first, as RFC 9218 asks) are visited in a
 * ring, each visit adds [quantum] to the session's deficit, and the session's waiters are served while their cost fits
 * it. A session therefore gets its share by cost (bytes for data, one per stream for opens) however many writers or
 * openers it has, and a session that stops waiting leaves the ring with its deficit. Every cost must be at most
 * [quantum].
 *
 * Session dispatcher only: no locks.
 */
internal class WtFairQueue(
    private val quantum: Long,
) {
    private class Waiter(
        val cost: Long,
    ) {
        val granted = CompletableDeferred<Unit>()
    }

    private class Session {
        val waiters = ArrayDeque<Waiter>()
        var deficit = 0L
        var visited = false
    }

    /** Rings of sessions with waiters, by urgency (RFC 9218: 0, the most urgent, to 7). */
    private val rings = Array(8) { ArrayDeque<Session>() }
    private val sessions = HashMap<Any, Pair<Int, Session>>()
    private var busy = false

    /** Grants handed out so far, by session key (a test hook). */
    val grantsForTest = ArrayList<Any>()

    /**
     * Runs [block] in [key]'s turn at [urgency] for [cost] (at most [quantum]); waits for the turn first. Cancelled while
     * waiting: it leaves the queue; cancelled once granted: the turn passes on.
     */
    suspend fun <T> inTurn(
        key: Any,
        urgency: Int,
        cost: Long,
        block: suspend () -> T,
    ): T {
        require(cost in 1..quantum) { "cost $cost outside 1..$quantum" }
        val w = Waiter(cost)
        val (level, s) =
            sessions.getOrPut(key) {
                val s = Session()
                val u = urgency.coerceIn(0, 7)
                rings[u].addLast(s)
                u to s
            }
        s.waiters.addLast(w)
        dispatch()
        try {
            w.granted.await()
        } catch (e: CancellationException) {
            if (w.granted.isCompleted) {
                release()
            } else {
                s.waiters.remove(w)
                if (s.waiters.isEmpty()) leave(key, level, s)
            }
            throw e
        }
        grantsForTest += key
        try {
            return block()
        } finally {
            release()
        }
    }

    private fun release() {
        busy = false
        dispatch()
    }

    private fun leave(
        key: Any,
        level: Int,
        s: Session,
    ) {
        sessions.remove(key)
        rings[level].remove(s)
    }

    private fun dispatch() {
        if (busy) return
        while (true) {
            val level = rings.indexOfFirst { it.isNotEmpty() }
            if (level < 0) return
            val ring = rings[level]
            val s = ring.first()
            val w = s.waiters.first()
            if (!s.visited) {
                s.deficit += quantum
                s.visited = true
            }
            if (s.deficit >= w.cost) {
                s.deficit -= w.cost
                s.waiters.removeFirst()
                if (s.waiters.isEmpty()) {
                    // out of the ring with its deficit (deficit round robin): a session that is back starts afresh
                    val key = sessions.entries.first { it.value.second === s }.key
                    leave(key, level, s)
                }
                busy = true
                w.granted.complete(Unit)
                return
            }
            // its share of this round is used: the next session's turn
            s.visited = false
            ring.removeFirst()
            ring.addLast(s)
        }
    }
}

/** A connection's fair queues (section 8): opening streams of each kind (one per open), and the send buffer (by bytes). */
internal class WtFairness {
    private val open = arrayOf(WtFairQueue(1), WtFairQueue(1))

    /** Handing data to the transport: a quantum of one stream chunk. */
    val send = WtFairQueue(SEND_QUANTUM)

    /** Opening a stream of the kind. */
    fun opening(bidi: Boolean): WtFairQueue = open[if (bidi) 0 else 1]

    companion object {
        /** The largest chunk a WebTransport stream hands to the transport at once. */
        const val SEND_QUANTUM: Long = 16_384
    }
}

/** A session's turn at its connection's send buffer, for [cost] bytes. */
internal fun interface WtSendTurn {
    suspend fun run(
        cost: Long,
        block: suspend () -> Unit,
    )
}
