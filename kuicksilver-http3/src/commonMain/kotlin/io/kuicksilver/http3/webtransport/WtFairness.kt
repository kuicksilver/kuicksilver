// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.kuicksilver.quic.QuicStream
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * One shared resource of a connection taken in turns by its WebTransport sessions: the fairness scheme of
 * draft-ietf-webtrans-http3-17 section 8, "WebTransport endpoints SHOULD implement a fairness scheme that ensures that each
 * session that shares a transport connection gets a reasonable share of controlled resources; this applies both to
 * sending data and to opening new streams".
 *
 * Weighted deficit round robin: one user at a time; the sessions waiting are visited in a ring, each visit adds [quantum]
 * times the session's weight to its deficit, and the session's waiters are served while their cost fits it. The weight
 * follows the urgency of the session's CONNECT stream (section 3.4, RFC 9218): 8 - urgency, so a session at urgency 0 gets
 * eight times the share of one at 7, and none waits more than one round. Urgency is a preference here, never strict: the
 * sessions are separate trust domains and the client sets their urgency, so a strict order would let one session starve
 * the others (RFC 9218 section 10, "it is RECOMMENDED that servers avoid such starvation where possible", and its section
 * 13.1 on round robin between connections of different clients sharing one). The weight is read again at every request,
 * so a PRIORITY_UPDATE takes effect while a session keeps waiting. A session gets its share by cost (bytes for data, one
 * per stream for opens) however many writers or openers it has; one that stops waiting leaves the ring with its deficit.
 * Every cost must be at most [quantum].
 *
 * Datagrams and the capsules of a session's CONNECT stream are not taken in turns: a capsule is a few bytes, and a
 * datagram goes to QUIC's datagram queue, which drops the oldest when full, so one session's burst can push out other
 * sessions' datagrams (unreliable by design, RFC 9221), never stall their streams.
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

    private class Session(
        val key: Any,
    ) {
        val waiters = ArrayDeque<Waiter>()
        var deficit = 0L
        var visited = false
        var weight = 1
    }

    private val ring = ArrayDeque<Session>()
    private val sessions = HashMap<Any, Session>()
    private var busy = false

    /** Grants handed out so far, by session key (a test hook). */
    val grantsForTest = ArrayList<Any>()

    /** Nobody holds or waits for a turn (a test hook). */
    val idleForTest: Boolean get() = !busy && sessions.isEmpty() && ring.isEmpty()

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
        val s = sessions.getOrPut(key) { Session(key).also { ring.addLast(it) } }
        s.weight = 8 - urgency.coerceIn(0, 7)
        s.waiters.addLast(w)
        dispatch()
        try {
            w.granted.await()
        } catch (e: CancellationException) {
            if (w.granted.isCompleted) {
                release()
            } else {
                s.waiters.remove(w)
                if (s.waiters.isEmpty()) leave(s)
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

    private fun leave(s: Session) {
        sessions.remove(s.key)
        ring.remove(s)
    }

    private fun dispatch() {
        if (busy) return
        while (true) {
            val s = ring.firstOrNull() ?: return
            val w = s.waiters.first()
            if (!s.visited) {
                s.deficit += quantum * s.weight
                s.visited = true
            }
            if (s.deficit >= w.cost) {
                s.deficit -= w.cost
                s.waiters.removeFirst()
                // out of the ring with its deficit (deficit round robin): a session that is back starts afresh
                if (s.waiters.isEmpty()) leave(s)
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

/**
 * A session's part of its connection's send buffer (QUIC's `maxSendBuffer`, the bytes of all streams written and not yet
 * acknowledged), so a session whose peer never reads a stream holds only its part and the others keep writing (section 8:
 * one session "aggressively using up those resources can cause other sessions to stall"). A [reserve] of the [buffer]
 * stays free for a session that joins; the rest is split between the [sessions] with flow control open on the
 * connection: a session alone gets all of it, and the parts always add up to the buffer less the reserve, so a newcomer
 * finds the reserve free at once. A session over its part (the others joined after it took more) waits outside the turn
 * ([WtSendTurns]) until the transport released enough. A session with nothing in the buffer may always write one chunk,
 * so a part smaller than a chunk still moves. Session dispatcher only.
 */
internal class WtSendShare(
    private val buffer: Long,
    private val reserve: Long,
    private val sessions: StateFlow<Int>,
) {
    /** The part of a session among [n]. */
    private fun capFor(n: Int): Long = maxOf(WtFairness.SEND_QUANTUM, (buffer - reserve) / maxOf(1, n))

    /** The session's part now. */
    val cap: Long get() = capFor(sessions.value)

    /** Bytes of the session written and not yet released by the transport. */
    val held = MutableStateFlow(0L)

    /** One stream's bytes in the share. */
    class Account(
        val headerLength: Int,
    ) {
        var counted = 0L
        var released = 0L
        var settled = false
    }

    fun fits(cost: Long): Boolean = held.value == 0L || held.value + cost <= cap

    /** Waits until [cost] more bytes fit the part, which shrinks as sessions join and grows as they leave. */
    suspend fun awaitRoom(cost: Long) {
        combine(held, sessions) { h, n -> h == 0L || h + cost <= capFor(n) }.first { it }
    }

    fun take(
        a: Account,
        cost: Long,
    ) {
        a.counted += cost
        held.value += cost
    }

    /** The transport released [total] bytes of [a]'s stream so far, its header first. */
    fun released(
        a: Account,
        total: Long,
    ) {
        if (a.settled) return
        val body = minOf(maxOf(0L, total - a.headerLength), a.counted)
        if (body > a.released) {
            held.value -= body - a.released
            a.released = body
        }
    }

    /** [a]'s stream is over (every byte released, or the connection gone): nothing of it counts any more. */
    fun settle(a: Account) {
        if (a.settled) return
        a.settled = true
        held.value -= a.counted - a.released
        a.released = a.counted
    }
}

/**
 * A session's turns at its connection's send buffer (section 8): it waits for room in its [share] outside the turn, then
 * writes in the [queue]'s turn at the session's current [urgency].
 */
internal class WtSendTurns(
    private val key: Any,
    private val urgency: () -> Int,
    private val queue: WtFairQueue,
    val share: WtSendShare,
) {
    /**
     * Follows [st]'s bytes in the send buffer ([QuicStream.sendReleased]) in [scope] until all of them were released, or
     * the stream or the connection ended; [headerLength] bytes of it came before the body.
     */
    fun follow(
        scope: CoroutineScope,
        st: QuicStream,
        headerLength: Int,
    ): WtSendShare.Account {
        val a = WtSendShare.Account(headerLength)
        val released = st.sendReleased
        scope.launch {
            try {
                if (released == null) {
                    runCatching { st.sentFinalSize?.await() }
                    return@launch
                }
                val follower = launch { released.collect { share.released(a, it) } }
                val f = runCatching { st.sentFinalSize?.await() }.getOrNull()
                if (f != null) released.first { it >= f }
                follower.cancel()
            } finally {
                share.settle(a)
            }
        }
        return a
    }

    /** Writes [cost] bytes of [a]'s stream with [block], in turn and within the session's share. */
    suspend fun run(
        a: WtSendShare.Account,
        cost: Long,
        block: suspend () -> Unit,
    ) {
        while (true) {
            share.awaitRoom(cost)
            val wrote =
                queue.inTurn(key, urgency(), cost) {
                    // another writer of the session took the room meanwhile: wait again, outside the turn
                    if (!share.fits(cost)) return@inTurn false
                    share.take(a, cost)
                    block()
                    true
                }
            if (wrote) return
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

    /** Nobody holds or waits for a turn in any queue (a test hook). */
    val idleForTest: Boolean get() = send.idleForTest && open.all { it.idleForTest }

    companion object {
        /** The largest chunk a WebTransport stream hands to the transport at once. */
        const val SEND_QUANTUM: Long = 16_384
    }
}
