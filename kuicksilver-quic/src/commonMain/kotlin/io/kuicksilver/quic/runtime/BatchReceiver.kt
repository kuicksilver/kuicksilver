// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.DirectReceive
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.TimeMark
import kotlinx.coroutines.yield
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/**
 * Takes a loop's next batch from one socket. The blocking receive waits on a `Dispatchers.IO` thread and hands the batch back
 * to the loop's dispatcher: two thread hand-offs, and the parking and waking of the threads involved, per batch. When the
 * sender's datagrams arrive spread out (paced, or one `sendmsg` each) a batch holds a few datagrams, and those hand-offs
 * cost more CPU than the QUIC work: 18 s of CPU per GB for the JVM client receiving from quinn's interop server, half of
 * it system time, 0.6 million voluntary context switches per GiB (docs/benchmarks.md).
 *
 * So while datagrams keep coming, a socket with [DirectReceive] is read on the loop's own thread: what is queued already, or
 * what arrives within [maxWait] and before the loop's next timer. Only a longer gap goes back to the blocking receive, which
 * also releases the dispatcher's thread while the socket is idle. The wait is in whole milliseconds and floored: a timer
 * due within 1 ms makes it 0, so the receiver falls back to the blocking receive and its hand-offs; a paced sender whose
 * pacing or ACK timers fall that close gets less of the gain. [maxWait] is zero where a short poll timeout is not precise
 * (Windows: whole timer ticks of 15.6 ms), so only what is already queued is taken there, and on a dispatcher the caller
 * supplied (`QuicEndpointConfig.dispatcher`): other work shares its thread (a second endpoint, whose datagram this one would
 * be waiting for, or a UI), and a wait there would hold that work up for every quiet gap.
 *
 * The work queued on the loop (timers, the application's reads and writes) runs as often as with the blocking receive,
 * which suspended after at most [YIELD_DATAGRAMS] datagrams: the receiver yields once it took that many directly, once
 * [YIELD_INTERVAL] passed since its last yield, and when a timer is due. Not after every batch: a paced sender's batches
 * hold a few datagrams, and an application reading the stream would be woken for each. Not less often either: an
 * application read that extends the stream's flow-control credit only every 2 ms stalls a fast sender (a first version
 * made kuicksilver -> kuicksilver 2.6 times slower).
 *
 * On the loop's own dispatcher ([queued]) the receiver also yields as soon as any task was queued behind it, and does not
 * start a wait while one is: an application's write or read hops onto the loop (`withContext`), and one that waited for the
 * receiver's next 16 datagrams or 1 ms held a single connection over loopback to about 30 MiB/s with the sender idle (a
 * stream's writer hands over 16 KiB per hop; docs/benchmarks.md, "One connection over loopback"). A task queued while a
 * wait is already under way still runs after it: when a datagram arrives, at most [maxWait] later.
 */
internal class BatchReceiver(
    private val io: DatagramIo,
    private val now: LoopClock,
    internal val maxWait: Duration = PLATFORM_WAIT,
    /** The loop's own dispatcher, whose count of queued tasks tells whether work waits behind the receiver; null: not known. */
    private val queued: LoopDispatcher? = null,
) {
    /** The loop's clock: an interface, so reading it does not box the [TimeMark] as a `() -> TimeMark` would, once per batch. */
    fun interface LoopClock {
        fun now(): TimeMark
    }

    /** The time left until the loop's next timer, unboxed like [LoopClock]. */
    fun interface TimerHorizon {
        fun untilTimer(): Duration
    }

    private val direct = io as? DirectReceive

    /** The last receive brought datagrams: the next ones are likely close behind. */
    private var flowing = false

    /** Datagrams taken directly since the receiver last let the loop's queued work run, and when that was. */
    private var sinceYield = 0
    private var lastYield = TimeMark(0)

    /** [LoopDispatcher.dispatched] up to the receiver's last yield: the tasks queued until then have run. */
    private var accounted = 0L

    /** A task was queued on the loop's dispatcher since the receiver last let queued work run. */
    private fun workQueued(): Boolean = queued != null && queued.dispatched() > accounted

    /** Batches taken on the loop's thread (tests, diagnostics). */
    var directBatches = 0L
        private set

    /**
     * Receives into [into] like [DatagramIo.receive]; [untilTimer] answers the time left until the loop's next timer.
     * [directTried]: [receiveDirect] just tried the loop's thread and got nothing, so the blocking receive follows at once.
     */
    suspend fun receive(
        into: PacketBatch,
        untilTimer: TimerHorizon,
        directTried: Boolean = false,
    ): Int {
        if (direct != null && flowing && !directTried) {
            if (yieldDue(untilTimer)) yieldToQueued()
            val n = takeDirect(direct, into, untilTimer)
            if (n > 0) return n
        }
        val n = io.receive(into) // suspends: the loop's queued work runs meanwhile
        yielded()
        // the resumption was queued behind what was waiting then; a task queued after it is taken as run too (it then waits
        // for the next yield, as before the count existed)
        accounted = queued?.dispatched() ?: 0L
        flowing = n > 0
        return n
    }

    /**
     * The part of [receive] that does not suspend, so the loop calls it without a coroutine frame per batch: while datagrams
     * flow and no yield is due, the next batch on the loop's thread. [NOT_TRIED] when [receive] has to run instead (it yields
     * first, or waits on the blocking receive), [NOTHING] when the loop's thread got nothing (then `receive(directTried = true)`).
     */
    fun receiveDirect(
        into: PacketBatch,
        untilTimer: TimerHorizon,
    ): Int {
        if (direct == null || !flowing || yieldDue(untilTimer)) return NOT_TRIED
        val n = takeDirect(direct, into, untilTimer)
        return if (n > 0) n else NOTHING
    }

    private fun yieldDue(untilTimer: TimerHorizon): Boolean =
        workQueued() || sinceYield >= YIELD_DATAGRAMS || now.now() - lastYield >= YIELD_INTERVAL ||
            untilTimer.untilTimer() <= Duration.ZERO

    /**
     * Lets the work queued on the loop run. The yield queues the receiver itself behind it (one more dispatch, its own): what
     * was queued before has run when it returns, what is queued after it is still waiting.
     */
    suspend fun yieldToQueued() {
        val before = queued?.dispatched() ?: 0L
        yield()
        yielded()
        accounted = before + 1
    }

    /** What is queued, or what arrives within [maxWait] and before the next timer; 0 when nothing came. */
    private fun takeDirect(
        direct: DirectReceive,
        into: PacketBatch,
        untilTimer: TimerHorizon,
    ): Int {
        var n = direct.receiveNow(into, 0)
        if (n == 0 && !workQueued()) {
            val timer = untilTimer.untilTimer()
            val wait = (if (timer < maxWait) timer else maxWait).inWholeMilliseconds // not minOf: it boxes both Durations
            if (wait > 0) n = direct.receiveNow(into, wait.toInt())
        }
        if (n > 0) {
            sinceYield += n
            directBatches++
        }
        return n
    }

    private fun yielded() {
        sinceYield = 0
        lastYield = now.now()
    }

    companion object {
        /** [receiveDirect]: not tried, call [receive]. */
        const val NOT_TRIED = -1

        /** [receiveDirect]: tried, nothing came; call [receive] with `directTried = true`. */
        const val NOTHING = -2

        /** Long enough for the gaps between a paced sender's bursts (under 0.2 ms from quinn at 0.9 Gbit/s), short for a command. */
        val DEFAULT_WAIT: Duration = 1.milliseconds

        /** [DEFAULT_WAIT] where the platform's poll timeout is precise to the millisecond, else zero (Windows). */
        val PLATFORM_WAIT: Duration get() = if (millisecondPollWaits) DEFAULT_WAIT else Duration.ZERO

        /** The blocking receive's batch (the loop's 16 slots): queued work ran at least this often. */
        const val YIELD_DATAGRAMS = 16

        /** Queued work waits no longer than this for a flow of a few datagrams per batch. */
        val YIELD_INTERVAL: Duration = 1.milliseconds
    }
}
