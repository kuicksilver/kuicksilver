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
 * also releases the dispatcher's thread while the socket is idle. [maxWait] is zero where a short poll timeout is not
 * precise (Windows: whole timer ticks of 15.6 ms), so only what is already queued is taken there.
 *
 * The work queued on the loop (timers, the application's reads and writes) runs as often as with the blocking receive,
 * which suspended after at most [YIELD_DATAGRAMS] datagrams: the receiver yields once it took that many directly, once
 * [YIELD_INTERVAL] passed since its last yield, and when a timer is due. Not after every batch: a paced sender's batches
 * hold a few datagrams, and an application reading the stream would be woken for each. Not less often either: an
 * application read that extends the stream's flow-control credit only every 2 ms stalls a fast sender (a first version
 * made kuicksilver -> kuicksilver 2.6 times slower). A command posted during a wait runs after it, at most [maxWait] later.
 */
internal class BatchReceiver(
    private val io: DatagramIo,
    private val now: () -> TimeMark,
    private val maxWait: Duration = if (millisecondPollWaits) DEFAULT_WAIT else Duration.ZERO,
) {
    private val direct = io as? DirectReceive

    /** The last receive brought datagrams: the next ones are likely close behind. */
    private var flowing = false

    /** Datagrams taken directly since the receiver last let the loop's queued work run, and when that was. */
    private var sinceYield = 0
    private var lastYield = TimeMark(0)

    /** Batches taken on the loop's thread (tests, diagnostics). */
    var directBatches = 0L
        private set

    /** Receives into [into] like [DatagramIo.receive]; [untilTimer] answers the time left until the loop's next timer. */
    suspend fun receive(
        into: PacketBatch,
        untilTimer: () -> Duration,
    ): Int {
        if (direct != null && flowing) {
            if (sinceYield >= YIELD_DATAGRAMS || now() - lastYield >= YIELD_INTERVAL || untilTimer() <= Duration.ZERO) {
                yield()
                yielded()
            }
            var n = direct.receiveNow(into, 0)
            if (n == 0) {
                val wait = minOf(maxWait, untilTimer()).inWholeMilliseconds
                if (wait > 0) n = direct.receiveNow(into, wait.toInt())
            }
            if (n > 0) {
                sinceYield += n
                directBatches++
                return n
            }
        }
        val n = io.receive(into) // suspends: the loop's queued work runs meanwhile
        yielded()
        flowing = n > 0
        return n
    }

    private fun yielded() {
        sinceYield = 0
        lastYield = now()
    }

    companion object {
        /** Long enough for the gaps between a paced sender's bursts (under 0.2 ms from quinn at 0.9 Gbit/s), short for a command. */
        val DEFAULT_WAIT: Duration = 1.milliseconds

        /** The blocking receive's batch (the loop's 16 slots): queued work ran at least this often. */
        const val YIELD_DATAGRAMS = 16

        /** Queued work waits no longer than this for a flow of a few datagrams per batch. */
        val YIELD_INTERVAL: Duration = 1.milliseconds
    }
}
