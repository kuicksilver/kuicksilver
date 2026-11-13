// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.DatagramPacketWriter
import io.kuicksilver.quic.DatagramPolicy
import io.kuicksilver.quic.DatagramSender
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch

/**
 * The send side of the datagram API: callers from any thread hand copies over through a bounded command
 * channel and atomic counters (so `trySendDatagram` never enters the loop); the loop applies the policies, keeps the queue
 * within [maxCount] / [maxBytes], and feeds the core as its [DatagramSender]. Nothing here is retransmitted (RFC 9221).
 *
 * The queue is one FIFO per urgency ([Cmd.urgency], -1 and RFC 9218's 0..7): the most urgent non-empty one goes first, so a
 * datagram never waits behind a less urgent one, and order is kept within an urgency, which is all RFC 9221 asks. One
 * [onTransmit] writes datagrams of one urgency only, the one [nextUrgency] announced to the packet builder.
 *
 * The channel holds at most [maxCount] commands and drops its oldest when a caller outruns the loop, so the commands, the
 * one command waiting for room and the queue together never exceed `2 × maxCount + 1` datagrams.
 * [DatagramPolicy.Reject] callers checked [hasRoom] (fewer than [maxCount] buffered in all), so they alone never overflow
 * the channel; only a concurrent DropOldest / LatestWins flood can push a datagram out, as the policy says.
 */
@OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)
internal class DatagramSendQueue(
    private val maxCount: Int,
    private val maxBytes: Long,
) : DatagramSender {
    internal class Cmd(
        val data: ByteArray,
        val policy: DatagramPolicy,
        /** RFC 9218 urgency for scheduling against stream data ([DatagramSender.nextUrgency]); -1: ahead of every stream. */
        val urgency: Int = -1,
    ) {
        /** Arrival order across the urgencies (loop only): eviction drops the oldest of all. */
        var seq = 0L
    }

    /** Commands from the application, applied on the loop; an overflow drops (and un-counts) the oldest. */
    val commands = Channel<Cmd>(maxCount, BufferOverflow.DROP_OLDEST) { release(it) }

    /** Wakes the loop-side drainer once per burst. */
    val signal = Channel<Unit>(Channel.CONFLATED)

    /** Datagrams queued and not yet sent, as seen from any thread (for Reject); the loop keeps them exact. */
    val count = AtomicInt(0)
    val bytes = AtomicLong(0)

    /** One FIFO per urgency, index urgency + 1; [nonEmpty] has bit i set while queue i holds a datagram. */
    private val queues = Array(URGENCIES) { ArrayDeque<Cmd>() }
    private var nonEmpty = 0
    private var queued = 0
    private var nextSeq = 0L

    private fun addLast(c: Cmd) {
        val i = c.urgency + 1
        c.seq = nextSeq++
        queues[i].addLast(c)
        nonEmpty = nonEmpty or (1 shl i)
        queued++
        queuedBytes += c.data.size
    }

    private fun removeFirst(i: Int): Cmd {
        val c = queues[i].removeFirst()
        if (queues[i].isEmpty()) nonEmpty = nonEmpty and (1 shl i).inv()
        queued--
        queuedBytes -= c.data.size
        return c
    }

    /** The FIFO of the most urgent queued datagram, -1 when none. */
    private fun first(): Int = if (nonEmpty == 0) -1 else nonEmpty.countTrailingZeroBits()

    /** Any thread: true when a datagram under [DatagramPolicy.Reject] has room. */
    fun hasRoom(size: Int): Boolean = count.load() < maxCount && bytes.load() + size <= maxBytes

    /** Any thread: hands [data] (already copied) over; [DatagramPolicy.Reject] callers check [hasRoom] first. */
    fun offer(
        data: ByteArray,
        policy: DatagramPolicy,
        urgency: Int = -1,
    ) {
        count.incrementAndFetch()
        bytes.addAndFetch(data.size.toLong())
        commands.trySend(Cmd(data, policy, urgency))
        signal.trySend(Unit)
    }

    private var queuedBytes = 0L

    /** Loop only: moves commands into the queue while it has room (a LatestWins replacement always fits); true when something was added. */
    fun applyCommands(): Boolean {
        var any = false
        while (true) {
            // the command that did not fit last time goes first (order is kept)
            val cmd = pending ?: commands.tryReceive().getOrNull() ?: break
            pending = null
            val policy = cmd.policy
            var replaced = false
            if (policy is DatagramPolicy.LatestWins) {
                for ((qi, q) in queues.withIndex()) {
                    val i = q.indexOfFirst { (it.policy as? DatagramPolicy.LatestWins)?.key == policy.key }
                    if (i < 0) continue
                    val old = q.removeAt(i)
                    if (q.isEmpty()) nonEmpty = nonEmpty and (1 shl qi).inv()
                    queued--
                    queuedBytes -= old.data.size
                    release(old)
                    replaced = true
                    break
                }
            }
            if (!replaced && (queued >= maxCount || queuedBytes + cmd.data.size > maxBytes)) {
                pending = cmd
                break
            } // full: the loop sends first, evicts only if that did not help
            addLast(cmd)
            any = true
        }
        return any
    }

    /** A command taken from the channel that did not fit yet. */
    private var pending: Cmd? = null
    val hasPendingCommands: Boolean get() = pending != null || !commands.isEmpty

    /** Loop only: the network could not take the queue; drop the oldest so the pending command gets in (DropOldest / LatestWins semantics). */
    fun evictForPending() {
        val cmd = pending ?: return
        pending = null
        while (queued > 0 &&
            (queued >= maxCount || queuedBytes + cmd.data.size > maxBytes)
        ) {
            // the oldest of all, whatever its urgency (DropOldest semantics): the smallest arrival among the heads
            var oldest = -1
            for (i in 0 until URGENCIES) {
                if (nonEmpty and (1 shl i) != 0 && (oldest < 0 || queues[i].first().seq < queues[oldest].first().seq)) oldest = i
            }
            release(removeFirst(oldest))
        }
        addLast(cmd)
    }

    val isFull: Boolean get() = queued >= maxCount || queuedBytes >= maxBytes

    /** Datagrams dropped because they outgrew the path MTU. */
    var dropped: Long = 0
        private set

    private fun release(c: Cmd) {
        count.decrementAndFetch()
        bytes.addAndFetch(-c.data.size.toLong())
    }

    val isEmpty: Boolean get() = queued == 0

    override fun hasPending(): Boolean = queued > 0

    /** The urgency of the most urgent queued datagram. */
    override fun nextUrgency(): Int = first().let { if (it < 0) -1 else it - 1 }

    /**
     * Writes datagrams of the most urgent queue only: the packet builder let more urgent stream data go first for that
     * urgency ([nextUrgency]), so a less urgent datagram waits for a packet of its own turn.
     */
    override fun onTransmit(packet: DatagramPacketWriter) {
        val i = first()
        if (i < 0) return
        val q = queues[i]
        while (true) {
            val c = q.firstOrNull() ?: break
            if (c.data.size > packet.maxPayload) {
                release(removeFirst(i))
                dropped++
                continue
            } // the path MTU shrank under it: it can never be sent (RFC 8899 black hole)
            if (c.data.size >
                packet.remaining
            ) {
                break
            }
            if (!packet.write(c.data, 0, c.data.size)) break
            release(removeFirst(i))
        }
    }

    fun close() {
        commands.close()
        signal.close()
        queues.forEach { it.clear() }
        nonEmpty = 0
        queued = 0
        queuedBytes = 0
        pending = null
    }

    private companion object {
        /** -1 (no urgency) and RFC 9218's eight urgencies. */
        const val URGENCIES = 9
    }
}
