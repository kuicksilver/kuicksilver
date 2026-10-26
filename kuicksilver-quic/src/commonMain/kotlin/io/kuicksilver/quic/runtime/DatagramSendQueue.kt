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
    )

    /** Commands from the application, applied on the loop; an overflow drops (and un-counts) the oldest. */
    val commands = Channel<Cmd>(maxCount, BufferOverflow.DROP_OLDEST) { release(it) }

    /** Wakes the loop-side drainer once per burst. */
    val signal = Channel<Unit>(Channel.CONFLATED)

    /** Datagrams queued and not yet sent, as seen from any thread (for Reject); the loop keeps them exact. */
    val count = AtomicInt(0)
    val bytes = AtomicLong(0)
    private val queue = ArrayDeque<Cmd>()

    /** Any thread: true when a datagram under [DatagramPolicy.Reject] has room. */
    fun hasRoom(size: Int): Boolean = count.load() < maxCount && bytes.load() + size <= maxBytes

    /** Any thread: hands [data] (already copied) over; [DatagramPolicy.Reject] callers check [hasRoom] first. */
    fun offer(
        data: ByteArray,
        policy: DatagramPolicy,
    ) {
        count.incrementAndFetch()
        bytes.addAndFetch(data.size.toLong())
        commands.trySend(Cmd(data, policy))
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
                val i =
                    queue.indexOfFirst {
                        (it.policy as? DatagramPolicy.LatestWins)?.key ==
                            policy.key
                    }
                ; if (i >= 0) {
                    val old = queue.removeAt(i)
                    queuedBytes -= old.data.size
                    release(old)
                    replaced = true
                }
            }
            if (!replaced && (queue.size >= maxCount || queuedBytes + cmd.data.size > maxBytes)) {
                pending = cmd
                break
            } // full: the loop sends first, evicts only if that did not help
            queue.addLast(cmd)
            queuedBytes += cmd.data.size
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
        while (queue.isNotEmpty() &&
            (queue.size >= maxCount || queuedBytes + cmd.data.size > maxBytes)
        ) {
            val old = queue.removeFirst()
            queuedBytes -=
                old.data.size
            release(old)
        }
        queue.addLast(cmd)
        queuedBytes += cmd.data.size
    }

    val isFull: Boolean get() = queue.size >= maxCount || queuedBytes >= maxBytes

    /** Datagrams dropped because they outgrew the path MTU. */
    var dropped: Long = 0
        private set

    private fun release(c: Cmd) {
        count.decrementAndFetch()
        bytes.addAndFetch(-c.data.size.toLong())
    }

    val isEmpty: Boolean get() = queue.isEmpty()

    override fun hasPending(): Boolean = queue.isNotEmpty()

    override fun onTransmit(packet: DatagramPacketWriter) {
        while (true) {
            val c = queue.firstOrNull() ?: break
            if (c.data.size > packet.maxPayload) {
                queue.removeFirst()
                queuedBytes -= c.data.size
                release(c)
                dropped++
                continue
            } // the path MTU shrank under it: it can never be sent (RFC 8899 black hole)
            if (c.data.size >
                packet.remaining
            ) {
                break
            }
            if (!packet.write(c.data, 0, c.data.size)) break
            queue.removeFirst()
            queuedBytes -= c.data.size
            release(c)
        }
    }

    fun close() {
        commands.close()
        signal.close()
        queue.clear()
        queuedBytes = 0
        pending = null
    }
}
