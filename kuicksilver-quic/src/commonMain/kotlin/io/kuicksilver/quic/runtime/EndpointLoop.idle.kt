// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, InternalKuicksilverApi::class, ExperimentalAtomicApi::class)

package io.kuicksilver.quic.runtime

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.core.failInternal
import io.kuicksilver.quic.core.idleDeadline
import kotlin.concurrent.atomics.ExperimentalAtomicApi

// The sockets are drained before an idle timer closes a connection.
//
// RFC 9000 section 10.1: the idle timer restarts "when a packet from its peer is received and processed successfully". A
// process frozen past a connection's idle deadline (an Android app freeze or Doze, a sleeping laptop, a stopped debugger)
// wakes with its timer overdue while the peer's datagrams wait in the socket's queue, or in a receive whose thread has not
// handed them back yet. Fired first, the timer would close a connection those datagrams keep alive.
//
// So a connection whose idle deadline has passed is held instead ([holdForDrain]): none of its timers run, and the loop asks
// every receiver of its sockets for a drain round ([startDrainRound], BatchReceiver.requestDrain): a receive in flight is
// interrupted, and the receiver takes what its socket holds without waiting, at most BatchReceiver.DRAIN_BUDGET datagrams, and
// the loop processes it. Once every receiver finished a round that began after the hold ([releaseHeld]), the connection's
// timers run again: the idle timer closes it only if none of those datagrams restarted it. A Stateless Reset among them ends
// it as reset (section 10.3.1), a CONNECTION_CLOSE as draining (section 10.2.2): both leave the idle timer behind.
//
// A held connection is released after IDLE_HOLD_LIMIT whatever the receivers did (a receive that never hands back). Only
// the receivers that can drain count ([BatchReceiver.drains]: every socket of the library; a caller's own DatagramIo is not
// drained); with none, a connection is never held. In a group, the datagrams other loops forwarded and this loop has not
// processed yet are a further queue ([forwardLoop]); what another loop's socket still holds is not reached.

/** A connection held for a drain: the round that decides it, and when it was held. */
internal class HeldForDrain(
    val core: ConnectionCore,
    val round: Long,
    val since: TimeMark,
)

/**
 * The receiver [r] of one of this loop's sockets takes part in drain rounds from now on. It owes nothing for rounds that
 * ended, but the round still open while a connection is held (a migration path's socket added meanwhile may hold that
 * connection's datagrams) is asked of it too.
 */
internal fun EndpointLoop.registerReceiver(r: BatchReceiver) {
    r.startAtDrainRound(if (held.isEmpty()) drainRound else drainRound - 1)
    r.onDrained = drainedSignal
    receivers += r
    if (held.isNotEmpty()) r.requestDrain(drainRound)
}

/** [r]'s socket is gone: the rounds stop waiting for it. */
internal fun EndpointLoop.unregisterReceiver(r: BatchReceiver) {
    receivers.remove(r)
    if (held.isNotEmpty()) wake.trySend(Unit)
}

private fun EndpointLoop.anyReceiverDrains(): Boolean {
    for (i in 0 until receivers.size) if (receivers[i].drains) return true
    return false
}

/**
 * The timer coroutine's question for a due connection [c]: true when it is held for a drain (its idle deadline passed and a
 * receiver can drain), and then none of its timers runs now. Loop dispatcher only.
 */
internal fun EndpointLoop.holdForDrain(
    c: ConnectionCore,
    now: TimeMark,
): Boolean {
    if (c.idleHeld || c.idleDeadline() > now || !anyReceiverDrains()) return false
    c.idleHeld = true
    held += HeldForDrain(c, drainRound + 1, now)
    drainRoundWanted = true
    onIdleHeldForTest?.invoke(held.size)
    return true
}

/** Asks every receiver for the next drain round when a connection was held since the last one. Loop dispatcher only. */
internal fun EndpointLoop.startDrainRound() {
    if (!drainRoundWanted) return
    drainRoundWanted = false
    val round = ++drainRound
    idleDrainRoundsForTest++
    for (i in 0 until receivers.size) receivers[i].requestDrain(round)
    // the forwarded queue: counted until processed, since one handed to the waiting forward loop has left the channel already
    if (forwardedPending.load() == 0) {
        forwardDrainServed = round
    } else {
        forwardDrainRequested = round
        forwardDrainTaken = 0
    }
}

/** The forward loop finished a round of [taken] datagrams, [dry] when nothing forwarded waits any more. Loop dispatcher only. */
internal fun EndpointLoop.forwardRoundDone(
    taken: Int,
    dry: Boolean,
) {
    if (forwardDrainRequested <= forwardDrainServed) return
    forwardDrainTaken += taken
    if (dry || forwardDrainTaken >= BatchReceiver.DRAIN_BUDGET) {
        forwardDrainServed = forwardDrainRequested
        wake.trySend(Unit)
    }
}

/** The last round every draining receiver (and the forwarded queue) has finished. */
private fun EndpointLoop.drainedThrough(): Long {
    var through = if (group != null) forwardDrainServed else Long.MAX_VALUE
    for (i in 0 until receivers.size) {
        val r = receivers[i]
        if (r.drains && r.drainServed < through) through = r.drainServed
    }
    return through
}

/** When the oldest hold ends whatever the receivers did; [TimeMark.NEVER] when nothing is held. */
internal fun EndpointLoop.idleHoldEnd(): TimeMark = if (held.isEmpty()) TimeMark.NEVER else held[0].since + EndpointLoop.IDLE_HOLD_LIMIT

/**
 * Runs the timers of the held connections whose round was drained (or whose hold reached its limit, or whose idle deadline
 * moved on: a packet restarted it, or the connection left the states it applies to). Loop dispatcher only.
 */
internal fun EndpointLoop.releaseHeld(now: TimeMark) {
    if (held.isEmpty()) return
    val through = drainedThrough()
    var i = 0
    while (i < held.size) {
        val h = held[i]
        val c = h.core
        val closed = c.state == ConnectionState.Closed || runtimes[c] == null
        if (!closed && h.round > through && c.idleDeadline() <= now && now - h.since < EndpointLoop.IDLE_HOLD_LIMIT) {
            i++
            continue
        }
        held.removeAt(i)
        c.idleHeld = false
        if (closed) continue
        core.markDirty(c)
        try {
            c.onTimeout(now) // the idle timer first: it closes the connection if nothing restarted it
        } catch (e: Throwable) {
            c.failInternal(e) // sans-IO, not suspending: even a CancellationException is the connection's failure
        }
        onIdleReleasedForTest?.invoke(c)
    }
}

/** Connections held for a drain now (tests). */
internal val EndpointLoop.heldForDrainForTest: Int get() = held.size
