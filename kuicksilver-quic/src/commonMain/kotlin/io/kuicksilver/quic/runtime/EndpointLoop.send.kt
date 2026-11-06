// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class, InternalKuicksilverApi::class)

package io.kuicksilver.quic.runtime

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.KslDatagramIo
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.SocketDefunctException
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.core.failInternal
import io.kuicksilver.quic.core.onEmsgsize
import io.kuicksilver.quic.runtime.EndpointLoop.Companion.FLUSH_ROUNDS
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.withLock
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.coroutines.CoroutineContext

// Sending: the flush of every connection that has something to write, and what a send error or a full socket does to the datagram.

/** Sends [out]: in one call when every slot uses the endpoint socket, otherwise slot by slot through each path's socket. */
internal inline fun EndpointLoop.sendOutWith(
    rt: ConnectionRuntime,
    out: PacketBatch,
    sendOrLose: (target: DatagramIo, batch: PacketBatch, rt: ConnectionRuntime) -> Unit,
) {
    var mixed = false
    for (i in 0 until out.count) if (out.path(i) != PathId.Initial) mixed = true
    if (!mixed) {
        sendOrLose(io, out, rt)
        return
    }
    for (i in 0 until out.count) {
        val n = out.length(i)
        out.buffer(i).copyTo(copy, 0, 0, n)
        single.clear()
        single.buffer(0).copyFrom(copy, 0, 0, n)
        single.setLength(0, n)
        single.setAddress(0, out.address(i)!!)
        single.setLocalAddress(0, out.localAddress(i))
        single.setEcn(0, out.ecn(i))
        val target = ioFor(rt, out.path(i), out.address(i))
        if (target == null) {
            lose(1, rt) // its socket is gone (the preferred address went down): loss recovery or the close deals with it
            continue
        }
        sendOrLose(target, single, rt)
    }
}

/**
 * True while no socket this loop sends on can suspend a send: the endpoint's, its preferred-address sockets and every path
 * socket are [KslDatagramIo]s, whose `send` is `trySend`. A flush then runs without a coroutine frame ([flushNow]).
 */
internal fun EndpointLoop.sendsNeverSuspend(): Boolean {
    if (io !is KslDatagramIo || suspendingPathSockets) return false
    val p = preferredIos
    for (i in 0 until p.size) if (p[i] !is KslDatagramIo) return false
    return true
}

/**
 * A send that throws (EPERM from a filter, an unreachable route, a socket closed under a closing endpoint) loses this batch,
 * one that takes only part of it (a full send buffer) loses the rest; loss detection repairs both, and [rt]'s connection
 * counts them (a throwing send counts its whole batch, so the count may exceed what was really lost when the socket
 * fails mid-batch). It never propagates: it would end a loop coroutine.
 */
internal suspend fun EndpointLoop.sendOrLose(
    target: DatagramIo,
    batch: PacketBatch,
    rt: ConnectionRuntime?,
) {
    val ctx = currentCoroutineContext()
    sendOrLoseWith(target, batch, rt, ctx) { full -> if (full) target.trySend(batch) else target.send(batch) }
}

/** [sendOrLose]'s body; [send] sends [batch] on [target] (`trySend` once the socket refused part of a batch in this flush). */
internal inline fun EndpointLoop.sendOrLoseWith(
    target: DatagramIo,
    batch: PacketBatch,
    rt: ConnectionRuntime?,
    ctx: CoroutineContext,
    send: (full: Boolean) -> Int,
) {
    val lost =
        if (isDefunct(target)) {
            batch.count // a lost socket is not written again: its paths wait for a move to a new one
        } else {
            try {
                // a socket that already refused part of a batch in this flush (after its one wait for room) is not waited on
                // again: the flush holds flushLock, so each wait would stall ACKs and timers of every other connection
                val full = isFullThisFlush(target)
                val sent = send(full).coerceIn(0, batch.count)
                // a datagram of this connection the kernel refused as too large: a DPLPMTUD hint (RFC 8899 section 4.6)
                if (rt != null && target is KslDatagramIo) {
                    val tooBig = target.takeEmsgsize()
                    if (tooBig > 0) {
                        rt.core.onEmsgsize(tooBig)
                        core.markDirty(rt.core)
                    }
                }
                if (sent < batch.count && !full) fullThisFlush.add(target)
                observer.datagramsSent += sent
                batch.count - sent
            } catch (e: CancellationException) {
                ctx.ensureActive() // else a DatagramIo's own failure: a lost batch
                sendFailures++
                batch.count
            } catch (e: SocketDefunctException) {
                sendFailures++
                // a server's own socket serves every client: one refused destination must not take it down
                if (target !== io || clientOnly) socketLost(target, e)
                batch.count
            } catch (e: Throwable) {
                sendFailures++
                batch.count
            }
        }
    if (lost > 0) lose(lost, rt)
}

internal fun EndpointLoop.lose(
    n: Int,
    rt: ConnectionRuntime?,
) {
    socketDrops += n
    if (rt != null) rt.core.datagramsDroppedSocket += n
}

/** By index: an iterator per send would allocate. */
internal fun EndpointLoop.isFullThisFlush(target: DatagramIo): Boolean {
    for (i in 0 until fullThisFlush.size) if (fullThisFlush[i] === target) return true
    return false
}

/**
 * Drains events, sends what the dirty connections have to send, retires closed ones, re-arms their timers. Loop dispatcher
 * only; [touched] joins the dirty list first. Runs on the loop's thread for every received batch, timer and application
 * write, so it allocates nothing on its own when it cannot suspend ([sendsNeverSuspend], the accelerated socket): then it
 * takes the lock without waiting and calls [flushBody] directly, and only the suspending path gets a coroutine frame.
 */
internal suspend fun EndpointLoop.flush(
    touched: ConnectionCore? = null,
    signalTimer: Boolean = true,
) {
    if (sendsNeverSuspend() && flushLock.tryLock()) {
        try {
            flushNow(touched, signalTimer, currentCoroutineContext())
        } finally {
            flushLock.unlock()
        }
        return
    }
    flushSuspending(touched, signalTimer)
}

/** [flush] when no send can suspend; [flushLock] held. */
internal fun EndpointLoop.flushNow(
    touched: ConnectionCore?,
    signalTimer: Boolean,
    ctx: CoroutineContext,
) {
    flushBody(
        touched,
        signalTimer,
        ctx,
        sendOut = { rt, out -> sendOutWith(rt, out) { t, b, r -> sendOrLoseWith(t, b, r, ctx) { t.trySend(b) } } },
        sendStateless = { t, b -> sendOrLoseWith(t, b, null, ctx) { t.trySend(b) } },
    )
}

/** [flush] through the lock, each send through [sendOrLose] (it may wait for room). */
internal suspend fun EndpointLoop.flushSuspending(
    touched: ConnectionCore?,
    signalTimer: Boolean,
) {
    flushLock.withLock {
        val ctx = currentCoroutineContext()
        flushBody(
            touched,
            signalTimer,
            ctx,
            sendOut = { rt, out -> sendOutWith(rt, out) { t, b, r -> sendOrLose(t, b, r) } },
            sendStateless = { t, b -> sendOrLose(t, b, null) },
        )
    }
}

/** What a flush does, with its two kinds of send passed in; [flushLock] held. */
internal inline fun EndpointLoop.flushBody(
    touched: ConnectionCore?,
    signalTimer: Boolean,
    ctx: CoroutineContext,
    sendOut: (rt: ConnectionRuntime, out: PacketBatch) -> Unit,
    sendStateless: (target: DatagramIo, batch: PacketBatch) -> Unit,
) {
    if (released) return // a coroutine resumed after the close job freed the batches
    if (touched != null) core.markDirty(touched)
    val now = now()
    val dirty = core.dirtyConnections
    if (dirty.isEmpty() && !core.hasStateless) return
    val head = timers.peek()?.heapDeadline ?: TimeMark.NEVER
    fullThisFlush.clear()
    // connections marked dirty while this flush runs (a refusal in onHandshakeCompleted, a failure marking others) get
    // further rounds here: their CONNECTION_CLOSE must not wait for the next datagram or timer
    try {
        var rounds = 0
        while (dirty.isNotEmpty() && rounds++ < FLUSH_ROUNDS) {
            // the list is copied (into a list kept for it, by index: no copy or iterator allocated per flush): a flush can
            // retire connections, and a failure inside one marks others dirty
            val list = flushRound
            list.clear()
            for (i in 0 until dirty.size) list.add(dirty[i])
            core.clearDirty()
            for (k in 0 until list.size) {
                val c = list[k]
                val rt = runtimes[c] ?: continue
                try {
                    // a connection closing: its CONNECTION_CLOSE goes to the socket first, and the application side of the end
                    // (failing streams, waking waiters, the listener's onClosed) follows; the paths' addresses are what the send needs
                    if (c.state == ConnectionState.Closing) rt.refreshPathRemotes() else rt.drainEvents()
                    outBatch.clear()
                    if (c.poll(outBatch, now) > 0) sendOut(rt, outBatch)
                    rt.drainEvents()
                    rt.tick()
                } catch (e: Throwable) {
                    // our own cancellation goes on; a CancellationException out of a callback is that connection's failure
                    if (e is CancellationException) ctx.ensureActive()
                    c.failInternal(e)
                    rt.drainEvents()
                }
                if (c.state ==
                    ConnectionState.Closed
                ) {
                    handshakeEnded(rt)
                    rt.finish()
                    timers.remove(c)
                    core.remove(c)
                    runtimes.remove(c)
                    if (shuttingDown && runtimes.isEmpty()) drained.complete(Unit)
                } else {
                    timers.update(c, c.nextTimeoutOrNever())
                }
            }
        }
    } finally {
        // the round's connections are not kept past the flush, also when it ends in an exception (our cancellation):
        // a closed one would stay reachable from the loop
        flushRound.clear()
    }
    if (dirty.isNotEmpty()) wake.trySend(Unit) // still more after the bounded rounds: the timer coroutine flushes again
    outBatch.clear()
    if (core.pollStateless(outBatch) > 0) sendStateless(io, outBatch)
    if (core.dirtyConnections.isNotEmpty()) flushesEndingDirtyForTest++
    val newHead = timers.peek()?.heapDeadline ?: TimeMark.NEVER
    if (signalTimer && newHead < head) wake.trySend(Unit)
}
