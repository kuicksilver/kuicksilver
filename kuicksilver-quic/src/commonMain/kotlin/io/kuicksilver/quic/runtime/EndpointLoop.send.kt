// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class, InternalKuicksilverApi::class)

package io.kuicksilver.quic.runtime

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.DfFamilyRestricted
import io.kuicksilver.quic.NonSuspendingSend
import io.kuicksilver.quic.PATH_MTU_FLOOR
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.PathMtuRefusedException
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.SocketDefunctException
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.core.failInternal
import io.kuicksilver.quic.core.idleDeadline
import io.kuicksilver.quic.core.onEmsgsize
import io.kuicksilver.quic.ipFamilyOf
import io.kuicksilver.quic.runtime.EndpointLoop.Companion.FLUSH_ROUNDS
import io.kuicksilver.quic.sameIpAs
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.withLock
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.coroutines.CoroutineContext

// Sending: the flush of every connection that has something to write, and what a send error or a full socket does to the datagram.

/** Sends [out]: in one call when every slot uses the endpoint socket, otherwise slot by slot through each path's socket. */
private inline fun EndpointLoop.sendOutWith(
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
 * socket are [NonSuspendingSend]s (the accelerated socket, or a loop's view of one a group shares), whose `send` is `trySend`. A flush then runs without a coroutine frame ([flushNow]).
 */
private fun EndpointLoop.sendsNeverSuspend(): Boolean {
    if (io !is NonSuspendingSend || suspendingPathSockets) return false
    val p = preferredIos
    for (i in 0 until p.size) if (p[i] !is NonSuspendingSend) return false
    return true
}

/**
 * A send that throws (EPERM from a filter, an unreachable route, a socket closed under a closing endpoint) loses this batch,
 * one that takes only part of it (a full send buffer) loses the rest; loss detection repairs both, and [rt]'s connection
 * counts them (a throwing send counts its whole batch, so the count may exceed what was really lost when the socket
 * fails mid-batch). It never propagates: it would end a loop coroutine.
 */
private suspend fun EndpointLoop.sendOrLose(
    target: DatagramIo,
    batch: PacketBatch,
    rt: ConnectionRuntime?,
) {
    val ctx = currentCoroutineContext()
    sendOrLoseWith(target, batch, rt, ctx) { full -> if (full) target.trySend(batch) else target.send(batch) }
}

/** [sendOrLose]'s body; [send] sends [batch] on [target] (`trySend` once the socket refused part of a batch in this flush). */
private inline fun EndpointLoop.sendOrLoseWith(
    target: DatagramIo,
    batch: PacketBatch,
    rt: ConnectionRuntime?,
    ctx: CoroutineContext,
    send: (full: Boolean) -> Int,
) {
    var counted = 0
    val lost =
        if (isDefunct(target)) {
            batch.count // a lost socket is not written again: its paths wait for a move to a new one
        } else {
            try {
                // a socket that already refused part of a batch in this flush (after its one wait for room) is not waited on
                // again: the flush holds flushLock, so each wait would stall ACKs and timers of every other connection
                val full = isFullThisFlush(target)
                val sent = send(full).coerceIn(0, batch.count)
                // a datagram of this batch the kernel refused as too large: a DPLPMTUD hint (RFC 8899 section 4.6). Taken after
                // every batch, stateless ones (rt null) too, so a refusal is never charged to the next connection's batch
                if (target is NonSuspendingSend) {
                    val tooBig = target.takeEmsgsize()
                    if (rt != null && tooBig > 0) {
                        val to = slotOfLength(batch, tooBig)
                        if (tooBig <= PATH_MTU_FLOOR) {
                            // DF in DO mode (probe refused) met a cached path MTU below QUIC's floor; a refusal that matches no
                            // datagram of this batch is not this connection's, and one whose length several destinations share
                            // (a probe on another path) cannot be placed: the socket reports only the length
                            if (to != null) rt.onPathMtuRefused(tooBig, target, to)
                        } else {
                            rt.core.onEmsgsize(tooBig)
                            core.markDirty(rt.core)
                        }
                    }
                }
                if (sent < batch.count && !full) fullThisFlush.add(target)
                observer.datagramsSent += sent
                counted = sent
                batch.count - sent
            } catch (e: CancellationException) {
                ctx.ensureActive() // else a DatagramIo's own failure: a lost batch
                sendFailures++
                batch.count
            } catch (e: QuicException.DontFragmentUnavailable) {
                // no DF for this destination's address family: nothing goes out without it, the connection has no viable path
                sendFailures++
                rt?.onDontFragmentUnavailable(e, target, null)
                batch.count
            } catch (e: PathMtuRefusedException) {
                sendFailures++
                if (rt != null && e.size <= PATH_MTU_FLOOR) rt.onPathMtuRefused(e.size, target, e.destination)
                batch.count
            } catch (e: SocketDefunctException) {
                sendFailures++
                // a server's own socket serves every client: one refused destination must not take it down
                if (target !== io || clientOnly) socketLost(target, e)
                batch.count
            } catch (e: Throwable) {
                sendFailures++
                batch.count
            } finally {
                // slots the socket skipped for want of DF towards their family (no QUIC without DF): not sent, and their path
                // fails (it closes, or the connection ends, so their packets leave loss and congestion state with it). Taken
                // even when the send threw part-way through the batch: they are this batch's, never the next one's
                val skipped = takeDfRefusals(target, rt)
                if (skipped > 0) {
                    observer.datagramsSkippedNoDf += skipped
                    observer.datagramsSent -= minOf(skipped, counted)
                }
            }
        }
    if (lost > 0) lose(lost, rt)
}

/** The destinations [target] skipped for want of DF in its latest send, reported to [rt]; returns how many. */
private fun takeDfRefusals(
    target: DatagramIo,
    rt: ConnectionRuntime?,
): Int {
    if (target !is DfFamilyRestricted) return 0
    val refused = target.takeDfRefusals()
    for (to in refused) {
        val family = ipFamilyOf(to)
        val e = QuicException.DontFragmentUnavailable(family, "this socket has no DF for ${family?.label ?: to}")
        rt?.onDontFragmentUnavailable(e, target, to)
    }
    return refused.size
}

/**
 * The one destination of the slots of [batch] that are [length] bytes long, or null when none is, or when such slots go to
 * more than one destination (the accelerated socket reports a refused datagram by its length only, so the refusal cannot be
 * placed on a path; a later batch places it).
 */
internal fun slotOfLength(
    batch: PacketBatch,
    length: Int,
): io.ktor.network.sockets.InetSocketAddress? {
    var found: io.ktor.network.sockets.InetSocketAddress? = null
    for (i in 0 until batch.count) {
        if (batch.length(i) != length) continue
        val a = batch.address(i) ?: continue
        if (found == null) {
            found = a
        } else if (!found.sameIpAs(a)) {
            return null
        }
    }
    return found
}

internal fun EndpointLoop.lose(
    n: Int,
    rt: ConnectionRuntime?,
) {
    socketDrops += n
    if (rt != null) rt.core.datagramsDroppedSocket += n
}

/** By index: an iterator per send would allocate. */
private fun EndpointLoop.isFullThisFlush(target: DatagramIo): Boolean {
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

/** [flush] when no send can suspend; `flushLock` held. */
private fun EndpointLoop.flushNow(
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
private suspend fun EndpointLoop.flushSuspending(
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

/** What a flush does, with its two kinds of send passed in; `flushLock` held. */
private inline fun EndpointLoop.flushBody(
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
                    // held for a drain past its idle deadline: nothing goes out (an application write would restart the timer,
                    // RFC 9000 section 10.1; the core's poll refuses it too) until the drain decides
                    if (!(c.idleHeld && c.idleDeadline() <= now) && c.poll(outBatch, now) > 0) sendOut(rt, outBatch)
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
                    core.noteClock(now) // the IDs a moved connection leaves behind are kept from now, not from its last event
                    core.remove(c)
                    runtimes.remove(c)?.forgotten()
                    if (shuttingDown && runtimes.isEmpty()) drained.complete(Unit)
                } else {
                    // held for a drain while its idle deadline stays passed: no timer of it runs until the drain decides
                    timers.update(c, if (c.idleHeld && c.idleDeadline() <= now) TimeMark.NEVER else c.nextTimeoutOrNever())
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
