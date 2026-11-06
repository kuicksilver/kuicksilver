// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class, InternalKuicksilverApi::class)

package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.KslDatagramIo
import io.kuicksilver.quic.PREFERRED_SOCKET
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.SocketDefunctException
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.core.failInternal
import io.kuicksilver.quic.runtime.EndpointLoop.Companion.FORWARD_BATCH
import io.kuicksilver.quic.runtime.EndpointLoop.Companion.FORWARD_MAX
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.selects.onTimeout
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.time.Duration

// The loops that read datagrams, forward them to the connections and fire the timers.

/** One datagram off this loop's socket: routed by the core, or, in a group, copied to the loop its connection ID names. */
internal fun EndpointLoop.onDatagram(
    buf: PacketBuffer,
    length: Int,
    from: InetSocketAddress,
    ecn: Ecn,
    now: TimeMark,
    socket: PathId = PathId.Initial,
    local: InetSocketAddress? = null,
) {
    if (socket == PREFERRED_SOCKET && preferredIos.isEmpty()) {
        core.droppedPreferredDown++ // the preferred address went down; another loop forwarded this before it knew
        return
    }
    val misroute = testMisrouteTo
    if (misroute >= 0 && group != null) {
        if (!group.forward(misroute, buf, length, from, ecn, asReceived = true, socket, local)) core.droppedQueue++
        return
    }
    if (core.handleDatagram(buf, length, from, ecn, now, socket, local) != null || group == null) return
    val owner = core.ownerLoop(buf, length)
    if (owner >= 0 && owner != index &&
        !group.forward(owner, buf, length, from, ecn, asReceived = false, socket, local)
    ) {
        core.droppedQueue++
    }
}

internal suspend fun EndpointLoop.receiveLoop() {
    try {
        limiter.start(now())
        while (true) {
            inBatch.clear()
            // the batch on the loop's thread without a coroutine frame; the suspending receive only to yield or to wait
            val direct = receiver.receiveDirect(inBatch, untilTimer)
            if (direct < 0) receiver.receive(inBatch, untilTimer, directTried = direct == BatchReceiver.NOTHING)
            observer.datagramsReceived += inBatch.count
            val now = now()
            for (i in 0 until inBatch.count) {
                onDatagram(
                    inBatch.buffer(i),
                    inBatch.length(i),
                    inBatch.address(i)!!,
                    inBatch.ecn(i),
                    now,
                    local = inBatch.localAddress(i),
                )
            }
            afterReceive(now)
            // a socket that never runs dry (a flood) must not starve the timer coroutine and the queued application commands
            if (limiter.shouldYield(now)) {
                yield()
                limiter.start(now())
            }
        }
    } catch (e: CancellationException) {
        currentCoroutineContext().ensureActive() // our cancellation goes on; else a socket's own failure
        if (!closing) fatal("transport failed", e)
    } catch (e: SocketDefunctException) {
        // a client endpoint keeps its connections: each can move to a new socket (QuicConnection.rebind); connect() fails fast
        if (closing) return
        if (clientOnly) socketLost(io, e) else fatal("transport failed", e)
    } catch (e: Throwable) {
        if (!closing) fatal("transport failed", e)
    } // a dead socket ends the endpoint: accept() and connect() must not hang
}

internal fun EndpointLoop.isDefunct(target: DatagramIo): Boolean = defunct.isNotEmpty() && defunct.any { it === target }

/** The ICMP Packet Too Big messages [io] queued (Linux and Android), as hints for the connections' DPLPMTUD. */
internal fun EndpointLoop.drainPacketTooBig(
    io: DatagramIo,
    socket: PathId,
    now: TimeMark,
) {
    if (io !is KslDatagramIo) return
    io.drainPacketTooBig { quote, len, dst, mtu -> core.handlePacketTooBig(quote, len, dst, mtu, now, socket) }
}

internal suspend fun EndpointLoop.afterReceive(now: TimeMark) {
    afterReceiveCount++
    drainPacketTooBig(io, PathId.Initial, now)
    core.processPending(now) // admission runs once per receive batch
    while (true) {
        val c = core.nextAccepted() ?: break
        val rt = adopt(c)
        rt.serverSide = true
        rt.handshaking = true
        handshaking++
        handshakingForTest = handshaking
    } // new server connections leave the core's queue at once
    flush()
}

/** Datagrams other loops of the group handed over (a flow the kernel hashed onto their socket). */
internal suspend fun EndpointLoop.forwardLoop() {
    val buf = PacketBuffer.allocate(FORWARD_MAX)
    try {
        // in batches of FORWARD_BATCH like the receiver's: admission and a flush after each, then a yield, so a rebound
        // high-rate flow cannot starve this loop's own socket, timers and commands. Every round, not the WorkLimiter's 16
        // rounds or 2 ms: queued work held that long starved the application's reads, which extend a stream's
        // flow-control credit, and slowed a fast sender 2.6 times when the receive path did it (docs/benchmarks.md)
        var sinceRound = 0
        for (f in forwarded) {
            forwardedCount.incrementAndFetch()
            buf.copyFrom(f.bytes, 0, 0, f.bytes.size)
            val now = now()
            if (f.asReceived) {
                onDatagram(
                    buf,
                    f.bytes.size,
                    f.from,
                    f.ecn,
                    now,
                    f.socket,
                    f.local,
                )
            } else if (f.socket == PREFERRED_SOCKET && preferredIos.isEmpty()) {
                core.droppedPreferredDown++
            } else {
                core.handleDatagram(buf, f.bytes.size, f.from, f.ecn, now, f.socket, f.local)
            }
            @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
            val drained = forwarded.isEmpty
            if (++sinceRound == FORWARD_BATCH || drained) {
                sinceRound = 0
                afterReceive(now)
                yield()
            }
        }
    } catch (e: Throwable) {
        if (e is CancellationException) currentCoroutineContext().ensureActive()
        if (!closing) fatal("forwarding failed", e)
    } finally {
        buf.close()
    }
}

internal suspend fun EndpointLoop.timerLoop() {
    try {
        timerTicks()
    } catch (e: Throwable) {
        if (e is CancellationException) currentCoroutineContext().ensureActive()
        if (!closing) fatal("timer failed", e)
    } // like the receive loop: a dead timer ends the endpoint instead of escaping
}

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class) // select's onTimeout
internal suspend fun EndpointLoop.timerTicks() {
    while (true) {
        val head = timers.peek()
        val wait = head?.let { it.heapDeadline - now() }
        if (wait == null) {
            wake.receive()
        } else if (wait > Duration.ZERO) {
            // not withTimeoutOrNull: its expiry creates and throws a TimeoutCancellationException, and on Kotlin/Native every
            // throw captures a stack trace and unwinds through C++; a select's timeout clause just resumes (docs/benchmarks.md)
            select<Unit> {
                wake.onReceive {}
                onTimeout(wait) {}
            }
        }
        val now = now()
        while (true) {
            val c = timers.peek() ?: break
            if (c.heapDeadline > now) break
            timers.remove(c)
            core.markDirty(c)
            try {
                c.onTimeout(now)
            } catch (e: Throwable) {
                c.failInternal(e) // sans-IO, not suspending: even a CancellationException is the connection's failure
            }
        }
        flush(signalTimer = false) // the timer loop re-reads the heap itself; signalling itself here would spin
    }
}
