// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class, InternalKuicksilverApi::class)

package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.EndpointStats
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.PREFERRED_SOCKET
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.core.AddressClass
import io.kuicksilver.quic.core.preferredSocketDown
import io.kuicksilver.quic.emit
import io.kuicksilver.quic.runtime.EndpointLoop.Companion.SLOT_SIZE
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlin.concurrent.atomics.ExperimentalAtomicApi

// The preferred-address socket: the second socket a connection moves to after the server's preferred_address (RFC 9000 section 9.6) and the capabilities the endpoint follows.

/**
 * A socket's capabilities can drop while connections run on it (ECN marking turned off, a route without DF): every
 * connection hears of it on the paths that use [socket] (the endpoint's socket is [PathId.Initial], a migrating client's
 * extra socket its path id). Runs on the loop dispatcher, so never inside a connection's poll.
 */
internal suspend fun EndpointLoop.followCapabilities(
    io: DatagramIo,
    socket: PathId,
    only: ConnectionCore? = null,
) {
    // the current value too: a drop between the path's setup and this subscription must not be missed (a repeat changes nothing)
    io.capabilities.collect { caps ->
        for (rt in runtimes.values) {
            if (only != null && rt.core !== only) continue
            rt.core.updateSocketCapabilities(socket, caps)
            core.markDirty(rt.core)
        }
    }
}

/** The socket a slot of `out` goes out on: the endpoint's, the preferred one of [to]'s family, or the one of the connection's path. */
internal fun EndpointLoop.ioFor(
    rt: ConnectionRuntime,
    path: PathId,
    to: InetSocketAddress? = null,
): DatagramIo? =
    if (path ==
        PathId.Initial
    ) {
        io
    } else if (path == PREFERRED_SOCKET) {
        preferredIoFor(to) // none once the preferred address is down: never the main socket, the client would see a stranger
    } else {
        (rt.paths.firstOrNull { it.id == path } as? PathRuntime)?.io ?: io
    }

/** The preferred-address socket of [to]'s family (a v4 and a v6 socket at most). */
private fun EndpointLoop.preferredIoFor(to: InetSocketAddress?): DatagramIo? {
    if (preferredIos.size <= 1 || to == null) return preferredIos.firstOrNull()
    val v4 = AddressClass.ipBytes(to).size == 4
    return preferredIos.firstOrNull { (AddressClass.ipBytes(it.localAddress).size == 4) == v4 } ?: preferredIos[0]
}

/**
 * Receives on a preferred-address socket: the datagrams of connections that moved there (RFC 9000 section 9.6), as
 * [PREFERRED_SOCKET]; a new connection never starts there. In a group the kernel may hash a moved client onto
 * another loop's preferred socket: copied to its owner like any other datagram.
 */
internal suspend fun EndpointLoop.receivePreferred(p: DatagramIo) {
    val batch = PacketBatch(16, SLOT_SIZE)
    val limiter = WorkLimiter()
    val receiver = BatchReceiver(p, clock, directWait, dispatcher as? LoopDispatcher)
    try {
        limiter.start(now())
        while (true) {
            batch.clear()
            receiver.receive(batch, untilTimer)
            observer.datagramsReceived += batch.count
            val now = now()
            for (i in 0 until batch.count) {
                onDatagram(
                    batch.buffer(i),
                    batch.length(i),
                    batch.address(i)!!,
                    batch.ecn(i),
                    now,
                    PREFERRED_SOCKET,
                    batch.localAddress(i),
                )
            }
            drainPacketTooBig(p, PREFERRED_SOCKET, now)
            flush()
            if (limiter.shouldYield(now)) {
                receiver.yieldToQueued()
                limiter.start(now())
            }
        }
    } catch (e: CancellationException) {
        currentCoroutineContext().ensureActive()
        if (!closing) preferredFailed(p, e)
    } catch (e: Throwable) {
        if (!closing) preferredFailed(p, e)
    } finally {
        batch.close()
    }
}

/**
 * A preferred-address socket failed: the endpoint degrades instead of failing. The preferred address is served
 * by every loop of a group or by none, so the whole group takes it down ([dropPreferred]); counted once in
 * `EndpointStats.preferredAddressFailures`. Loop dispatcher only.
 */
internal fun EndpointLoop.preferredFailed(
    failed: DatagramIo,
    e: Throwable,
) {
    if (core.preferredDown) return // already going down: this loop's other socket, or the group's degrade closing it
    if (group != null && !group.claimPreferredFailure()) return // another loop's socket failed first
    observer.logger.emit(LogLevel.Warn, e) {
        "endpoint ${io.localAddress} loop $index: the preferred-address socket ${failed.localAddress} failed; no longer offering " +
            "the preferred address, closing the connections that moved there"
    }
    core.preferredAddressFailures++
    core.preferredDown = true
    if (group != null) group.dropPreferred() else scope.launch { dropPreferred() }
}

/**
 * Takes this loop's part of the preferred address down: its preferred sockets close, new connections no longer get the offer,
 * connections whose active path is on a preferred socket are closed at once (an INTERNAL_ERROR close is attempted, but with no
 * socket left on that address it may never reach the client, which then times out), and a preferred path still under validation
 * fails, its connection staying where it was (RFC 9000 section 9.6.1). Datagrams that still arrive for the preferred socket (forwarded
 * by another loop before it went down) are dropped. Loop dispatcher only.
 */
internal suspend fun EndpointLoop.dropPreferred() {
    core.preferredDown = true
    if (preferredIos.isEmpty()) return
    val down = preferredIos
    preferredIos = emptyList()
    for (p in down) p.close()
    for (rt in runtimes.values.toList()) {
        if (rt.core.preferredSocketDown()) core.markDirty(rt.core)
    }
    flush()
}
