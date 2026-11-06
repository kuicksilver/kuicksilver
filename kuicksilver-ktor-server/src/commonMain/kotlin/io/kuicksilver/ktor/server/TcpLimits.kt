// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.server

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Semaphore
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * The TCP connection limits of one connector (`maxTcpConnections`, `maxTcpConnectionsPerIp`; threat model 3.2), used by its
 * [acceptLoop]. A slot ([maxConnections] in all) is taken before each `accept()`, so at the limit the loop waits instead of
 * accepting and the kernel backlog holds new clients (Go `x/net/netutil.LimitListener`, Jetty `ConnectionLimit`, nginx
 * `worker_connections`); a client is counted per address ([maxPerIp], by [peerIpKey]) right after `accept()`, the earliest
 * its address is known, and refused over the limit (nginx stream `limit_conn`, Envoy `connection_limit`). Each accepted
 * client holds a [TcpLease] that gives both back once, when its socket's job completes; a socket whose release hangs past
 * the abort wait ([closeWithin]) is given up then, so its descriptor can briefly outlive its slot.
 *
 * The per-address counts belong to the accept loop's coroutine alone (no lock on the accept path); a lease released from
 * any other thread hands its address back through [left], which the loop takes in before it counts the next client.
 */
internal class TcpLimits(
    val maxConnections: Int,
    val maxPerIp: Int?,
) {
    init {
        require(maxConnections >= 1) { "maxConnections must be at least 1" }
        require(maxPerIp == null || maxPerIp >= 1) { "maxPerIp must be at least 1, or null" }
    }

    private val slots = Semaphore(maxConnections)

    /** Connections per address key; the accept loop's alone. */
    private val perIp = HashMap<String, Int>()

    /** Address keys of released leases, for the accept loop to take off [perIp]; at most one per open connection. */
    private val left = Channel<String>(Channel.UNLIMITED)

    private val open = AtomicInt(0)

    /** Accepted connections not released yet (a slot the loop holds for an `accept()` still waiting is not one). */
    val connections: Int get() = open.load()

    /** Waits for a free slot; the next `accept()` may then run. */
    suspend fun awaitSlot() = slots.acquire()

    /** Gives back the slot of an `accept()` that failed or was cancelled. */
    fun cancelSlot() = slots.release()

    /** The lease of the slot [awaitSlot] took, for the client `accept()` returned. */
    fun lease(): TcpLease {
        open.addAndFetch(1)
        return TcpLease(this)
    }

    /**
     * Counts [lease]'s client under its address [key]: false when the address already holds [maxPerIp] connections (the
     * caller refuses the client and releases the lease). A client of unknown address (null) is not counted per address.
     * From the accept loop's coroutine only.
     */
    fun admit(
        lease: TcpLease,
        key: String?,
    ): Boolean {
        val max = maxPerIp ?: return true
        if (key == null) return true
        takeInReleased()
        val n = perIp[key] ?: 0
        if (n >= max) return false
        perIp[key] = n + 1
        lease.ipKey = key
        return true
    }

    /** Takes the addresses of released leases off [perIp]. */
    private fun takeInReleased() {
        while (true) {
            val key = left.tryReceive().getOrNull() ?: return
            val n = (perIp[key] ?: continue) - 1
            if (n <= 0) perIp.remove(key) else perIp[key] = n
        }
    }

    internal fun released(lease: TcpLease) {
        lease.ipKey?.let { left.trySend(it) } // an unlimited channel that is never closed: never fails
        open.addAndFetch(-1)
        slots.release()
    }
}

/** One accepted client's slot in [TcpLimits]; [release] gives it back, once, from any thread. */
internal class TcpLease(
    private val limits: TcpLimits,
) {
    private val done = AtomicBoolean(false)

    /** The address the client is counted under; set by the accept loop before the lease leaves it. */
    @Volatile internal var ipKey: String? = null

    fun release() {
        if (done.compareAndSet(false, true)) limits.released(this)
    }
}
