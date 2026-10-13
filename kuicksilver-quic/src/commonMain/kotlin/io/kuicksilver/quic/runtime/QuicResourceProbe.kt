// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.withContext
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * The sizes of every live endpoint loop's tables, for the soak harness (`kuicksilver-soak`): connections, connection IDs,
 * the per-IP and per-remote maps, the timer heap, the accept, admission and stateless queues, the 0-RTT replay register
 * and the client session cache. Off by default: only loops started while [enabled] is true are tracked, so production
 * pays one volatile read per endpoint bind and nothing per datagram.
 */
@InternalKuicksilverApi
@OptIn(ExperimentalAtomicApi::class)
public object QuicResourceProbe {
    /** Tracks loops started from now on; loops started before stay untracked. */
    @Volatile public var enabled: Boolean = false

    private val loops = AtomicReference<List<EndpointLoop>>(emptyList())

    internal fun register(loop: EndpointLoop) {
        if (!enabled) return
        while (true) {
            val l = loops.load()
            if (loops.compareAndSet(l, l + loop)) return
        }
    }

    internal fun unregister(loop: EndpointLoop) {
        while (true) {
            val l = loops.load()
            if (loop !in l || loops.compareAndSet(l, l - loop)) return
        }
    }

    /**
     * One snapshot, summed over the tracked loops (`quic.loops` counts them); each loop is read on its own dispatcher, so
     * the tables are never read while their owner changes them. A loop's 0-RTT replay register is shared by its group and
     * counted once per loop.
     */
    @OptIn(ExperimentalKuicksilverApi::class)
    public suspend fun snapshot(): Map<String, Long> {
        val out = LinkedHashMap<String, Long>()
        for (k in keys) out[k] = 0L
        val tracked = loops.load()
        out["quic.loops"] = tracked.size.toLong()
        for (loop in tracked) {
            val one =
                withContext(loop.dispatcher) {
                    val c = loop.core
                    longArrayOf(
                        c.connections.size.toLong(),
                        loop.runtimes.size.toLong(),
                        loop.runtimes.values
                            .sumOf { it.streams.size }
                            .toLong(),
                        c.registry.size.toLong(),
                        c.perIp.size.toLong(),
                        c.byRemote.size.toLong(),
                        loop.timers.count.toLong(),
                        c.accepted.size.toLong(),
                        loop.pendingAcceptForTest.toLong(),
                        loop.handshakingForTest.toLong(),
                        (c.queue?.size ?: 0).toLong(),
                        c.stateless.size.toLong(),
                        c.limiter.addresses.toLong(),
                        c.earlyPendingForTest.toLong(),
                        (c.serverEarly?.register?.liveEntries() ?: 0).toLong(),
                        activeJobs(loop.scope.coroutineContext[Job]!!),
                    )
                }
            val sessions = loop.sessions.size().toLong()
            for (i in one.indices) out[keys[i]] = out.getValue(keys[i]) + one[i]
            out["quic.sessionCache"] = out.getValue("quic.sessionCache") + sessions
        }
        return out
    }

    /** Coroutines still active below [root] ([root] excluded): a receiver or a pump that never ends shows here. */
    private fun activeJobs(root: Job): Long = root.children.sumOf { (if (it.isActive) 1L else 0L) + activeJobs(it) }

    private val keys =
        listOf(
            "quic.connections",
            "quic.runtimes",
            "quic.streams",
            "quic.cids",
            "quic.perIp",
            "quic.byRemote",
            "quic.timerHeap",
            "quic.acceptedQueue",
            "quic.pendingAccept",
            "quic.handshaking",
            "quic.admissionQueue",
            "quic.statelessQueue",
            "quic.statelessLimiter",
            "quic.earlyPending",
            "quic.replayLive",
            "quic.loopJobs",
            "quic.sessionCache",
        )
}
