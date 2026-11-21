// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h3

import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * Origin hosts whose QUIC connections must not resume (no session ticket, no 0-RTT) for a while: a resumed handshake there
 * ended with `QuicException.ConnectionLost.ServerConnectionIdChanged`. That is an msquic server (IIS, .NET Kestrel on
 * Windows) given a ClientHello of 3 or more datagrams, which the pre-shared key and GREASE ECH make of a resumption one
 * (msquic#3762, #4905); a full handshake's ClientHello fits 2 datagrams, which msquic answers correctly, so HTTP/3 stays in
 * use with full handshakes instead of the alternative being marked broken.
 *
 * The backoff is the broken alternatives' schedule ([io.kuicksilver.ktor.client.BrokenAltSvc]): 5 minutes, doubling at each
 * new mark of the host up to 2 days, all forgotten when the network changes. A mark ends on whichever of the monotonic
 * [clock] and the [wallClock] (which goes on while a device sleeps) gets there first. At most [MAX_HOSTS] hosts are kept,
 * the least recently marked dropped first. Safe to call from any thread (one immutable map, replaced by compare-and-set).
 *
 * Only a failure of a handshake that offered resumption marks a host (`ServerConnectionIdChanged.resumptionOffered`): the
 * same failure on a full handshake marks the alternative broken instead, as nothing would get better by not resuming. The
 * backoff is the pool's: with a session cache the application shares between engines, this engine drops the host's
 * tickets from it, and another engine marks the host on its own failure.
 */
@OptIn(ExperimentalAtomicApi::class)
internal class ResumptionBackoff(
    private val clock: () -> Long,
    private val wallClock: () -> Long = clock,
) {
    private class Mark(
        val until: Long,
        val untilWall: Long,
        val level: Int,
    )

    private val marks = AtomicReference<Map<String, Mark>>(emptyMap())

    private fun update(change: (Map<String, Mark>) -> Map<String, Mark>) {
        while (true) {
            val now = marks.load()
            if (marks.compareAndSet(now, change(now))) return
        }
    }

    /** [host]'s resumed handshake failed so: no resumption for the next backoff period, one level longer than the last. */
    fun mark(host: String) {
        val now = clock()
        val wall = wallClock()
        update { m ->
            val level = m[host]?.let { it.level + 1 } ?: 0
            val duration = (BASE_MILLIS shl minOf(level, 20)).coerceAtMost(MAX_MILLIS)
            val next = LinkedHashMap(m)
            next.remove(host)
            next[host] = Mark(now + duration, wall + duration, level)
            while (next.size > MAX_HOSTS) next.remove(next.keys.first())
            next
        }
    }

    /** Whether connections to [host] must not resume now. */
    fun avoids(host: String): Boolean = marks.load()[host]?.let { it.until > clock() && it.untilWall > wallClock() } ?: false

    /** Forgets [host]'s mark and its level (`clearAlternativeServices` of an origin of it). */
    fun clear(host: String) = update { it - host }

    /** Forgets every mark: the backoff belongs to the network it was seen on. */
    fun onNetworkChanged() = update { emptyMap() }

    /** The backoff level of [host]'s mark, live or expired, or -1 without one (tests). */
    fun levelForTest(host: String): Int = marks.load()[host]?.level ?: -1

    /** Ends [host]'s mark now and keeps its level, as the passing of its backoff would (tests). */
    fun expireForTest(host: String) =
        update { m ->
            val old = m[host] ?: return@update m
            m + (host to Mark(clock() - 1, wallClock() - 1, old.level))
        }

    companion object {
        /** The first period: 5 minutes. */
        const val BASE_MILLIS: Long = 5 * 60_000L

        /** The longest period: 2 days. */
        const val MAX_MILLIS: Long = 2 * 24 * 3_600_000L

        /** Hosts kept at most. */
        const val MAX_HOSTS: Int = 1024
    }
}
