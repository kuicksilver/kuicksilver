// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.concurrent.Volatile
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeMark
import kotlin.time.TimeSource

/**
 * The opt-in backoff of `http2RepeatOffenderPenalty` (threat model 3.23): client addresses whose HTTP/2 connections keep
 * ending in a flood defence (GOAWAY ENHANCE_YOUR_CALM from a flood limit: Rapid Reset, MadeYouReset, CONTINUATION, PING
 * or SETTINGS floods; not a slow field block). The core already ends each such connection; this makes a client that just
 * reconnects and floods again pay too: [strikes] of them within [window] refuse the address's next TCP connections for
 * [penalty], at accept and before any TLS work. Every client behind one shared address (a NAT, an L4 load balancer or a
 * proxy that does not keep client addresses) is refused with the flooder, which is why it is off by default.
 *
 * Keys: an IPv4 address (an IPv4-mapped IPv6 address, as a dual-stack listener reports IPv4 peers, counts as its IPv4
 * address), and an IPv6 address by its /56: end sites are assigned a /56 or a /48 (RFC 6177), so a client can move within
 * its /56 at will; a /48 would refuse more bystanders. At most [maxTracked] addresses are remembered: addresses that only
 * struck are forgotten first (oldest first), one serving a penalty only when every remembered one does, and a refusal
 * keeps the refused address fresh, so a stream of new addresses does not cut a penalty short. Safe to call from any
 * coroutine: a [Mutex], never a spinning lock; the accept loop skips it while the table is empty.
 */
internal class RepeatOffenders(
    private val penalty: Duration,
    private val strikes: Int = 3,
    private val window: Duration = 60.seconds,
    private val maxTracked: Int = 4_096,
    private val timeSource: TimeSource = TimeSource.Monotonic,
) {
    private class Entry {
        val marks = ArrayDeque<TimeMark>()
        var refusedUntil: TimeMark? = null
    }

    private val lock = Mutex()
    private val entries = LinkedHashMap<String, Entry>()

    /** Entries in [entries]: the accept loop skips the lock and the key while it is 0, the usual case. */
    @Volatile private var size = 0

    /** Records one flood-ended connection of [remote]; true when it starts a penalty (the caller logs that). */
    suspend fun strike(remote: InetSocketAddress?): Boolean {
        val key = keyOf(remote) ?: return false
        val now = timeSource.markNow()
        return lock.withLock {
            val e = entries.remove(key) ?: Entry()
            entries[key] = e // the most recent last
            evict()
            while (e.marks.isNotEmpty() && e.marks.first().elapsedNow() >= window) e.marks.removeFirst()
            e.marks.addLast(now)
            size = entries.size
            if (e.marks.size < strikes) return@withLock false
            e.marks.clear()
            e.refusedUntil = now + penalty
            true
        }
    }

    /** True while [remote] serves a penalty: its connection is closed at accept. */
    suspend fun refuses(remote: InetSocketAddress?): Boolean {
        if (size == 0 || remote == null) return false
        val key = keyOf(remote) ?: return false
        return lock.withLock {
            val e = entries[key] ?: return@withLock false
            val until = e.refusedUntil ?: return@withLock false
            if (until.hasNotPassedNow()) {
                entries.remove(key)
                entries[key] = e // still refused: kept fresh against eviction
                return@withLock true
            }
            e.refusedUntil = null
            if (e.marks.isEmpty()) entries.remove(key)
            size = entries.size
            false
        }
    }

    /** Over [maxTracked]: the oldest entry that serves no penalty goes, else the oldest. Under [lock]. */
    private fun evict() {
        while (entries.size > maxTracked) {
            val victim = entries.entries.firstOrNull { it.value.refusedUntil?.hasNotPassedNow() != true }?.key ?: entries.keys.first()
            entries.remove(victim)
        }
    }

    /** Addresses remembered (a test hook for the bound). */
    suspend fun tracked(): Int = lock.withLock { entries.size }

    companion object {
        /** The address as the table counts it, for a log line: a.b.c.d, or an IPv6 /56; never a name (no lookup). */
        fun describe(remote: InetSocketAddress?): String =
            remote?.let { peerAddressBytes(it) }?.let { describe(it) } ?: "an unknown address"

        /** [describe] of address bytes (4 or 16). */
        fun describe(bytes: ByteArray): String = describeIp(bytes, IPV6_PREFIX_BYTES)

        /** The table's key of address bytes: an IPv4 address (mapped ones included) whole, an IPv6 address by its /56 ([ipKey]). */
        fun keyOf(bytes: ByteArray): String = ipKey(bytes, IPV6_PREFIX_BYTES)

        /** The table's key of [remote] ([peerIpKey]). */
        fun keyOf(remote: InetSocketAddress?): String? = peerIpKey(remote, IPV6_PREFIX_BYTES)

        /** /56 */
        private const val IPV6_PREFIX_BYTES = 7
    }
}
