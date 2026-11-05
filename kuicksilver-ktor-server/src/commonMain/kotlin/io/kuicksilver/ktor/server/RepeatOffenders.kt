// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeMark
import kotlin.time.TimeSource

/**
 * Client addresses whose HTTP/2 connections keep ending in a flood defence (GOAWAY ENHANCE_YOUR_CALM: Rapid Reset,
 * MadeYouReset, CONTINUATION, PING or SETTINGS floods, a trickled field block; threat model 3.23). The core already ends
 * each such connection; this makes a client that just reconnects and floods again pay too: [strikes] of them within
 * [window] refuse the address's next TCP connections for [penalty], at accept and before any TLS work. Defaults: 3
 * within a minute, then 30 seconds. An IPv6 address counts by its /64, the usual prefix of one site (RFC 6177): a client
 * holds all of it, so a full address would be one new address away. At most [maxTracked] addresses are remembered, the
 * oldest first forgotten, so an attacker with many addresses costs bounded memory (and those addresses still meet the
 * per-connection limits). Safe to call from any thread.
 */
internal class RepeatOffenders(
    private val strikes: Int = 3,
    private val window: Duration = 60.seconds,
    private val penalty: Duration = 30.seconds,
    private val maxTracked: Int = 4_096,
    private val timeSource: TimeSource = TimeSource.Monotonic,
) {
    private class Entry {
        val marks = ArrayDeque<TimeMark>()
        var refusedUntil: TimeMark? = null
    }

    private val lock = AtomicInt(0)
    private val entries = LinkedHashMap<String, Entry>()

    private inline fun <T> locked(block: () -> T): T {
        while (!lock.compareAndSet(0, 1)) {
            // a few map operations under the lock; nothing in it suspends or blocks
        }
        try {
            return block()
        } finally {
            lock.store(0)
        }
    }

    /** Records one ENHANCE_YOUR_CALM for [remote]; true when it starts a penalty (the caller logs that). */
    fun strike(remote: InetSocketAddress?): Boolean {
        val key = keyOf(remote) ?: return false
        val now = timeSource.markNow()
        return locked {
            val e = entries.remove(key) ?: Entry()
            entries[key] = e // the most recent last: the oldest is forgotten first
            while (entries.size > maxTracked) entries.remove(entries.keys.first())
            while (e.marks.isNotEmpty() && e.marks.first().elapsedNow() >= window) e.marks.removeFirst()
            e.marks.addLast(now)
            if (e.marks.size < strikes) return@locked false
            e.marks.clear()
            e.refusedUntil = now + penalty
            true
        }
    }

    /** True while [remote] serves a penalty: its connection is closed at accept. */
    fun refuses(remote: InetSocketAddress?): Boolean {
        val key = keyOf(remote) ?: return false
        return locked {
            val e = entries[key] ?: return@locked false
            val until = e.refusedUntil ?: return@locked false
            if (until.hasNotPassedNow()) return@locked true
            e.refusedUntil = null
            if (e.marks.isEmpty()) entries.remove(key)
            false
        }
    }

    /** Addresses remembered (a test hook for the bound). */
    val tracked: Int get() = locked { entries.size }

    companion object {
        /** The address as the table counts it, for a log line: a.b.c.d, or an IPv6 /64; never a name (no lookup). */
        fun describe(remote: InetSocketAddress?): String {
            val bytes = remote?.resolveAddress() ?: return "an unknown address"
            if (bytes.size != 16) return bytes.joinToString(".") { (it.toInt() and 0xff).toString() }
            return (0 until 4).joinToString(":", postfix = "::/64") { i ->
                (((bytes[2 * i].toInt() and 0xff) shl 8) or (bytes[2 * i + 1].toInt() and 0xff)).toString(16)
            }
        }

        /** The address bytes (never a name: no lookup), an IPv6 address cut to its /64. */
        private fun keyOf(remote: InetSocketAddress?): String? {
            val bytes = remote?.resolveAddress() ?: return null
            val n = if (bytes.size == 16) 8 else bytes.size
            val sb = StringBuilder(n * 2 + 2)
            sb.append(bytes.size).append(':')
            for (i in 0 until n) {
                val b = bytes[i].toInt() and 0xff
                sb.append(HEX[b shr 4]).append(HEX[b and 0xf])
            }
            return sb.toString()
        }

        private const val HEX = "0123456789abcdef"
    }
}
