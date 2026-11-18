// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class, InternalKuicksilverApi::class)

package io.kuicksilver.http3.connectudp

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.http3.message.UdpHost
import io.kuicksilver.quic.ipLiteral
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch

/**
 * The key a client's limits are kept under: its IPv4 address, or its IPv6 address cut to [ipv6Prefix] bits (a /64 is one
 * subscriber's network: a client with a /64 must not count as 2^64 clients). An IPv4-mapped address is its IPv4 address.
 */
internal fun clientKey(
    remote: InetSocketAddress,
    ipv6Prefix: Int,
): String {
    val literal = remote.ipLiteral().substringBefore('%')
    UdpHost.parseIpv4(literal)?.let { return literal }
    val b = UdpHost.parseIpv6(literal) ?: return literal
    if ((0 until 10).all { b[it] == 0.toByte() } && b[10] == 0xff.toByte() && b[11] == 0xff.toByte()) {
        return (12 until 16).joinToString(".") { (b[it].toInt() and 0xff).toString() }
    }
    for (bit in ipv6Prefix until 128) {
        b[bit / 8] = (b[bit / 8].toInt() and (0x80 ushr (bit % 8)).inv()).toByte()
    }
    return UdpHost.ipv6Text(b) + "/" + ipv6Prefix
}

/**
 * A token bucket several coroutines share, without a lock: GCRA (the theoretical arrival time of the next packet, one
 * compare-and-set per take). [rate] per second, [burst] at once; [now] in nanoseconds.
 */
internal class SharedTokenBucket(
    rate: Int,
    burst: Int,
    private val now: () -> Long,
) {
    private val interval = 1_000_000_000L / rate.coerceAtLeast(1)
    private val tolerance = interval * burst.coerceAtLeast(1)
    private val tat = AtomicLong(Long.MIN_VALUE)

    fun tryTake(): Boolean {
        while (true) {
            val t = now()
            val old = tat.load()
            val base = if (old == Long.MIN_VALUE || old < t) t else old
            val next = base + interval
            if (next - t > tolerance) return false
            if (tat.compareAndSet(old, next)) return true
        }
    }
}

/**
 * The starts of the latest payloads a tunnel sent to its target, for the RFC 8085 section 5.2 check of an ICMP unreachable:
 * one that quotes none of them did not answer this tunnel's traffic. Fixed buffers, no allocation per datagram; written by
 * the tunnel's sender only, read by its watcher, each slot under a sequence number (odd while it is written) so a read that
 * overlaps a write is not trusted.
 */
internal class SentPrefixes {
    private val bytes = ByteArray(SLOTS * PREFIX)
    private val lens = IntArray(SLOTS)
    private val seq = Array(SLOTS) { AtomicInt(0) }
    private var next = 0 // the sender's only

    /** Keeps the start of `d[off, off + len)`. One thread at a time. */
    fun record(
        d: ByteArray,
        off: Int,
        len: Int,
    ) {
        val i = next
        next = (i + 1) % SLOTS
        val n = minOf(len, PREFIX)
        seq[i].incrementAndFetch() // odd: being written
        d.copyInto(bytes, i * PREFIX, off, off + n)
        lens[i] = n
        seq[i].incrementAndFetch()
    }

    /**
     * Whether [quote] is the start of one of the kept payloads and long enough to say so: at least [MIN_QUOTE] bytes, or
     * the whole payload when it was shorter. A forger guessing a byte or two would match too often.
     */
    fun matches(quote: ByteArray): Boolean {
        if (quote.isEmpty()) return false
        for (i in 0 until SLOTS) {
            val before = seq[i].load()
            if (before == 0 || before % 2 == 1) continue
            val n = lens[i]
            val ok =
                quote.size <= n && quote.size >= minOf(MIN_QUOTE, n) &&
                    (quote.indices).all { quote[it] == bytes[i * PREFIX + it] }
            if (ok && seq[i].load() == before) return true
        }
        return false
    }

    companion object {
        const val SLOTS = 16
        const val PREFIX = 64

        /** The shortest quote of a longer payload taken as evidence: a UDP payload start of 8 bytes. */
        const val MIN_QUOTE = 8
    }
}

/** How many payloads a client sent to one target and whether that target ever answered (RFC 9298 section 7). */
internal class TargetAnswer {
    val sent = AtomicLong(0)
    val answered = AtomicBoolean(false)
}

/**
 * What a proxy keeps per client ([clientKey]) across its tunnels: how many are open, one token bucket for all of them (a
 * client's 64 tunnels share one rate), and per target whether it answered, so reopening a tunnel to a silent target does not
 * give a fresh `unansweredLimit`. Kept a retention period after the last tunnel closed (the proxy's lock).
 */
internal class ClientState(
    val bucket: SharedTokenBucket,
) {
    var tunnels = 0
    var idleSince = 0L

    /** Name lookups of this client not returned yet (a blocking one counts until its call returns). */
    val lookups = AtomicInt(0)

    /** At most [MAX_TARGETS] targets, the oldest forgotten first. */
    private val targets = LinkedHashMap<String, TargetAnswer>()

    /** The record of [target]; under the proxy's lock. */
    fun answerFor(target: InetSocketAddress): TargetAnswer {
        val k = target.ipLiteral() + "|" + target.port
        targets.remove(k)?.let {
            targets[k] = it // most recent last
            return it
        }
        if (targets.size >= MAX_TARGETS) targets.remove(targets.keys.first())
        return TargetAnswer().also { targets[k] = it }
    }

    companion object {
        const val MAX_TARGETS = 256
    }
}
