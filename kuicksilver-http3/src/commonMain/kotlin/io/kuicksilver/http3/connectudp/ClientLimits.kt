// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class, InternalKuicksilverApi::class)

package io.kuicksilver.http3.connectudp

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.http3.message.UdpHost
import io.kuicksilver.quic.ipLiteral
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi

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
