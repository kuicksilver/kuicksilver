// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.quic.TimeMark

/**
 * The per-connection "glitch" token bucket (after ngtcp2; RFC 9000 section 21.9): every action of the peer
 * that costs us work but moves nothing forward spends a token, [refillPerSecond] come back per second up to
 * [capacity], and an empty bucket closes the connection with PROTOCOL_VIOLATION. Honest peers never spend: a
 * retransmission, a keep-alive PING or a real flow-control update is not a glitch.
 */
internal class GlitchBucket(
    private val capacity: Int,
    private val refillPerSecond: Int,
) {
    var tokens: Int = capacity
        private set

    /** Tokens spent over the connection's life, for `ConnectionStats.glitchTokensSpent`. */
    var spent: Long = 0L
        private set
    private var last: TimeMark = TimeMark.NEVER
    private var carryNanos: Long = 0

    /** Spends [cost] tokens at [now]; false when the bucket cannot cover it (the caller closes the connection). */
    fun spend(
        now: TimeMark,
        cost: Int = 1,
    ): Boolean {
        refill(now)
        spent += cost
        if (tokens < cost) {
            tokens = 0
            return false
        }
        tokens -= cost
        return true
    }

    private fun refill(now: TimeMark) {
        if (last == TimeMark.NEVER || now <= last) {
            if (last == TimeMark.NEVER) last = now
            return
        }
        carryNanos += (now - last).inWholeNanoseconds
        last = now
        val add = carryNanos * refillPerSecond / 1_000_000_000L
        if (add > 0) {
            carryNanos -= add * 1_000_000_000L / refillPerSecond
            tokens = minOf(capacity.toLong(), tokens + add).toInt()
        }
        if (tokens >= capacity) carryNanos = 0
    }
}
