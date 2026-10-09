// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.message

/**
 * Token bucket for useless peer work (after nghttp3's glitch limiter): unknown frames on the control stream,
 * empty unidirectional streams, PRIORITY_UPDATE floods. Time is a parameter (sans-IO): nanoseconds on any monotonic clock.
 */
internal class GlitchLimiter(
    private val capacity: Int = 1000,
    private val perSecond: Int = 33,
) {
    private var available = capacity.toDouble()
    private var last = Long.MIN_VALUE

    /** Spends [n] tokens at [nowNanos]; false once the bucket is empty (the caller closes with H3_EXCESSIVE_LOAD). */
    fun spend(
        nowNanos: Long,
        n: Int = 1,
    ): Boolean {
        if (last != Long.MIN_VALUE &&
            nowNanos > last
        ) {
            available = minOf(capacity.toDouble(), available + (nowNanos - last) * perSecond / 1e9)
        }
        last = nowNanos
        if (available < n) return false
        available -= n
        return true
    }
}
