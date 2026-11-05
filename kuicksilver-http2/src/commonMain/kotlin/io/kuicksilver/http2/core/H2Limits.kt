// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

/**
 * A token bucket on virtual time: [burst] tokens, refilled at [perSecond] per second (0: never), like nghttp2's
 * `nghttp2_ratelim`.
 * A connection has two: a server's budget for the client's RST_STREAM frames (Rapid Reset, CVE-2023-44487) and the glitch
 * budget for suspicious frames and the stream errors the peer causes (MadeYouReset, CVE-2025-8671); an empty bucket ends
 * the connection. Tokens are kept in billionths so the refill needs no division per call.
 */
internal class TokenBucket(
    private val burst: Int,
    private val perSecond: Int,
    now: Long,
) {
    private val capacity = burst.toLong() * UNIT
    private var tokens = capacity
    private var last = now

    /** Takes one token at [now] (nanoseconds); false when the bucket is empty. */
    fun take(now: Long): Boolean {
        val elapsed = now - last
        if (elapsed > 0 && perSecond > 0) {
            last = now
            // elapsed ns x perSecond tokens/s = elapsed x perSecond billionths; cap first so the product cannot overflow
            tokens = if (elapsed >= capacity / perSecond) capacity else minOf(capacity, tokens + elapsed * perSecond)
        }
        if (tokens < UNIT) return false
        tokens -= UNIT
        return true
    }

    private companion object {
        const val UNIT = 1_000_000_000L
    }
}

/**
 * Collects one field block (HEADERS or PUSH_PROMISE and its CONTINUATION frames, RFC 9113 section 4.3) within the
 * limits of section 3.23 of the threat model, before HPACK sees any of it: at most [maxBytes] compressed bytes (the core
 * passes twice SETTINGS_MAX_HEADER_LIST_SIZE, as Go's frame.go readMetaFrame) and
 * [maxContinuations] CONTINUATION frames (CVE-2023-45288, CVE-2024-27316). Over a limit, [add] returns false and the
 * connection ends; the buffer never holds more than [maxBytes].
 */
internal class HeaderBlockCollector(
    private val maxBytes: Int,
    private val maxContinuations: Int,
) {
    private var buf = ByteArray(0)
    var size: Int = 0
        private set
    var continuations: Int = 0
        private set

    /** Adds a fragment; false when the block passes a limit (nothing is kept then). */
    fun add(
        fragment: ByteArray,
        continuation: Boolean,
    ): Boolean {
        if (continuation && ++continuations > maxContinuations) return false
        if (fragment.size > maxBytes - size) return false
        if (size + fragment.size > buf.size) buf = buf.copyOf(minOf(maxBytes, maxOf(buf.size * 2, size + fragment.size)))
        fragment.copyInto(buf, size)
        size += fragment.size
        return true
    }

    /** The block collected so far (a copy). */
    fun block(): ByteArray = buf.copyOf(size)

    /** The largest buffer this collector held (a test hook). */
    val capacity: Int get() = buf.size

    fun reset() {
        buf = ByteArray(0)
        size = 0
        continuations = 0
    }
}
