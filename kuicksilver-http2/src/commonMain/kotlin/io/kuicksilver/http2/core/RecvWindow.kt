// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

/**
 * Receive-side flow control of a stream or of the connection (RFC 9113 sections 5.2, 6.9): the peer may send up to
 * [limit] bytes in total; credit goes back with WINDOW_UPDATE only as the application consumes (back-pressure), once a
 * quarter of the window was consumed. Auto-tuning as in kuicksilver-quic's `RecvFlowController` (after quic-go's
 * `maybeAdjustWindowSize`): when more than half a window was read in an epoch shorter than 4 x fraction x RTT, the
 * window doubles up to [maxWindow]. Every count is a Long; a window never exceeds 2^31 - 1.
 */
internal class RecvWindow(
    initialWindow: Long,
    private val maxWindow: Long,
) {
    var window: Long = initialWindow
        private set
    var limit: Long = initialWindow
        private set
    var received: Long = 0
        private set
    private var consumed: Long = 0
    private var epochStart = Long.MIN_VALUE
    private var epochStartOffset = 0L

    /** Counts [n] received bytes; false when they pass the limit (a FLOW_CONTROL_ERROR). */
    fun onData(n: Int): Boolean {
        received += n
        return received <= limit
    }

    /** Moves the limit by [delta] (our SETTINGS_INITIAL_WINDOW_SIZE changed, RFC 9113 section 6.9.2). */
    fun adjust(
        delta: Long,
        newWindow: Long,
    ) {
        limit += delta
        window = newWindow
    }

    /**
     * The application took [n] bytes at [now] (nanoseconds) with [rttNanos] as the round-trip estimate; returns the
     * WINDOW_UPDATE increment that is due, or 0.
     */
    fun onConsumed(
        n: Long,
        now: Long,
        rttNanos: Long,
    ): Int {
        if (epochStart == Long.MIN_VALUE) {
            epochStart = now
            epochStartOffset = consumed
        }
        consumed += n
        if (limit - consumed > window - window / 4) return 0
        val inEpoch = consumed - epochStartOffset
        if (inEpoch > window / 2) {
            // elapsed < 4 x (inEpoch / window) x RTT, multiplied out in doubles (no division, no Long overflow)
            val elapsed = (now - epochStart).toDouble()
            if (elapsed * window < 4.0 * inEpoch * rttNanos && window < maxWindow) window = minOf(window * 2, maxWindow)
            epochStart = now
            epochStartOffset = consumed
        }
        val newLimit = consumed + window
        if (newLimit <= limit) return 0
        val inc = newLimit - limit
        limit = newLimit
        return inc.toInt()
    }
}
