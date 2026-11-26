// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.flow

import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.wire.QuicWireException
import kotlin.time.Duration

/**
 * Receive-side flow control of a stream or of the connection (RFC 9000 section 4.1): the peer may send up
 * to [limit]; a credit update goes out once a quarter of the window was consumed. Auto-tuning follows quic-go
 * (`flow_controller_base.go` `maybeAdjustWindowSize`): an epoch starts at the first read; at an update, once more than
 * half a window was read in the epoch, the window doubles (up to [maxWindow]) when that part took less than
 * 4 x fraction x sRTT — the application reads a whole window in under four RTTs, so the window limits the peer — and a
 * new epoch starts. The window settles at 4-8 x the bandwidth-delay product of what the application reads.
 */
internal class RecvFlowController(
    initialWindow: Long,
    private val maxWindow: Long,
) {
    var window: Long = initialWindow
        private set
    var limit: Long = minOf(initialWindow, MAX_LIMIT)
        private set
    private var consumed: Long = 0

    /** A lower bound of the window set from outside the auto-tuning ([setFloor]); 0 by default. */
    private var floor: Long = 0

    /** The window in effect: the auto-tuned one, or the floor when that is larger. */
    private val effective: Long get() = maxOf(window, floor)
    private var epochStart: TimeMark = TimeMark.NEVER
    private var epochStartOffset: Long = 0

    /** Checks the highest offset (or total) the peer would have sent: above [limit] it is a FLOW_CONTROL_ERROR. Changes nothing (the caller keeps the count). */
    fun onData(endOffset: Long) {
        if (endOffset >
            limit
        ) {
            throw QuicWireException(TransportError.FLOW_CONTROL_ERROR, 0, "data beyond the flow control limit: $endOffset > $limit")
        }
    }

    /** The application took [bytes]; returns the new limit to advertise, or -1 when no update is due (no boxing on the read path). */
    fun onConsumed(
        bytes: Long,
        now: TimeMark,
        smoothedRtt: Duration,
    ): Long {
        if (epochStart == TimeMark.NEVER) {
            epochStart = now
            epochStartOffset = consumed
        }
        consumed += bytes
        val w = effective
        if (limit - consumed > w - w / 4) return -1
        val inEpoch = consumed - epochStartOffset
        if (inEpoch > window / 2) {
            // elapsed < 4 x (inEpoch / window) x sRTT, multiplied out in doubles (no division, no Long overflow)
            val elapsed = (now - epochStart).inWholeNanoseconds.toDouble()
            if (elapsed * window < 4.0 * inEpoch * smoothedRtt.inWholeNanoseconds && window < maxWindow) {
                window = minOf(window * 2, maxWindow)
            }
            epochStart = now
            epochStartOffset = consumed
        }
        val next = advertised(consumed, effective)
        // no update when nothing grew: at the clamp (2^62-1) no credit is left to give, and after a lower floor or a smaller
        // window the new limit may be below the last one, which stands (an advertised limit never goes down)
        if (next <= limit) return -1
        limit = next
        return limit
    }

    /**
     * Sets the floor of the window to [w] (capped at the ceiling): the window in effect is never below it, while the
     * auto-tuning goes on beneath. A lower floor applies to the limits advertised from then on (an advertised limit never
     * shrinks). True when the limit grew (a MAX_DATA is due).
     */
    fun setFloor(w: Long): Boolean {
        floor = minOf(maxOf(w, 0L), maxWindow)
        val l = advertised(consumed, effective)
        if (l > limit) {
            limit = l
            return true
        }
        return false
    }

    /** Keeps this (connection) window at least [w], capped at the ceiling: the connection window follows the stream windows. True when the limit grew (a MAX_DATA is due). */
    fun ensureWindowAtLeast(w: Long): Boolean {
        val target = minOf(w, maxWindow)
        if (target <=
            window
        ) {
            return false
        }
        window = target
        val l = advertised(consumed, window)
        if (l > limit) {
            limit = l
            return true
        }
        return false
    }
}

/**
 * The largest limit MAX_DATA and MAX_STREAM_DATA can carry, 2^62-1 (RFC 9000 sections 16, 19.9 and 19.10: a variable-length
 * integer); a credit of [consumed] + window is clamped to it (2^62-1 bytes is never reached, but the arithmetic must not
 * advertise more).
 */
internal const val MAX_LIMIT: Long = (1L shl 62) - 1

/** `consumed + window`, at most [MAX_LIMIT]. */
internal fun advertised(
    consumed: Long,
    window: Long,
): Long = if (window > MAX_LIMIT - consumed) MAX_LIMIT else consumed + window
