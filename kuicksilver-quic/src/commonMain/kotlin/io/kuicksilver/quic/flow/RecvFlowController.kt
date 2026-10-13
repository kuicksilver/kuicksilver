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
    var limit: Long = initialWindow
        private set
    private var consumed: Long = 0
    private var received: Long = 0
    private var epochStart: TimeMark = TimeMark.NEVER
    private var epochStartOffset: Long = 0

    /** The highest offset (or total) the peer has sent; above [limit] it is a FLOW_CONTROL_ERROR. */
    fun onData(endOffset: Long) {
        if (endOffset >
            limit
        ) {
            throw QuicWireException(TransportError.FLOW_CONTROL_ERROR, 0, "data beyond the flow control limit: $endOffset > $limit")
        }
        if (endOffset > received) received = endOffset
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
        if (limit - consumed > window - window / 4) return -1
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
        limit = consumed + window
        return limit
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
        val l = consumed + window
        if (l > limit) {
            limit = l
            return true
        }
        return false
    }
}
