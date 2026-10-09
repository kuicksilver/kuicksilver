// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.flow

import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.wire.QuicWireException
import kotlin.time.Duration

/**
 * Receive-side flow control of a stream or of the connection (RFC 9000 section 4.1): the peer may send up
 * to [limit]; a credit update goes out once a quarter of the window was consumed, and the window doubles (up to
 * [maxWindow]) when updates come faster than two RTTs — the receiver is reading faster than the window allows.
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
    private var lastUpdate: TimeMark = TimeMark.NEVER

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
        consumed += bytes
        if (limit - consumed > window - window / 4) return -1
        val last = lastUpdate
        if (last != TimeMark.NEVER && now - last < smoothedRtt * 2 && window < maxWindow) window = minOf(window * 2, maxWindow)
        lastUpdate = now
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
