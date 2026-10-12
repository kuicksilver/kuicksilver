// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.flow

/** Send-side credit of a stream or the connection (RFC 9000 section 4.1): limits only grow; one DATA_BLOCKED per limit. */
internal class SendFlowController(
    initialLimit: Long,
) {
    private var limit: Long = initialLimit
    private var sent: Long = 0
    private var blockedReportedAt: Long = -1

    val available: Long get() = limit - sent
    val maxLimit: Long get() = limit

    /** Credit consumed so far (the highest offset sent). */
    val used: Long get() = sent

    fun consume(bytes: Long) {
        require(bytes <= available) { "flow control credit exceeded" }
        sent += bytes
    }

    /** True when the limit grew; a MAX_DATA/MAX_STREAM_DATA that does not is ignored (RFC 9000 section 4.1) and counts as a glitch. */
    fun onMaxUpdate(limit: Long): Boolean {
        if (limit <= this.limit) return false
        this.limit = limit
        return true
    }

    /** The limit to report in DATA_BLOCKED / STREAM_DATA_BLOCKED when blocked at it for the first time, else -1. */
    fun takeBlocked(): Long {
        if (available > 0 || blockedReportedAt == limit) return -1
        blockedReportedAt = limit
        return limit
    }
}
