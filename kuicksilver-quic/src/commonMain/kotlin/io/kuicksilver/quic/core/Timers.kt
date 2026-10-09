// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.quic.TimeMark
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/** Deadlines of a connection besides loss detection: handshake, idle, keep-alive and the closing period (RFC 9000 section 10). */
internal class Timers {
    var handshakeDeadline: TimeMark? = null
    var lastActivity: TimeMark = TimeMark(0)
    var lastAckElicitingSent: TimeMark = TimeMark.NEVER
    var closeDeadline: TimeMark? = null
    var lastCloseSent: TimeMark? = null
    var keepAlivePending: Boolean = false

    /** Set by the first ack-eliciting send after a receipt; RFC 9000 section 10.1 lets only that send restart the idle timer. */
    var ackElicitingSentSinceReceive: Boolean = false

    /** Effective idle timeout: the smaller of both peers' values, never below 3 x PTO (RFC 9000 section 10.1); INFINITE when neither side set one. */
    fun effectiveIdle(
        local: Duration,
        peerMs: Long,
        pto: Duration,
    ): Duration {
        val peer = peerMs.milliseconds // ZERO when the peer sent none
        val base =
            when {
                local == Duration.ZERO && peerMs <= 0 -> return Duration.INFINITE

                local == Duration.ZERO -> peer

                peerMs <= 0 -> local

                local <
                    peer -> local

                else -> peer
            }
        val floor = pto * 3
        return if (base > floor) base else floor
    }
}
