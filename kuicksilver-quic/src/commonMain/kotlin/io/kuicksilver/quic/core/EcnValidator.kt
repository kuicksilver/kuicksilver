// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.EcnState

/**
 * Per-path ECN validation (RFC 9000 section 13.4.2): the first ten packets go out with ECT(0); the peer's ACK_ECN counts
 * must appear, never decrease, and cover every newly acknowledged marked packet; ECT(1) counts mean the marks were
 * rewritten; losing all ten test packets fails too. A failed path never marks again. CE growth is reported to the caller,
 * who turns it into one congestion event per recovery period.
 */
internal class EcnValidator {
    var state: EcnState = EcnState.Disabled
        private set
    private var testingSent = 0
    private var testingLost = 0

    /** The peer's last reported counts per packet number space (ECT(0), ECT(1), CE). */
    private val peer = Array(3) { LongArray(3) }
    private val peerSeen = BooleanArray(3)
    val peerCountsForTest: LongArray get() = peer[2]

    fun enable() {
        if (state == EcnState.Disabled) state = EcnState.Testing
    }

    fun disable() {
        if (state == EcnState.Testing || state == EcnState.Unknown) state = EcnState.Disabled
    }

    /** The codepoint for the next datagram on this path. */
    fun markFor(): Ecn =
        when (state) {
            EcnState.Testing, EcnState.Unknown, EcnState.Capable -> Ecn.Ect0
            else -> Ecn.NotEct
        }

    fun onSent(marked: Boolean) {
        if (marked &&
            state == EcnState.Testing
        ) {
            testingSent++
            if (testingSent >= TEST_PACKETS) state = EcnState.Unknown
        }
    }

    /** One ACK frame of [space]: validates the counts; true when the CE count grew (a congestion signal). */
    fun onAck(
        space: Int,
        ecn: LongArray?,
        newlyAckedMarked: Int,
    ): Boolean {
        if (state == EcnState.Disabled || state == EcnState.Failed) return false
        if (ecn == null) {
            if (newlyAckedMarked > 0) state = EcnState.Failed
            return false
        } // marked packets acknowledged without counts (section 13.4.2.1)
        val p = peer[space]
        if (peerSeen[space] && (ecn[0] < p[0] || ecn[1] < p[1] || ecn[2] < p[2])) {
            state = EcnState.Failed
            return false
        } // counts never decrease
        val increase = (ecn[0] + ecn[1] + ecn[2]) - (if (peerSeen[space]) p[0] + p[1] + p[2] else 0L)
        if (increase < newlyAckedMarked) {
            state = EcnState.Failed
            return false
        } // every newly acknowledged marked packet must be counted
        if (ecn[1] > 0) {
            state = EcnState.Failed
            return false
        } // we send ECT(0) only: ECT(1) means the network rewrote the marks
        val ceGrew = (peerSeen[space] && ecn[2] > p[2]) || (!peerSeen[space] && ecn[2] > 0)
        p[0] = ecn[0]
        p[1] = ecn[1]
        p[2] = ecn[2]
        peerSeen[space] = true
        if (newlyAckedMarked > 0 && state != EcnState.Capable) state = EcnState.Capable
        return ceGrew
    }

    /** A PTO expired while the test packets were still unacknowledged: an ECN black hole gives no ACKs for loss detection to work with (appendix A.4), so the path stops marking. */
    fun onPto() {
        if (state == EcnState.Unknown) state = EcnState.Failed
    }

    fun onLost(marked: Boolean) {
        if (marked && state != EcnState.Capable &&
            state != EcnState.Disabled
        ) {
            testingLost++
            if (testingLost >= TEST_PACKETS) state = EcnState.Failed
        }
    } // appendix A.4: all test packets lost

    private companion object {
        const val TEST_PACKETS = 10
    }
}
