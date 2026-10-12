// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.EcnState

/**
 * Per-path ECN validation (RFC 9000 section 13.4.2): the first ten packets go out with ECT(0); the peer's ACK_ECN counts
 * must appear and move consistently (the connection-wide bookkeeping of `LossDetection` checks that they never decrease, show
 * no ECT(1) and cover every newly acknowledged marked packet); losing all ten test packets fails too. A failed path never marks
 * again. CE growth is reported to the caller by loss detection, who turns it into one congestion event per recovery period.
 */
internal class EcnValidator {
    var state: EcnState = EcnState.Disabled
        private set
    private var testingSent = 0
    private var testingLost = 0

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

    /**
     * One ACK frame that newly acknowledged packets of this path: [countsPresent] when it carried ECN counts, [countsValid] when
     * they moved consistently, [newlyAckedMarked] of this path's packets were sent marked.
     */
    fun onAck(
        countsPresent: Boolean,
        countsValid: Boolean,
        newlyAckedMarked: Int,
    ) {
        if (state == EcnState.Disabled || state == EcnState.Failed) return
        if (!countsPresent) {
            if (newlyAckedMarked > 0) state = EcnState.Failed
            return
        } // marked packets acknowledged without counts (section 13.4.2.1)
        if (!countsValid) {
            state = EcnState.Failed
            return
        } // counts decreased, ECT(1) appeared or a marked packet went uncounted
        if (newlyAckedMarked > 0 && state != EcnState.Capable) state = EcnState.Capable
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
