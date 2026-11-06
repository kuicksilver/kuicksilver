// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.quic.core

import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.recovery.SpaceId

// What follows a datagram: the handshake-time address decisions, stream events and the amplification limit (RFC 9000 sections 8.1 and 9.3).

/**
 * Server: the anti-amplification limit leaves no PTO probe to send, so no PTO is armed (RFC 9002 section 6.2.2.1). Below 64
 * bytes PacketBuilder builds no datagram; below 1200 an ack-eliciting Initial may not go out (RFC 9000 section 14.1), so a
 * probe needs Handshake data in flight to resend.
 */
internal fun ConnectionCore.amplificationLeavesNoProbe(): Boolean {
    if (amplification.validated) return false
    val budget = amplification.budget()
    if (budget < 64) return true
    if (budget >= 1200) return false
    val handshake = SpaceId.Handshake
    return writeKeys[2] == null || spaceDiscarded[handshake.ordinal] || loss.space(handshake).ackElicitingInFlight <= 0
}

internal fun ConnectionCore.afterInput(now: TimeMark) {
    if (tlsDirty) {
        tlsDirty = false
        driveTls(now)
    }
    pendingHandshakeMove?.let {
        pendingHandshakeMove = null
        onHandshakeDatagramDone(it)
    }
    finishPathResponses()
    if (discardHandshakeKeysAfterPacket) {
        discardHandshakeKeysAfterPacket = false
        discardSpace(SpaceId.Handshake)
    }
    if (discardInitialPending) {
        discardInitialPending = false
        discardSpace(SpaceId.Initial)
    }
    drainStreamEvents()
}

internal fun ConnectionCore.drainStreamEvents() {
    while (true) events += streams.events.removeFirstOrNull() ?: break
}
