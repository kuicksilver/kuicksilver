// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.quic.CongestionController
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.recovery.SpaceId

// Invariant probes of the fuzz targets and randomized tests (never called in production): what a connection holds must agree
// with what it reports, whatever sequence of input and application calls led there.

/** The stream a per-stream event is about, or null for an event of the connection. */
internal fun streamEventIdForTest(e: ConnectionEvent): Long? =
    when (e) {
        is ConnectionEvent.StreamOpened -> e.id
        is ConnectionEvent.StreamReadable -> e.id
        is ConnectionEvent.StreamWritable -> e.id
        is ConnectionEvent.StreamReset -> e.id
        is ConnectionEvent.StopSendingReceived -> e.id
        is ConnectionEvent.StreamFinished -> e.id
        else -> null
    }

/**
 * Items held back until the server answers our 0-RTT ([io.kuicksilver.quic.stream.StreamManager.heldUntilZeroRttAnswerForTest]);
 * 0 once the answer is known or the connection ended.
 */
internal fun ConnectionCore.zeroRttHeldForTest(): Int = streams.heldUntilZeroRttAnswerForTest()

/** 0-RTT packets still in the sent history (in flight or waiting for an acknowledgment). */
internal fun ConnectionCore.zeroRttPacketsSentForTest(): Int {
    var n = 0
    for (p in loss.space(SpaceId.Application).sent) if (p.zeroRtt) n++
    return n
}

/**
 * The first disagreement between the sent history and what loss detection and the congestion controllers count, or null:
 * `bytesInFlight` is the size of the in-flight packets of every space, each controller counts exactly the in-flight packets
 * it was charged with (a path's controller with none counts 0), and each space's ack-eliciting count is its ack-eliciting
 * packets. RFC 9002 section 6.4: packets whose keys or space were discarded (a rejected 0-RTT included) leave all of them.
 */
internal fun ConnectionCore.recoveryViolationForTest(): String? {
    var total = 0L
    val perCc = HashMap<CongestionController, Long>()
    for (space in SpaceId.entries) {
        val sp = loss.space(space)
        var eliciting = 0
        for (p in sp.sent) {
            if (p.ackEliciting) eliciting++
            if (!p.inFlight) continue
            total += p.size
            p.cc?.let { perCc[it] = (perCc[it] ?: 0L) + p.size }
        }
        if (eliciting != sp.ackElicitingInFlight) {
            return "${space.name}: ${sp.ackElicitingInFlight} ack-eliciting packets counted, $eliciting in the history"
        }
    }
    if (total != loss.bytesInFlight) return "bytesInFlight ${loss.bytesInFlight}, the in-flight packets hold $total"
    for ((cc, bytes) in perCc) {
        if (cc.bytesInFlight != bytes) return "a congestion controller counts ${cc.bytesInFlight} bytes in flight, its packets hold $bytes"
    }
    for (path in paths.all) {
        if (path.cc !in perCc && path.cc.bytesInFlight != 0L) {
            return "path ${path.id.value}'s congestion controller counts ${path.cc.bytesInFlight} bytes in flight, none of its packets is"
        }
    }
    return null
}
