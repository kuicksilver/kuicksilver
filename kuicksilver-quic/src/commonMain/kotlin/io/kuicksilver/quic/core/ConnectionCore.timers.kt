// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.recovery.CongestionEvent
import io.kuicksilver.quic.recovery.CongestionKind
import io.kuicksilver.quic.recovery.LossListener
import io.kuicksilver.quic.recovery.SentFrames
import io.kuicksilver.quic.recovery.SentPacket
import io.kuicksilver.quic.recovery.SpaceId
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

// Timers and loss callbacks of a [ConnectionCore]: PTO, idle and keep-alive deadlines, PTO probes and the [LossListener] (RFC 9000
// section 10.1; RFC 9002).

/** PTO as RFC 9002 section 6.2.1 computes it for timers outside loss detection. */
internal fun ConnectionCore.pto(): Duration {
    val v4 =
        rtt.rttVar * 4
    return rtt.smoothed + (if (v4 > 1.milliseconds) v4 else 1.milliseconds) +
        (if (loss.handshakeConfirmed) loss.peerMaxAckDelay else Duration.ZERO)
}

internal fun ConnectionCore.idleDeadline(): TimeMark {
    if (state == ConnectionState.Closing || state == ConnectionState.Draining ||
        state == ConnectionState.Closed
    ) {
        return TimeMark.NEVER
    }
    val d = timers.effectiveIdle(config.maxIdleTimeout, peerIdleMs, pto())
    if (d ==
        Duration.INFINITE
    ) {
        return TimeMark.NEVER
    }
    return timers.lastActivity + d
}

internal fun ConnectionCore.keepAliveDeadline(): TimeMark {
    val k =
        config.keepAlive ?: return TimeMark.NEVER
    if (state !=
        ConnectionState.Confirmed
    ) {
        return TimeMark.NEVER
    }
    return (
        if (timers.lastAckElicitingSent !=
            TimeMark.NEVER
        ) {
            timers.lastAckElicitingSent
        } else {
            timers.lastActivity
        }
    ) +
        k
}

/**
 * A PTO in one long-header space also probes the other one when it holds unacknowledged data: the probe datagram is
 * padded to 1200 bytes anyway, and a server whose Initial probes keep winning the timer would otherwise never resend
 * its Handshake flight to a client that cannot acknowledge Initial packets it did not fully receive (RFC 9002
 * section 6.2.4 lets an endpoint send more than the one probe; seen as `handshakeloss` stalls against quic-go).
 */
internal fun ConnectionCore.probeOtherHandshakeSpace(space: SpaceId) {
    if (space == SpaceId.Application) return
    val other = if (space == SpaceId.Initial) SpaceId.Handshake else SpaceId.Initial
    if (spaceDiscarded[other.ordinal] || loss.space(other).ackElicitingInFlight <= 0 || probePending[other.ordinal] > 0) return
    probePending[other.ordinal] = 1
    requeueForProbe(other, 1)
}

/** A PTO probe carries the frames of the oldest unacknowledged packets rather than a bare PING (RFC 9002 section 6.2.4). */
internal fun ConnectionCore.requeueForProbe(
    space: SpaceId,
    n: Int,
) {
    probeScratch.clear()
    loss.oldestUnacked(space, n, probeScratch)
    for (p in probeScratch) {
        val f = p.frames
        for (i in 0 until f.cryptoCount) cryptoStreams.send[f.cryptoLevel[i]].onLost(f.cryptoOffset[i], f.cryptoLength[i])
        if (f.streamCount >
            0
        ) {
            streams.onFramesLost(f)
        }
        if (f.flags and SentFrames.HANDSHAKE_DONE != 0) sendHandshakeDone = true
    }
}

internal class ConnectionLossListener(
    private val core: ConnectionCore,
) : LossListener {
    override fun onAcked(
        space: SpaceId,
        p: SentPacket,
    ) {
        val f = p.frames
        if (f.ackLargest >= 0) {
            core.loss
                .space(space)
                .ack
                .onAckFrameAcknowledged(f.ackLargest) // the ACK it carried need not be repeated
        }
        for (i in 0 until f.cryptoCount) core.cryptoStreams.send[f.cryptoLevel[i]].onAcked(f.cryptoOffset[i], f.cryptoLength[i])
        if (f.streamCount > 0 || f.idCount > 0) core.streams.onFramesAcked(f)
        if (space == SpaceId.Handshake) core.loss.peerAddressValidated = true
        if (f.flags and SentFrames.HANDSHAKE_DONE != 0) core.sendHandshakeDone = false
        if (space == SpaceId.Application) core.keyPhase?.onPacketAcked(p.pn)
        for (i in 0 until f.idCount) if (f.idKind[i] == SentFrames.ID_RETIRE_CONNECTION_ID) core.cids.onRetireAcked(f.idValue[i])
        core.paths.byId(PathId(p.pathId))?.let { path ->
            path.pmtud?.let { m ->
                if (f.flags and SentFrames.PMTU_PROBE !=
                    0
                ) {
                    m.onProbeAcked(p.size, core.now)
                    if (p.size > path.mtu) core.setMtu(path, p.size)
                } else if (m.onPacketAcked(p.size, p.pn)) {
                    core.setMtu(path, m.current) // a black-hole verdict the late ACK disproved
                }
            }
        }
        if (f.dgCount > 0) core.datagramSender?.let { s -> for (i in 0 until f.dgCount) if (f.dgId[i] >= 0) s.onAcked(f.dgId[i]) }
    }

    override fun onLost(
        space: SpaceId,
        p: SentPacket,
    ) {
        core.lostPackets++
        core.qlog?.packetLost(space, p.pn, "time_or_packet_threshold", core.now)
        if (p.ecnMarked) {
            core.paths.byId(PathId(p.pathId))?.let { path ->
                path.ecn.onLost(true)
                core.ecnPathFailed(path)
            }
        }
        core.paths.byId(PathId(p.pathId))?.let { path ->
            path.pmtud?.let { m ->
                if (p.frames.flags and SentFrames.PMTU_PROBE !=
                    0
                ) {
                    m.onProbeLost(p.size, core.now)
                } else {
                    m.onPacketLost(p.size, p.pn)
                }
            }
        } // RFC 8899: a lost probe is not congestion; the black-hole verdict waits for the end of the ACK (checkPmtuBlackHoles)
        val f = p.frames
        for (i in 0 until f.cryptoCount) core.cryptoStreams.send[f.cryptoLevel[i]].onLost(f.cryptoOffset[i], f.cryptoLength[i])
        if (f.streamCount > 0 || f.idCount > 0 ||
            f.flags and (SentFrames.MAX_DATA or SentFrames.MAX_STREAMS_BIDI or SentFrames.MAX_STREAMS_UNI) != 0
        ) {
            core.streams.onFramesLost(f)
        }
        if (f.flags and SentFrames.HANDSHAKE_DONE != 0) core.sendHandshakeDone = true
        // a lost PATH_CHALLENGE is not resent here: the path's PTO-paced timer repeats it (RFC 9000 section 8.2.4), otherwise a dead path draws one 1200-byte probe per loss detection; PATH_RESPONSE is never retransmitted (section 13.3)
        for (i in 0 until f.idCount) {
            when (f.idKind[i]) {
                SentFrames.ID_RETIRE_CONNECTION_ID -> core.cids.onRetireLost(f.idValue[i])
                SentFrames.ID_NEW_CONNECTION_ID -> core.cids.onNewCidLost(f.idValue[i], core.now + core.pto() * 3)
            }
        }
        // RFC 9221 section 5: never retransmitted, only reported
        if (f.dgCount > 0) core.datagramSender?.let { s -> for (i in 0 until f.dgCount) if (f.dgId[i] >= 0) s.onLost(f.dgId[i]) }
    }

    override fun onCongestion(event: CongestionEvent) {
        // the controller that counted the packets: after a NAT rebinding it lives on the new path (`inheritFrom`); without one, the
        // path's controller, or nothing for a path that is gone
        val target = event.cc ?: core.paths.byId(PathId(event.pathId))?.cc ?: return
        if (event.kind ==
            CongestionKind.Acked
        ) {
            target.onAck(
                event.now,
                event.sentTime,
                event.bytes,
                core.rtt.smoothed,
                appLimited =
                    target.bytesInFlight < target.cwnd / 2,
            )
        } else {
            target.onLoss(event.now, event.bytes, event.sentTime, event.persistentCongestion)
        }
        core.qlog?.metricsUpdated(core.stats, event.now)
    }

    override fun onDiscarded(bytes: Int) {
        core.cc.onDiscarded(bytes)
    }

    override fun onRttSample(
        now: TimeMark,
        latest: Duration,
        min: Duration,
    ) {
        core.cc.onRttSample(now, latest, min)
    }

    override fun onEcnAck(
        space: SpaceId,
        countsPresent: Boolean,
        countsValid: Boolean,
        newlyAckedMarked: Int,
        ceGrew: Boolean,
        now: TimeMark,
        largestSentTime: TimeMark,
        pathId: Int,
    ) {
        val p = core.paths.byId(PathId(pathId)) ?: return // the path is gone: its ECN state too
        p.ecn.onAck(countsPresent, countsValid, newlyAckedMarked)
        core.ecnPathFailed(p)
        if (ceGrew &&
            (core.ceRecoveryStart == TimeMark.NEVER || largestSentTime > core.ceRecoveryStart)
        ) {
            core.ceRecoveryStart = now
            core.ecnCeEvents++
            p.cc.onEcnCe(now, largestSentTime)
        } // one congestion event per recovery period (RFC 9002 section 7.1)
    }
}
