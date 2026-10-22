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
import kotlin.time.Duration.Companion.seconds

// Timers and loss callbacks of a [ConnectionCore]: PTO, idle and keep-alive deadlines, PTO probes and the [LossListener] (RFC 9000
// section 10.1; RFC 9002).

/** PTO as RFC 9002 section 6.2.1 computes it for timers outside loss detection. */
internal fun ConnectionCore.pto(): Duration {
    val v4 =
        rtt.rttVar * 4
    return rtt.smoothed + (if (v4 > 1.milliseconds) v4 else 1.milliseconds) +
        (if (loss.handshakeConfirmed) loss.peerMaxAckDelay else Duration.ZERO)
}

/** After a send: a newly reported flow-control limit (re)starts the fast schedule of [onBlockedRepeatTimer]. */
internal fun ConnectionCore.armBlockedRepeat(now: TimeMark) {
    val epoch = streams.blockedEpoch
    if (epoch == timers.blockedEpochSeen) return
    timers.blockedEpochSeen = epoch
    timers.blockedRepeats = 0
    timers.blockedRepeatAt = now + blockedRepeatGap(0)
}

/**
 * A sender blocked by flow control repeats its DATA_BLOCKED / STREAM_DATA_BLOCKED while it stays blocked, at the gaps of
 * [blockedRepeatGap]: fast at first, since a lost MAX_DATA / MAX_STREAM_DATA otherwise waits on the receiver's own PTO backoff
 * (64 PTOs, 11 s, in a simulated upload with 75 % loss on the return path), then backing off to a third of the idle timeout. The
 * receiver answers each repeat that comes at least an RTT after the previous one with its current limit (RFC 9000 section 4.1).
 */
internal fun ConnectionCore.onBlockedRepeatTimer(now: TimeMark) {
    if (timers.blockedRepeatAt > now) return
    if (state != ConnectionState.Confirmed || !streams.flowBlocked()) {
        timers.blockedRepeatAt = TimeMark.NEVER
        return
    }
    // not only with nothing in flight: an unacknowledged report waits on our own PTO backoff, which the lossy return path that
    // ate the update also feeds (ungated, the 20-seed simulation's longest stall fell from 9.0 s to 5.3 s)
    streams.repeatBlockedReports()
    if (timers.blockedRepeats < Int.MAX_VALUE) timers.blockedRepeats++
    timers.blockedRepeatAt = now + blockedRepeatGap(timers.blockedRepeats)
}

private fun ConnectionCore.blockedRepeatGap(done: Int): Duration =
    blockedRepeatGap(done, pto(), timers.effectiveIdle(config.maxIdleTimeout, peerIdleMs, pto()))

/**
 * Repeats at one blocked limit that keep the gaps of before (1, 2, 4, then 8 PTO); later ones back off. At the 75 % loss of
 * every answer in FlowBlockedTest, 32 lost answers in a row have probability 1e-4 per blocked limit (0.75^32); at 10 % loss,
 * 1e-32. A sender still blocked after them almost surely faces a receiver that does not read, not a lost window update.
 */
internal const val BLOCKED_FAST_REPEATS = 32

/** Unused window, in datagrams, that still counts as a window in use (quic-go's maxBurstPackets, RFC 9002 section 7.8). */
private const val BURST_DATAGRAMS = 3

/** The datagram size assumed for a path that is gone. */
private const val MIN_DATAGRAM = 1200

/**
 * The longest gap between repeats when neither side has an idle timeout (both sent max_idle_timeout 0). Nothing has to be kept
 * alive then; the reports only find a lost update late in a long block. 10 s is the gap the default 30 s idle timeout gives, so
 * disabling the idle timeout does not change the traffic of a blocked connection, and a lost update after a long block costs
 * at most 10 s.
 */
internal val BLOCKED_REPEAT_CAP_WITHOUT_IDLE = 10.seconds

/**
 * The longest gap between repeated *_BLOCKED reports: a third of the effective [idle] timeout (the smaller of both sides'
 * max_idle_timeout, at least 3 PTO), so at least two reports and their acknowledgements, each restarting both idle timers
 * (RFC 9000 section 10.1), fall in every idle period and one lost exchange does not let a blocked connection idle out.
 * [BLOCKED_REPEAT_CAP_WITHOUT_IDLE] without an idle timeout.
 */
internal fun blockedRepeatCap(idle: Duration): Duration = if (idle.isInfinite()) BLOCKED_REPEAT_CAP_WITHOUT_IDLE else idle / 3

/**
 * The gap before the next repeat after [done] repeats at the current limit ([done] = 0: the first report). 1, 2 and 4 PTO, then
 * 8 PTO through repeat [BLOCKED_FAST_REPEATS] (report n, n >= 4, goes out 8n - 17 PTO after the first, as before), then
 * doubling from 16 PTO; every gap at most [blockedRepeatCap]. Doubling reaches the cap within a few repeats (five from 16 PTO
 * at PTO 36 ms and a 10 s cap), so a block of length T costs about 33 + log2(cap / 8 PTO) + T / cap reports, not T / 8 PTO.
 */
internal fun blockedRepeatGap(
    done: Int,
    pto: Duration,
    idle: Duration,
): Duration {
    val cap = blockedRepeatCap(idle)
    // 2^43 PTO is beyond any cap; stopping the shift there avoids its overflow
    if (done - BLOCKED_FAST_REPEATS >= 40) return cap
    val ptos =
        when {
            done <= 3 -> 1L shl done
            done < BLOCKED_FAST_REPEATS -> 8L
            else -> 16L shl (done - BLOCKED_FAST_REPEATS)
        }
    val gap = pto * ptos.toDouble()
    return if (gap < cap) gap else cap
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
    // at least every half of the effective idle timeout, which a peer may have made shorter than k (quic-go's KeepAlivePeriod)
    val idle = timers.effectiveIdle(config.maxIdleTimeout, peerIdleMs, pto())
    val interval = if (idle != Duration.INFINITE && idle / 2 < k) idle / 2 else k
    return (
        if (timers.lastAckElicitingSent !=
            TimeMark.NEVER
        ) {
            timers.lastAckElicitingSent
        } else {
            timers.lastActivity
        }
    ) +
        interval
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

/**
 * A PTO probe carries the frames of the oldest unacknowledged packets that hold something to resend and that no earlier probe
 * took, rather than a bare PING (RFC 9002 section 6.2.4; [io.kuicksilver.quic.recovery.LossDetection.takeForProbe]).
 */
internal fun ConnectionCore.requeueForProbe(
    space: SpaceId,
    n: Int,
) {
    probeScratch.clear()
    loss.takeForProbe(space, n, probeScratch)
    for (p in probeScratch) {
        val f = p.frames
        for (i in 0 until f.cryptoCount) cryptoStreams.send[f.cryptoLevel[i]].onLost(f.cryptoOffset[i], f.cryptoLength[i])
        // stream control frames too: a probe for a packet that carried only MAX_DATA / MAX_STREAM_DATA must carry the update, not a
        // bare PING, or a receiver whose window update was lost waits for a loss declaration that its own PTO backoff delays
        if (f.streamCount > 0 || f.idCount > 0 || f.flags and SentFrames.STREAM_CONTROL != 0) streams.onFramesLost(f)
        if (f.flags and SentFrames.HANDSHAKE_DONE != 0) sendHandshakeDone = true
        requeueNewToken(f)
    }
}

/** A lost (or probed) packet carried the NEW_TOKEN frame still unacknowledged: the same token goes again. */
internal fun ConnectionCore.requeueNewToken(f: SentFrames) {
    for (i in 0 until f.idCount) {
        if (f.idKind[i] == SentFrames.ID_NEW_TOKEN && f.idValue[i] == newTokenSeq && newToken != null) sendNewToken = true
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
        // Handshake and 1-RTT acknowledgements cannot be forged: one for a packet sent to the client's current address proves it
        if (space != SpaceId.Initial && core.role == io.kuicksilver.tls.TlsRole.Server) core.onHandshakePathAcked(p.pathId, p.addressEpoch)
        if (f.flags and SentFrames.HANDSHAKE_DONE != 0) core.sendHandshakeDone = false
        if (space == SpaceId.Application) core.keyPhase?.onPacketAcked(p.pn, core.now)
        for (i in 0 until f.idCount) {
            if (f.idKind[i] == SentFrames.ID_RETIRE_CONNECTION_ID) core.cids.onRetireAcked(f.idValue[i])
            if (f.idKind[i] == SentFrames.ID_NEW_TOKEN && f.idValue[i] == core.newTokenSeq) {
                core.newToken = null // delivered: nothing to repeat
                core.sendNewToken = false
            }
        }
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

    override fun onDelivered(
        p: SentPacket,
        now: TimeMark,
    ) {
        if (p.inFlight) (p.cc as? io.kuicksilver.quic.Bbr)?.onPacketAcked(p, now)
    }

    override fun onSpuriousLoss(
        space: SpaceId,
        pn: Long,
        bytes: Int,
        cc: io.kuicksilver.quic.CongestionController?,
        pathId: Int,
        now: TimeMark,
    ) {
        core.spuriousLosses++
        (cc as? io.kuicksilver.quic.Bbr)?.onSpuriousLoss(now)
    }

    override fun onLossSettled(
        cc: io.kuicksilver.quic.CongestionController?,
        now: TimeMark,
    ) {
        (cc as? io.kuicksilver.quic.Bbr)?.onLossSettled(now)
    }

    override fun onLost(
        space: SpaceId,
        p: SentPacket,
    ) {
        core.lostPackets++
        if (p.inFlight) (p.cc as? io.kuicksilver.quic.Bbr)?.onPacketLost(p, core.now)
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
                    if (m.onProbeLost(p.size, core.now)) core.setMtu(path, m.current) // a Packet Too Big confirmed by lost probes
                } else {
                    m.onPacketLost(p.size, p.pn)
                }
            }
        } // RFC 8899: a lost probe is not congestion; the black-hole verdict waits for the end of the ACK (checkPmtuBlackHoles)
        val f = p.frames
        for (i in 0 until f.cryptoCount) core.cryptoStreams.send[f.cryptoLevel[i]].onLost(f.cryptoOffset[i], f.cryptoLength[i])
        if (f.streamCount > 0 || f.idCount > 0 || f.flags and SentFrames.STREAM_CONTROL != 0) core.streams.onFramesLost(f)
        if (f.flags and SentFrames.HANDSHAKE_DONE != 0) core.sendHandshakeDone = true
        core.requeueNewToken(f)
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
        val prior = priorInFlight(target)
        if (event.kind ==
            CongestionKind.Acked
        ) {
            target.onAck(
                event.now,
                event.sentTime,
                event.bytes,
                core.rtt.smoothed,
                appLimited = !cwndLimited(target, prior, core.paths.byId(PathId(event.pathId))?.mtu ?: MIN_DATAGRAM),
            )
        } else {
            target.onLoss(event.now, event.bytes, event.sentTime, event.persistentCongestion)
        }
        core.qlog?.metricsUpdated(core.stats, event.now)
    }

    /** Controllers seen in the ACK frame being processed and their bytes in flight before it (the frame's losses included). */
    private val priorCcs = ArrayList<io.kuicksilver.quic.CongestionController>(4)
    private var priorBytes = LongArray(4)

    override fun onAckFrameStart() {
        priorCcs.clear()
    }

    private fun priorInFlight(cc: io.kuicksilver.quic.CongestionController): Long {
        for (i in priorCcs.indices) if (priorCcs[i] === cc) return priorBytes[i]
        if (priorCcs.size == priorBytes.size) priorBytes = priorBytes.copyOf(priorBytes.size * 2)
        priorBytes[priorCcs.size] = cc.bytesInFlight
        priorCcs += cc
        return cc.bytesInFlight
    }

    /**
     * RFC 9002 section 7.8: the window grows only while the sender uses it. Judged on the bytes in flight before the ACK frame (an
     * ACK of a whole window otherwise looks application-limited halfway through), with quic-go's isCwndLimited margins: at most
     * three datagrams unused, or more than half the window in flight during slow start (where the window doubles each RTT). A
     * pacer that keeps a burst back stays within that margin, so pacing delay is not taken for application limitation.
     */
    private fun cwndLimited(
        cc: io.kuicksilver.quic.CongestionController,
        prior: Long,
        mss: Int,
    ): Boolean {
        val cwnd = cc.cwnd
        if (prior >= cwnd) return true
        val slowStart =
            when (cc) {
                is io.kuicksilver.quic.Cubic -> cwnd < cc.ssthresh
                is io.kuicksilver.quic.NewReno -> cwnd < cc.ssthresh
                else -> false
            }
        return (slowStart && prior > cwnd / 2) || cwnd - prior <= BURST_DATAGRAMS * mss
    }

    override fun onAckProcessed(now: TimeMark) {
        val all = core.paths.all
        for (i in all.indices) (all[i].cc as? io.kuicksilver.quic.Bbr)?.onAckProcessed(now)
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
        if (ceGrew && p.cc is io.kuicksilver.quic.Bbr) {
            core.ecnCeEvents++
            p.cc.onEcnCe(now, largestSentTime)
        } // BBR treats CE like loss, once per round of its own path: every report counts
        else if (ceGrew &&
            (core.ceRecoveryStart == TimeMark.NEVER || largestSentTime > core.ceRecoveryStart)
        ) {
            core.ceRecoveryStart = now
            core.ecnCeEvents++
            p.cc.onEcnCe(now, largestSentTime)
        } // one congestion event per recovery period (RFC 9002 section 7.1)
    }
}
