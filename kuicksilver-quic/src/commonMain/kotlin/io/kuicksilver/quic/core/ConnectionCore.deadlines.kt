// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.quic.core

import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.EcnState
import io.kuicksilver.quic.PathFailureReason
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TimeoutKind
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.core.checkPmtuBlackHoles
import io.kuicksilver.quic.core.discardZeroRttKeys
import io.kuicksilver.quic.core.dropHandshakeCandidate
import io.kuicksilver.quic.core.ecnPathFailed
import io.kuicksilver.quic.core.fail
import io.kuicksilver.quic.core.idleDeadline
import io.kuicksilver.quic.core.keepAliveDeadline
import io.kuicksilver.quic.core.largePacketUnanswered
import io.kuicksilver.quic.core.markClosed
import io.kuicksilver.quic.core.nextChallengeDelay
import io.kuicksilver.quic.core.onBlockedRepeatTimer
import io.kuicksilver.quic.core.onPathFailed
import io.kuicksilver.quic.core.onRevalidateDue
import io.kuicksilver.quic.core.probeOtherHandshakeSpace
import io.kuicksilver.quic.core.pto
import io.kuicksilver.quic.core.requeueForProbe
import io.kuicksilver.quic.core.revertHandshakeMove
import io.kuicksilver.quic.core.setMtu
import io.kuicksilver.quic.core.settleHandshakeValidated
import io.kuicksilver.quic.core.silentClose
import io.kuicksilver.quic.core.validationTimeout
import io.kuicksilver.quic.recovery.SpaceId

// The bodies of ConnectionCore.nextTimeoutOrNever and ConnectionCore.onTimeout: every timer of a connection (RFC 9000 sections 10 and 8.2, RFC 9002 section 6).

/** [ConnectionCore.nextTimeoutOrNever]: the earliest deadline of any timer, [TimeMark.NEVER] when none is armed. */
internal fun ConnectionCore.earliestDeadline(): TimeMark {
    if (state == ConnectionState.Closed) return TimeMark.NEVER
    if (state == ConnectionState.Closing || state == ConnectionState.Draining) return timers.closeDeadline ?: TimeMark.NEVER
    var t: TimeMark = loss.timeout()
    for (i in 0 until 3) {
        if (spaceDiscarded[i]) continue
        val d = loss.space(SpaceId.entries[i]).ack.ackDeadline(config.maxAckDelay)
        if (d <
            t
        ) {
            t = d
        }
    }
    if (builder.pacerWakeup < t) t = builder.pacerWakeup
    if (state == ConnectionState.Handshaking) timers.handshakeDeadline?.let { if (it < t) t = it }
    handshakeFallback?.let { if (it.deadline < t) t = it.deadline }
    val idle = idleDeadline()
    if (idle < t) t = idle
    val keep = keepAliveDeadline()
    if (keep < t) t = keep
    if (timers.blockedRepeatAt < t) t = timers.blockedRepeatAt
    if (lifetimeDeadline < t) t = lifetimeDeadline
    keyPhase?.let { if (it.discardAt < t) t = it.discardAt }
    if (keyUpdateRetryAt < t) t = keyUpdateRetryAt
    if (zeroRttReadDiscardAt < t) t = zeroRttReadDiscardAt
    for (i in 0 until paths.all.size) {
        val p = paths.all[i]
        if (p.state ==
            PathState.Validating
        ) {
            if (p.challengeDeadline <
                t
            ) {
                t = p.challengeDeadline
            }
            if (p.nextChallengeAt <
                t
            ) {
                t = p.nextChallengeAt
            }
        }
        if (p.revalidateAt < t) t = p.revalidateAt
        p.pmtud?.let { m ->
            val mt = m.timeout()
            if (mt < t) t = mt
        }
    }
    val retired = cids.nextRetiredExpiry()
    if (retired < t) t = retired
    return t
}

/** [ConnectionCore.onTimeout]: runs every timer due at [now]. */
internal fun ConnectionCore.runDueTimers(now: TimeMark) {
    if (state == ConnectionState.Closed) return
    this.now = now
    if (state == ConnectionState.Closing ||
        state == ConnectionState.Draining
    ) {
        timers.closeDeadline?.let { if (it <= now) markClosed() }
        return
    }
    if (state ==
        ConnectionState.Handshaking
    ) {
        timers.handshakeDeadline?.let {
            if (it <=
                now
            ) {
                silentClose(QuicException.ConnectionLost.Timeout(TimeoutKind.Handshake, config.handshakeTimeout))
                return
            }
        }
    }
    if (idleDeadline() <=
        now
    ) {
        silentClose(
            QuicException.ConnectionLost.Timeout(TimeoutKind.Idle, timers.effectiveIdle(config.maxIdleTimeout, peerIdleMs, pto())),
        )
        return
    }
    if (lifetimeDeadline <= now) {
        fail(TransportError.NO_ERROR, 0, "connection lifetime reached", null)
        return
    }
    // before the path loop: an unvalidated handshake-time move is undone, not given another validation period nor failed (it may
    // outlive the handshake when a raced copy carried the client's Finished)
    handshakeFallback?.let { if (it.deadline <= now) revertHandshakeMove(it) }
    cids.expireRetired(now)
    if (zeroRttReadDiscardAt <= now) discardZeroRttKeys()
    for (i in 0 until paths.all.size) paths.all[i].pmtud?.onTimeout(now)
    for (i in paths.all.size - 1 downTo 0) paths.all.getOrNull(i)?.let { if (it.revalidateAt <= now) onRevalidateDue(it) }
    var pi = paths.all.size - 1
    while (pi >=
        0
    ) {
        val p = paths.all.getOrNull(pi)
        pi--
        if (p == null ||
            p.state != PathState.Validating
        ) {
            continue
        }
        if (p.challengeDeadline <=
            now
        ) {
            if (p.handshakeCandidate) {
                dropHandshakeCandidate() // the other address of a handshake-time rebind did not answer: only it goes, unreported
            } else if (p.awaitingCid) {
                onPathFailed(p, PathFailureReason.NoSpareConnectionId)
            } else if (p === paths.active && p.handshakeValidated &&
                handshakeCandidate?.let { it.state == PathState.Validating && it.challengeDeadline > now } == true
            ) {
                // the other address of a handshake-time rebind may still answer its own challenge: the one the client was reached
                // at settles only once that validation ended unanswered
                p.challengeDeadline = handshakeCandidate!!.challengeDeadline
            } else if (p === paths.active &&
                p.handshakeValidated
            ) {
                settleHandshakeValidated(p)
            } else if (p === paths.active && handshakeFallback?.let { it.path === p && !it.isAddress(p.remote) } == true &&
                !p.amplification.validated
            ) {
                // the address a handshake-time move took the path to failed its validation (it may have started before the move's
                // own deadline: a validation travels with its address between the active path and the candidate): the move is
                // undone as at that deadline (RFC 9000 section 9.3.2)
                revertHandshakeMove(handshakeFallback!!)
            } else if (p === paths.active &&
                state == ConnectionState.Handshaking
            ) {
                // every handshake-time move that leaves the active path validating keeps a HandshakeFallback whose deadline undoes it
                // (revertHandshakeMove); an address restored with a validation still under way restarts it here, so that a deadline
                // never stays in the past
                p.challengePending = true
                p.challengeDeadline = now + validationTimeout()
                p.nextChallengeAt = now + nextChallengeDelay(p)
            } else {
                onPathFailed(p)
            }
        } else if (p.nextChallengeAt <=
            now
        ) {
            p.challengePending = true
            p.nextChallengeAt = now + nextChallengeDelay(p)
        }
    } // RFC 9000 section 8.2.4
    // QuicEndpointConfig.maxConnectionLifetime: a transport close with NO_ERROR
    if (state == ConnectionState.Closed || state == ConnectionState.Closing || state == ConnectionState.Draining) return
    if (keepAliveDeadline() <= now) timers.keepAlivePending = true
    onBlockedRepeatTimer(now)
    if (loss.timeout() <=
        now
    ) {
        val probe = loss.onTimeout(now)
        checkPmtuBlackHoles()
        if (probe !=
            null
        ) {
            probePending[probe.space.ordinal] = probe.packets
            requeueForProbe(probe.space, probe.packets)
            if (probe.space != SpaceId.Application && handshakeMirror) handshakeMirrorDue = true
            probeOtherHandshakeSpace(probe.space)
            if (probe.space ==
                SpaceId.Application
            ) {
                path.let { p ->
                    if (p.ecn.state ==
                        EcnState.Unknown
                    ) {
                        p.ecn.onPto()
                        ecnPathFailed(p)
                    }
                    ; p.pmtud?.let { m ->
                        if (loss.ptoCount >= 2 &&
                            m.current > 1200 &&
                            largePacketUnanswered(p)
                        ) {
                            m.onBlackHole(now)
                            setMtu(p, m.current) // 1200, or the size of a validated Packet Too Big under confirmation
                        }
                    }
                }
            }
        }
        // RFC 9000 appendix A.4: a 1-RTT PTO with all ten test packets outstanding means the marked packets vanish; two PTOs above the base
        // MTU with nothing acknowledged are a PMTU black hole (RFC 8899 section 4.3)
    }
    if (builder.pacerWakeup <= now) builder.pacerWakeup = TimeMark.NEVER
    keyPhase?.onTimeout(now)
    if (now >= keyUpdateRetryAt) keyUpdateRetryAt = TimeMark.NEVER // a wake-up for a caller retrying initiateKeyUpdate, nothing more
}
