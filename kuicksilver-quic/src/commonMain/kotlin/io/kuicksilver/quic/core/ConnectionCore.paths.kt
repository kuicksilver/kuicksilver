// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.EcnState
import io.kuicksilver.quic.PathChangeReason
import io.kuicksilver.quic.PathFailureReason
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.recordForTest
import io.kuicksilver.quic.recovery.SentFrames
import io.kuicksilver.quic.recovery.SpaceId
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.tls.TlsRole
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

// Paths of a [ConnectionCore]: PMTUD and ECN per path, peer connection IDs, path validation, migration and NAT rebinding (RFC 9000
// sections 5.1, 8.2, 9 and 13.4; RFC 8899).

internal fun ConnectionCore.pmtudUpperBound(): Int =
    minOf(config.maxUdpPayloadSize.toLong(), peerTp?.maxUdpPayloadSize ?: Long.MAX_VALUE).toInt()

internal fun ConnectionCore.setMtu(
    p: Path,
    mtu: Int,
) {
    if (p.mtu ==
        mtu
    ) {
        return
    }
    p.mtu = mtu
    p.cc.onMtuUpdate(mtu)
    ccMtuUpdatesForTest.recordForTest(mtu)
    events += ConnectionEvent.MtuUpdated(p.id, mtu)
    qlog?.metricsUpdated(stats, now)
}

internal fun ConnectionCore.ecnCeReceived(): Long {
    var n = 0L
    for (i in 0 until 3) {
        if (spaceDiscarded[i]) continue
        loss.space(SpaceId.entries[i]).ack.ecnCounts?.let {
            n +=
                it[2]
        }
    }
    return n
}

internal fun ConnectionCore.ecnPathFailed(p: Path) {
    if (p.ecn.state == EcnState.Failed &&
        !p.ecnFailureReported
    ) {
        p.ecnFailureReported = true
        onEcnFailed?.invoke(p.id)
    }
}

/**
 * Whether an ack-eliciting packet above the 1200-byte base (not a PMTU probe) sent on [p] awaits acknowledgement: only such
 * packets can vanish in an MTU black hole, so repeated PTOs over small packets alone (the receiving side of a transfer whose
 * peer stalls) say nothing about the MTU.
 */
internal fun ConnectionCore.largePacketUnanswered(p: Path): Boolean {
    for (s in loss.space(SpaceId.Application).sent) {
        if (s.ackEliciting && s.pathId == p.id.value && s.size > 1200 && s.frames.flags and SentFrames.PMTU_PROBE == 0) return true
    }
    return false
}

/** After an ACK frame or a loss timer: a path whose large packets vanished while nothing full-size got through falls back to 1200 (decided once all of the ACK's losses and acknowledgements are in). */
internal fun ConnectionCore.checkPmtuBlackHoles() {
    for (i in 0 until paths.all.size) {
        val p = paths.all[i]
        val m =
            p.pmtud ?: continue
        if (m.takeBlackHole(now)) setMtu(p, 1200)
    }
}

// connection IDs from the peer ([ConnectionIdManager] manages them)
internal fun ConnectionCore.onNewConnectionId(
    seq: Long,
    retirePriorTo: Long,
    cid: PacketBuffer,
    off: Int,
    len: Int,
    tokenOff: Int,
) {
    val dup = cids.onNewConnectionId(seq, retirePriorTo, cid, off, len, tokenOff)
    remoteCid =
        cids.activePeerCid()
    if (dup) glitch(0x18)
    resumeCidWaiters()
}

/** Paths that waited for a peer connection ID start their validation now that one may be spare (RFC 9000 section 9.5). */
private fun ConnectionCore.resumeCidWaiters() {
    for (i in 0 until paths.all.size) {
        val p = paths.all[i]
        if (p.awaitingCid && p.state == PathState.Validating && p !== paths.active && dcidFor(p) != null) startValidation(p)
    }
}

/**
 * Client: [p] has no peer connection ID of its own and the peer gave us none spare (typically right after the handshake, before its
 * NEW_CONNECTION_ID frames arrived). Reusing the active path's ID would let an observer link the paths (RFC 9000 section 9.5), so
 * no PATH_CHALLENGE goes out: the path waits up to the validation timeout for a NEW_CONNECTION_ID ([resumeCidWaiters]) and then
 * fails with [PathFailureReason.NoSpareConnectionId]. quic-go keeps such a path queued for probing until an ID arrives
 * (path_manager_outgoing.go NextPathToProbe); ngtcp2 and quiche refuse at once (NGTCP2_ERR_CONN_ID_BLOCKED, OutOfIdentifiers).
 */
internal fun ConnectionCore.awaitPeerCid(p: Path) {
    if (!p.awaitingCid) {
        p.awaitingCid = true
        p.challengeDeadline = now + validationTimeout()
    }
    p.challengePending = false
    p.nextChallengeAt = TimeMark.NEVER
}

/** RETIRE_CONNECTION_ID: the ID keeps routing for 3 x PTO (RFC 9000 section 5.1.2); one for an ID already gone costs a glitch token. */
internal fun ConnectionCore.onRetireConnectionId(seq: Long) {
    if (!cids.onPeerRetired(seq, now + pto() * 3)) glitch(0x19)
}

/** The validation timeout of RFC 9000 section 8.2.4: max(3 x PTO, 6 x initial RTT). */
internal fun ConnectionCore.validationTimeout(): Duration {
    val p3 = pto() * 3
    val r6 = config.initialRtt * 6
    return if (p3 > r6) p3 else r6
}

/** False for a 1-RTT datagram from a new address the server must not follow: migration disabled, or a loopback/link-local address when the connection is not on one. */
internal fun ConnectionCore.migrationAllowedFrom(from: InetSocketAddress): Boolean {
    if (!config.allowMigration) return false
    if (config.allowMigrationToLoopback) return true
    val special = AddressClass.isLoopback(from) || AddressClass.isLinkLocal(from)
    return !special || AddressClass.isLoopback(path.remote) || AddressClass.isLinkLocal(path.remote)
}

internal fun ConnectionCore.sameIp(
    a: InetSocketAddress,
    b: InetSocketAddress,
): Boolean = AddressClass.ipBytes(a).contentEquals(AddressClass.ipBytes(b))

/** A 1-RTT packet authenticated from [from] on [socket]: a new address becomes a path under validation; its highest-numbered non-probing packet moves the connection there (RFC 9000 section 9.3). */
internal fun ConnectionCore.onPathPacket(
    socket: PathId,
    from: InetSocketAddress,
    pn: Long,
    nonProbing: Boolean,
    datagramBytes: Int,
) {
    val active = paths.active
    if (active.isRemote(from) &&
        socket == active.socket
    ) {
        if (nonProbing && pn > largestNonProbingPn) largestNonProbingPn = pn
        active.lastReceivedAt = now
        return
    }
    if (role == TlsRole.Client) return // servers do not migrate (preferred_address is not supported)
    var p = paths.byRemote(socket, from)
    if (p == null) {
        // four paths already: a migration (the newest non-probing packet) may abandon the oldest validation (RFC 9000 section 8.2.4),
        // a probe only one that has been silent for max(3 x PTO, 5 s) (quic-go's pathTimeout); otherwise the address is ignored
        val migrating = nonProbing && pn > largestNonProbingPn
        val idle = maxOf(pto() * 3, PATH_IDLE_TIMEOUT)
        p = paths.add(
            socket,
            from,
            config.congestionController(),
            config.initialRtt,
            now = now,
            abandonValidatingHeardBefore = if (migrating) TimeMark.NEVER else now - idle,
        ) ?: return
        p.amplification.onReceived(datagramBytes)
        p.caps = active.caps
        if (p.caps.ecnSend) p.ecn.enable() // the same socket: ECN is validated afresh on the new path (section 13.4.2)
        // NAT rebinding keeps the congestion state (same network); the old address probes on a controller of its own
        if (sameIp(from, active.remote)) p.inheritFrom(active, config.congestionController())
        startValidation(p)
    } else if (p.state == PathState.Unknown || (p.state == PathState.Failed && p.standbyUntil <= now)) {
        startValidation(p) // a path first seen through the peer's probe is validated once it carries anything else
    }
    p.lastReceivedAt = now
    if (nonProbing &&
        pn > largestNonProbingPn
    ) {
        largestNonProbingPn = pn
        if (p.state !=
            PathState.Failed
        ) {
            switchPath(
                p,
                if (sameIp(from, active.remote)) PathChangeReason.NatRebinding else PathChangeReason.PeerMigration,
                challengeOld = true,
            )
        }
    }
}

/** A validating path silent this long may give its slot to a probe from a new address (quic-go's pathTimeout). */
internal val PATH_IDLE_TIMEOUT: Duration = 5.seconds

internal fun ConnectionCore.startValidation(p: Path) {
    p.forgetChallenges()
    p.challengePending = true
    p.state = PathState.Validating
    p.handshakeValidated = false
    p.awaitingCid = false
    p.challengeRetries = 0
    p.challengeDeadline = now + validationTimeout()
    p.nextChallengeAt = now + nextChallengeDelay(p)
    // a client probe reserves its peer ID now; without a spare one it waits for a NEW_CONNECTION_ID instead of spending its
    // validation period on challenges that cannot be sent
    if (role == TlsRole.Client && p !== paths.active && dcidFor(p) == null) awaitPeerCid(p)
}

/**
 * The gap before the next PATH_CHALLENGE repeat on [p]: one PTO for the first two repeats, so three challenges (at 0, 1 and 2 PTO) go out
 * inside the 3 x PTO validation timeout, then doubled on every further unanswered repeat (capped at 64 x PTO), so a dead path is not probed
 * once per PTO for as long as it is remembered (RFC 9000 sections 8.2.1 and 8.2.4; the backoff of RFC 9002 section 6.2.1, as quic-go's
 * path_manager_outgoing.go doubles its probe interval).
 */
internal fun ConnectionCore.nextChallengeDelay(p: Path): Duration {
    val r = p.challengeRetries
    val shift =
        if (r < 1) {
            0
        } else if (r < 7) {
            r - 1
        } else {
            6
        }
    p.challengeRetries++
    return pto() * (1 shl shift)
}

internal fun ConnectionCore.switchPath(
    p: Path,
    reason: PathChangeReason,
    challengeOld: Boolean,
) {
    val old = paths.active
    if (old === p) return
    val oldPeer = cids.currentPeer
    paths.active = p
    loss.rtt = p.rtt
    loss.activePath = p.id.value
    if (old.remote != p.remote) onRemoteChanged?.invoke(old.remote, p.remote)
    // RFC 9000 section 9.3.3: probe the previous path too, against off-path forwarding
    if (challengeOld && old.state == PathState.Validated) startValidation(old)
    // RFC 9000 section 9.5: the new path keeps the unused ID it probed with (or takes one); the old path keeps its own while it is still probed, otherwise it is retired
    val held = p.peerCid?.takeIf { cids.isActive(it) }
    p.peerCid = null
    val moved =
        if (held != null) {
            cids.makeCurrent(held)
            true
        } else {
            cids.rotatePeerCid(retireOld = false)
        }
    if (moved && oldPeer != null &&
        oldPeer !== cids.currentPeer
    ) {
        if (old.state ==
            PathState.Validating
        ) {
            oldPeer.heldByPath = true
            old.peerCid = oldPeer
        } else {
            cids.releasePathPeer(oldPeer)
        }
    }
    remoteCid = cids.activePeerCid()
    events += ConnectionEvent.PathChanged(old.id, p.id, reason)
    qlog?.metricsUpdated(stats, now)
}

/**
 * The DCID of a packet to [p] (RFC 9000 section 9.5): the active path carries the current peer ID; any other path an unused one of its own,
 * reserved on its first packet. Null when the peer gave us no spare and reuse would link the paths; a server answering a new address from
 * the same socket may keep the current ID (section 9.5 allows it for a peer whose address changed under it), and a zero-length ID is never a link.
 */
internal fun ConnectionCore.dcidFor(p: Path): ConnectionId? {
    if (p === paths.active || remoteCid.length == 0) return remoteCid
    p.peerCid?.let {
        if (cids.isActive(it)) return it.cid
        p.peerCid = null
    }
    cids.takePathPeer()?.let {
        p.peerCid = it
        return it.cid
    }
    return if (role == TlsRole.Server && p.socket == paths.active.socket) remoteCid else null
}

/** Fresh unpredictable data for the PATH_CHALLENGE about to go out on [p] (RFC 9000 sections 8.2.1 and 13.3). */
internal fun ConnectionCore.newChallengeData(p: Path): Long {
    var d = random.nextLong()
    while (d == 0L || p.answers(d)) d = random.nextLong()
    p.onChallengeSent(d)
    return d
}

/** A path that stopped probing gives its peer ID back (retired: it was used, RFC 9000 section 9.5). */
internal fun ConnectionCore.releasePathCid(p: Path) {
    val peer =
        p.peerCid ?: return
    p.peerCid = null
    if (p !== paths.active) cids.releasePathPeer(peer)
}

internal fun ConnectionCore.onPathFailed(
    p: Path,
    reason: PathFailureReason = PathFailureReason.ValidationTimeout,
) {
    p.state = PathState.Failed
    p.awaitingCid = false
    p.challengePending = false
    p.challengeDeadline = TimeMark.NEVER
    p.nextChallengeAt = TimeMark.NEVER
    p.standbyUntil =
        now + validationTimeout()
    releasePathCid(p)
    events += ConnectionEvent.PathFailed(p.id, reason)
    if (p !== paths.active) return
    val back = paths.fallback(p)
    if (back != null) {
        // RFC 9000 section 9.3.2: the most recently validated path
        switchPath(back, PathChangeReason.ValidationFailed, challengeOld = false)
    } else {
        silentClose(QuicException.ConnectionLost.NoViablePath())
    }
}

/** PATH_CHALLENGE from [from]: the response goes back there (RFC 9000 section 8.2.2); at most three wait, more cost a glitch token (threat-model 3.2). */
internal fun ConnectionCore.onPathChallenge(
    data: Long,
    socket: PathId,
    from: InetSocketAddress,
    datagramBytes: Int,
) {
    var p = paths.byRemote(socket, from)
    if (p ==
        null
    ) {
        p = paths.add(socket, from, config.congestionController(), config.initialRtt)
        if (p ==
            null
        ) {
            glitch(0x1a)
            return
        }
        p.amplification.onReceived(datagramBytes)
    }
    if (!paths.queueResponse(data, p)) glitch(0x1a)
}

/** PATH_RESPONSE: validates the path whose challenge it answers, wherever it arrived (RFC 9000 section 8.2.3); unknown data is ignored. */
internal fun ConnectionCore.onPathResponse(data: Long) {
    for (i in 0 until paths.all.size) {
        val p = paths.all[i]
        if (p.state == PathState.Validating && p.answers(data)) {
            p.state = PathState.Validated
            p.amplification.validated = true
            p.challengePending = false
            p.challengeRetries = 0
            p.challengeDeadline =
                TimeMark.NEVER
            p.nextChallengeAt = TimeMark.NEVER
            p.validatedAt = now
            paths.lastValidated = p
            if (p !==
                paths.active
            ) {
                releasePathCid(p)
            }
            events += ConnectionEvent.PathValidated(p.id)
            return
        }
    }
}

/**
 * A client Initial or Handshake packet decrypted from a new address while the handshake is still open: the client's NAT mapping
 * changed between its first flight and ours (the interop runner's rebind cases do this one second in). RFC 9000 section 9 lets a
 * server "proceed with path validation and allow the peer to migrate"; a PATH_CHALLENGE could not be answered before the client
 * holds 1-RTT keys, so the handshake itself validates: the active path follows the latest decrypted source, its amplification
 * budget starts over for the new address (section 8.1), a PATH_CHALLENGE leads the first datagram there (section 9.1) and the next
 * Handshake packet from it marks it validated again.
 * Packets already in flight to the old address are retransmitted by the usual PTO to the new one.
 */
internal fun ConnectionCore.onHandshakeAddressChange(
    socket: PathId,
    from: InetSocketAddress,
    datagramBytes: Int,
    initial: Boolean,
) {
    val p = paths.active
    if (socket != p.socket) return
    if (!migrationAllowedFrom(from)) return // allowMigration = false (and the loopback/link-local rule) holds during the handshake too
    // Initial keys are public: an Initial moves the path only once the current address went quiet for a PTO; a Handshake packet proves
    // the client
    if (initial && now - lastReceivedOnActivePath < pto()) return
    val old = p.remote
    p.remote = from
    p.validatedAt = TimeMark.NEVER
    p.amplification.reset()
    p.amplification.onReceived(datagramBytes)
    // a PATH_CHALLENGE leads the first datagram to the new address and is repeated until answered (a client without 1-RTT keys drops
    // the first one)
    startValidation(p)
    onRemoteChanged?.invoke(old, from)
    qlog?.metricsUpdated(stats, now)
}

/**
 * The server saw a Handshake packet: the client's address is validated (RFC 9000 section 8.1). A PATH_CHALLENGE sent to that
 * address during the handshake stays outstanding (a client that had no 1-RTT keys yet dropped it; it answers a repeat), so the
 * path keeps validating with a fresh deadline that settles it instead of failing it.
 */
internal fun ConnectionCore.onInitialPathValidated() {
    val p = paths.active
    p.amplification.validated = true
    if (p.state == PathState.Validating) {
        p.handshakeValidated = true
        p.challengeDeadline = now + validationTimeout()
    } else if (p.state != PathState.Validated) {
        p.state = PathState.Validated
        p.validatedAt = now
        paths.lastValidated = p
    }
}

/** The handshake validated the address but no PATH_RESPONSE ever came: the path counts as validated at its deadline. */
internal fun ConnectionCore.settleHandshakeValidated(p: Path) {
    p.state = PathState.Validated
    p.handshakeValidated = false
    p.challengePending = false
    p.challengeDeadline = TimeMark.NEVER
    p.nextChallengeAt =
        TimeMark.NEVER
    p.validatedAt = now
    paths.lastValidated = p
    events += ConnectionEvent.PathValidated(p.id)
}
