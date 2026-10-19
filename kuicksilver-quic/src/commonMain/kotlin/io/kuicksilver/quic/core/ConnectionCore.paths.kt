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

/**
 * The validation timeout of RFC 9000 section 8.2.4: max(3 x PTO, 6 x initial RTT), as ngtcp2. The new-path term uses the configured
 * initial RTT (kInitialRtt), never an RTT remembered for the first path: "the new path could have a longer round-trip time".
 */
internal fun ConnectionCore.validationTimeout(): Duration {
    val p3 = pto() * 3
    val r6 = config.newPathInitialRtt * 6
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
        if (rxDcidSeq >= 0) activeDcidSeq = rxDcidSeq
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
            config.newPathInitialRtt,
            now = now,
            abandonValidatingHeardBefore = if (migrating) TimeMark.NEVER else now - idle,
        ) ?: return
        p.amplification.onReceived(datagramBytes)
        // NAT rebinding keeps the congestion state (same network); the old address probes on a controller of its own
        if (sameIp(from, active.remote)) p.inheritFrom(active, config.congestionController())
        initServerPath(p, active)
        startValidation(p)
    } else if (p.state == PathState.Unknown || (p.state == PathState.Failed && p.standbyUntil <= now)) {
        startValidation(p) // a path first seen through the peer's probe is validated once it carries anything else
    }
    notePeerDcid(p)
    p.lastReceivedAt = now
    if (nonProbing &&
        pn > largestNonProbingPn
    ) {
        largestNonProbingPn = pn
        // no ID to send there without linking the paths (RFC 9000 section 9.5): stay until the client gives us one
        if (p.state != PathState.Failed &&
            dcidFor(p) != null
        ) {
            switchPath(
                p,
                if (sameIp(from, active.remote)) PathChangeReason.NatRebinding else PathChangeReason.PeerMigration,
                challengeOld = true,
            )
        }
    }
}

/** Server: records whether the 1-RTT packet just received on [p] carries another of our IDs than the active path's packets. */
private fun ConnectionCore.notePeerDcid(p: Path) {
    if (p !== paths.active && rxDcidSeq >= 0 && activeDcidSeq >= 0) p.peerChangedDcid = rxDcidSeq != activeDcidSeq
}

/**
 * Server: a path the client opened toward our socket gets what that socket does for the active path: ECN validated afresh (RFC 9000
 * section 13.4.2) and DPLPMTUD with black-hole detection (RFC 8899 section 4.3; RFC 9000 section 14), starting from the MTU a NAT
 * rebinding inherited ([Path.inheritFrom]) or from 1200 on a new address.
 */
private fun ConnectionCore.initServerPath(
    p: Path,
    active: Path,
) {
    p.caps = active.caps
    if (p.caps.ecnSend) p.ecn.enable()
    if (p.caps.df && config.pmtud && p.pmtud == null) p.pmtud = Pmtud(upperBound = pmtudUpperBound(), start = p.mtu)
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
    p.peerProbed = false
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
 * the same socket may keep the current ID only while the client's packets there carry the same DCID as on the active path (section 9.5:
 * "Due to network changes outside the control of its peer ... it MAY continue to use the current connection ID"), and a zero-length ID
 * is never a link.
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
    return if (role == TlsRole.Server && p.socket == paths.active.socket && !p.peerChangedDcid) remoteCid else null
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
        p = paths.add(socket, from, config.congestionController(), config.newPathInitialRtt)
        if (p ==
            null
        ) {
            glitch(0x1a)
            return
        }
        p.amplification.onReceived(datagramBytes)
        if (role == TlsRole.Server) initServerPath(p, paths.active)
    }
    if (role == TlsRole.Server && p !== paths.active) {
        notePeerDcid(p)
        p.peerProbed = true
    }
    if (!paths.queueResponse(data, p)) glitch(0x1a)
}

/** PATH_RESPONSE: validates the path whose challenge it answers, wherever it arrived (RFC 9000 section 8.2.3); unknown data is ignored. */
internal fun ConnectionCore.onPathResponse(data: Long) {
    for (i in 0 until paths.all.size) {
        val p = paths.all[i]
        if (p.state == PathState.Validating && p.answers(data)) {
            p.amplification.validated = true
            if (p.answeredUndersized(data)) {
                // RFC 9000 section 8.2.1: the address is validated, the path MTU is not: "the endpoint MUST perform a second path
                // validation by sending a PATH_CHALLENGE frame in a datagram of at least 1200 bytes" (as ngtcp2's UNDERSIZED entries)
                startValidation(p)
                return
            }
            p.state = PathState.Validated
            p.challengePending = false
            p.challengeRetries = 0
            p.challengeDeadline =
                TimeMark.NEVER
            p.nextChallengeAt = TimeMark.NEVER
            p.validatedAt = now
            paths.lastValidated = p
            if (p === paths.active) handshakeFallback = null
            // a client gives back the ID of a path it only probed; a server keeps the one it answers a client's probe with, since the
            // client probes to migrate there next, and the switch must not need another spare ID (RFC 9000 section 9.5)
            if (p !== paths.active && (role == TlsRole.Client || !p.peerProbed)) releasePathCid(p)
            events += ConnectionEvent.PathValidated(p.id)
            return
        }
    }
}

/**
 * A client Initial or Handshake packet decrypted from a new address while the handshake is still open: the client's NAT mapping
 * changed between its first flight and ours (the interop runner's rebind cases do this one second in). RFC 9000 section 9 lets a
 * server "proceed with path validation and allow the peer to migrate": the active path follows the latest decrypted source, and its
 * amplification budget starts over for the new address.
 *
 * No packet proves the address it came from: an off-path attacker that sees the client's datagrams can race a copy of any of them
 * from a spoofed source (sections 9.3.3 and 21.1.3.2), and the genuine one is then dropped as a duplicate. A Handshake packet proves
 * that the client got our flight where we sent it, so it validates the active address only when that is where the whole flight
 * went ([onInitialPathValidated]); an acknowledgement of a Handshake or 1-RTT packet sent to the current address proves it too
 * ([onHandshakePathAcked]), and so does a PATH_RESPONSE. Every move is therefore provisional: the address it left is kept in a
 * [HandshakeFallback], and [revertHandshakeMove] returns there when nothing validated the new one within a validation period.
 *
 * When the move happens:
 *  * a Handshake packet: at once, led by a PATH_CHALLENGE (the client that sends it can soon answer one: it reads our Finished);
 *  * the datagram that completes the ClientHello (the server gets its keys from it): at once, after TLS ran on it
 *    ([ConnectionCore.afterInput]). Its CRYPTO bytes are what the whole handshake answers, so the flight must go where they came
 *    from (the 0.2.0 gate's kuicksilver->quiche:rebind-addr otherwise sent its whole ServerHello flight to the dead old mapping for
 *    2 s). No PATH_CHALLENGE leads: no ServerHello has left yet, so the client cannot read 1-RTT packets and would drop the probe
 *    (quiche does, "dropped invalid packet"); since the whole flight then goes to the new address, the client's Handshake packet
 *    validates it;
 *  * any other Initial (Initial keys are public, anyone can forge one): only once the current address went quiet for a PTO, and
 *    only when the server can lead the new address with a PATH_CHALLENGE (it holds 1-RTT keys): a repeat of the first half of a
 *    two-datagram ClientHello would otherwise send its Initial ACK there first.
 *
 * A newer packet from the address the move left takes the path back before the deadline (section 9.3.2). The new address's budget
 * counts every datagram the server decrypted from it since it first appeared (a ClientHello repeated in two datagrams credits both,
 * not only the second; section 8.1 counts all bytes received from the address), and the old one's what came from it meanwhile.
 * Packets in flight to the old address are resent by the usual PTO.
 */
internal fun ConnectionCore.onHandshakeAddressChange(
    socket: PathId,
    from: InetSocketAddress,
    datagramBytes: Int,
    datagram: Long,
    initial: Boolean,
    newest: Boolean,
) {
    val p = paths.active
    if (socket != p.socket) return
    if (handshakeMovesFrozen) return // a move already failed its validation: the address stays until the handshake completes
    if (!migrationAllowedFrom(from)) return // allowMigration = false (and the loopback/link-local rule) holds during the handshake too
    val fallback = handshakeFallback
    if (fallback != null && fallback.isAddress(from)) {
        fallback.credit(datagram, datagramBytes)
    } else {
        val credit = handshakeCredit?.takeIf { it.from == from } ?: HandshakeCredit(from).also { handshakeCredit = it }
        credit.credit(datagram, datagramBytes)
    }
    if (!newest) return
    val haveKeys = writeKeys[3] != null
    // with the keys already there, an Initial completes nothing: it moves the path only once the current address went quiet for a PTO
    if (initial && haveKeys && now - lastReceivedOnActivePath < pto()) return
    if (!initial || haveKeys) {
        pendingHandshakeMove = null
        applyHandshakeMove(from, completesClientHello = false)
    } else {
        pendingHandshakeMove = from // decided once TLS ran on this datagram: only a ClientHello it completed moves the path
    }
}

/** Bytes of the datagrams the server decrypted from [from], a client address the active path does not have yet (see [onHandshakeAddressChange]). */
internal class HandshakeCredit(
    val from: InetSocketAddress,
) {
    var bytes: Long = 0
    var lastDatagram: Long = -1

    /** Counts datagram number [datagram] once, however many of its packets decrypt. */
    fun credit(
        datagram: Long,
        size: Int,
    ) {
        if (lastDatagram == datagram) return
        lastDatagram = datagram
        bytes += size
    }
}

/** [afterInput]: the datagram from [from] that recorded a pending move went through TLS; it moves the path if it completed the ClientHello. */
internal fun ConnectionCore.onHandshakeDatagramDone(from: InetSocketAddress) {
    if (writeKeys[3] != null) applyHandshakeMove(from, completesClientHello = true)
}

/**
 * Moves the active path to [from] (see [onHandshakeAddressChange]), keeping the address it leaves in [ConnectionCore.handshakeFallback]
 * until the new one is validated; back to that address, it restores it instead. [completesClientHello]: the server only now got its
 * keys, so no ServerHello has left yet and no PATH_CHALLENGE leads; otherwise one does.
 */
internal fun ConnectionCore.applyHandshakeMove(
    from: InetSocketAddress,
    completesClientHello: Boolean,
) {
    if (writeKeys[3] == null || state != io.kuicksilver.quic.ConnectionState.Handshaking) return
    val p = paths.active
    if (p.isRemote(from)) return
    val fallback = handshakeFallback
    if (fallback != null && fallback.isAddress(from)) {
        // a newer packet from the address the unvalidated move left (section 9.3.2): back there as at the deadline, without the freeze
        restoreHandshakeAddress(fallback, resendAtOnce = handshakeRestores == 0)
        return
    }
    val old = p.remote
    if (fallback == null) {
        // a further move before the first is validated keeps the first one's address and deadline
        handshakeFallback =
            HandshakeFallback(
                p,
                old,
                epoch = p.addressEpoch,
                validated = p.state == PathState.Validated,
                validatedAt = p.validatedAt,
                received = p.amplification.received,
                sent = p.amplification.sent,
                addressValidated = p.amplification.validated,
                flightOnlyThere = handshakeFlightTo?.let { p.isRemote(it) } == true && !handshakeFlightElsewhere,
                deadline = now + validationTimeout(),
            )
    }
    p.remote = from
    p.validatedAt = TimeMark.NEVER
    p.amplification.reset()
    p.amplification.onReceived((handshakeCredit?.takeIf { it.from == from }?.bytes ?: 0L).toInt())
    handshakeCredit = null
    lastReceivedOnActivePath = now
    if (completesClientHello) {
        // validated by the client's first Handshake packet (onInitialPathValidated), its acknowledgements or a PATH_RESPONSE
        p.forgetChallenges()
        p.challengePending = false
        p.state = PathState.Unknown
        p.handshakeValidated = false
        p.challengeDeadline = TimeMark.NEVER
        p.nextChallengeAt = TimeMark.NEVER
    } else {
        // a PATH_CHALLENGE leads the first datagram to the new address and is repeated until answered (a client that has no 1-RTT keys
        // yet drops the first one)
        startValidation(p)
    }
    onRemoteChanged?.invoke(old, from)
    qlog?.metricsUpdated(stats, now)
}

/**
 * The server sent CRYPTO data of its handshake flight (an Initial or Handshake packet) on [target]: a client Handshake packet validates
 * an address only if the whole flight went there ([onInitialPathValidated]).
 */
internal fun ConnectionCore.onHandshakeFlightSent(target: Path) {
    val to = handshakeFlightTo
    if (to == null) {
        handshakeFlightTo = target.remote
    } else if (!target.isRemote(to)) {
        handshakeFlightElsewhere = true
    }
}

/**
 * The server decrypted a Handshake packet from [from]. It shows that the client processed our flight (RFC 9000 section 8.1), not that
 * [from] is the client: a copy raced from a spoofed address carries it as well. The active address is validated only when the packet
 * came from it and the whole flight went there and nowhere else, so the client can only have read it there.
 */
internal fun ConnectionCore.onInitialPathValidated(from: InetSocketAddress) {
    val p = paths.active
    val to = handshakeFlightTo ?: return
    if (handshakeFlightElsewhere || !p.isRemote(from) || !p.isRemote(to)) return
    validateHandshakeAddress(p)
}

/**
 * A Handshake or 1-RTT packet that went out on path [pathId] in its address epoch [epoch] was acknowledged (Handshake and 1-RTT keys
 * are not public, so no one but the client can acknowledge it): the address it went to reached the client. That validates the
 * handshake path's current address (RFC 9000 section 8.1's argument, without trusting the source of the acknowledging packet), and
 * marks the address a pending [HandshakeFallback] keeps as reached.
 */
internal fun ConnectionCore.onHandshakePathAcked(
    pathId: Int,
    epoch: Int,
) {
    if (pathId != PathId.Initial.value) return
    val fallback = handshakeFallback
    if (fallback != null && epoch == fallback.epoch) fallback.reached = true
    val p = paths.active
    if (p.id != PathId.Initial || epoch != p.addressEpoch || (fallback == null && p.amplification.validated)) return
    validateHandshakeAddress(p)
}

/** The handshake path's current address is validated (see [onInitialPathValidated], [onHandshakePathAcked]). */
internal fun ConnectionCore.validateHandshakeAddress(p: Path) {
    if (handshakeFallback?.path === p) handshakeFallback = null
    p.amplification.validated = true
    if (p.state == PathState.Validating) {
        // a PATH_CHALLENGE sent to the address stays outstanding (a client that had no 1-RTT keys yet dropped it; it answers a repeat),
        // so the path keeps validating with a fresh deadline that settles it instead of failing it
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

/**
 * The address a handshake-time move took [path] away from (see [ConnectionCore.applyHandshakeMove]), with what the server knew about
 * it, kept until the new address is validated or [deadline] passes.
 */
internal class HandshakeFallback(
    val path: Path,
    val remote: InetSocketAddress,
    val epoch: Int,
    val validated: Boolean,
    val validatedAt: TimeMark,
    val received: Long,
    val sent: Long,
    val addressValidated: Boolean,
    val flightOnlyThere: Boolean,
    val deadline: TimeMark,
) {
    private val remoteKey = AddressClass.ipKey(remote)

    /** A packet sent to this address before the move was acknowledged: the client is there. */
    var reached: Boolean = false

    /** Bytes received from this address since the move, each datagram once. */
    var receivedSince: Long = 0
    private var lastDatagram: Long = -1

    fun isAddress(a: InetSocketAddress): Boolean = remote == a || (remote.port == a.port && remoteKey == AddressClass.ipKey(a))

    fun credit(
        datagram: Long,
        size: Int,
    ) {
        if (lastDatagram == datagram) return
        lastDatagram = datagram
        receivedSince += size
    }
}

/**
 * [fallback]'s deadline passed and nothing validated the address a handshake-time move took the path to: the move is undone (RFC 9000
 * section 9.3.2: "revert to using the last validated peer address when validation of a new peer address fails", with the section
 * 8.2.4 period, max(3 x PTO, 6 x initial RTT), as for any path validation). This can happen after the handshake completed too: a
 * raced copy of the client's Handshake packet may carry its Finished.
 *
 * The new address may keep sending: an off-path attacker that sees the client's datagrams races a copy of each from a spoofed source
 * (sections 9.3.3 and 21.1.3.2), so every genuine datagram after the copy is dropped as a duplicate, the spoofed address stays fresh
 * and the client's own looks quiet; the address that keeps sending proves nothing, the client's ability to answer our flight does.
 * The server returns to the address it had before the move ([restoreHandshakeAddress]) and follows no other address until the
 * handshake completes, as quic-go, quiche, msquic and ngtcp2 never do during a handshake (section 9: "The design of QUIC relies on
 * endpoints retaining a stable address for the duration of the handshake"). A client that really rebound is not hurt: it answers the
 * flight or the PATH_CHALLENGE from its new address well inside the period. One that gets nothing through for a whole period ends
 * on its old address, as with those implementations.
 */
internal fun ConnectionCore.revertHandshakeMove(fallback: HandshakeFallback) {
    handshakeFallback = null
    if (state == io.kuicksilver.quic.ConnectionState.Closing || state == io.kuicksilver.quic.ConnectionState.Draining ||
        state == io.kuicksilver.quic.ConnectionState.Closed
    ) {
        return
    }
    val p = fallback.path
    // a 1-RTT migration already took the connection to another path, or the address was validated meanwhile: nothing to undo
    if (p !== paths.active || p.amplification.validated || fallback.isAddress(p.remote)) return
    handshakeMovesFrozen = true
    // the handshake completed and, when the path moved, the whole flight had gone to the old address only: the client read it there
    if (state != io.kuicksilver.quic.ConnectionState.Handshaking && fallback.flightOnlyThere) fallback.reached = true
    restoreHandshakeAddress(fallback, resendAtOnce = true)
}

/**
 * Puts [fallback]'s address back on its path with that address's state and budget. [resendAtOnce]: what went to the other address is
 * resent here at once (the deadline's revert, and the first restore of a connection); a later restore by a newer packet leaves it to
 * the PTO, or an attacker alternating raced copies with the client's own packets would have every pair answered with all that is
 * outstanding.
 */
internal fun ConnectionCore.restoreHandshakeAddress(
    fallback: HandshakeFallback,
    resendAtOnce: Boolean,
) {
    handshakeFallback = null
    pendingHandshakeMove = null
    handshakeCredit = null
    val p = fallback.path
    val old = p.remote
    p.remote = fallback.remote
    val reached = fallback.addressValidated || fallback.reached
    p.amplification.restore(fallback.received + fallback.receivedSince, fallback.sent, reached)
    p.forgetChallenges()
    p.challengePending = false
    p.handshakeValidated = false
    p.challengeDeadline = TimeMark.NEVER
    p.nextChallengeAt = TimeMark.NEVER
    p.challengeRetries = 0
    if (fallback.validated || reached) {
        p.state = PathState.Validated
        p.validatedAt = if (fallback.validated) fallback.validatedAt else now
        paths.lastValidated = p
    } else {
        p.state = PathState.Unknown // validated by the client's Handshake packet or acknowledgements from here on
        p.validatedAt = TimeMark.NEVER
    }
    // the flight went to the other address too: from here on only this one has it
    handshakeFlightTo = fallback.remote
    handshakeFlightElsewhere = false
    lastReceivedOnActivePath = now
    handshakeRestores++
    if (!resendAtOnce) return onRestored(old, fallback)
    handshakeResendsAtOnceForTest++
    // what went to the abandoned address goes here now, not after the PTO backoff (RFC 9002 section 6.2.4 probes)
    for (space in SpaceId.entries) {
        if (spaceDiscarded[space.ordinal] || loss.space(space).ackElicitingInFlight <= 0) continue
        if (probePending[space.ordinal] < 1) probePending[space.ordinal] = 1
        requeueForProbe(space, Int.MAX_VALUE)
    }
    onRestored(old, fallback)
}

private fun ConnectionCore.onRestored(
    old: InetSocketAddress,
    fallback: HandshakeFallback,
) {
    onRemoteChanged?.invoke(old, fallback.remote)
    qlog?.metricsUpdated(stats, now)
}
