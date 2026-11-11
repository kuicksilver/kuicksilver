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
import io.kuicksilver.quic.PREFERRED_SOCKET
import io.kuicksilver.quic.PathChangeReason
import io.kuicksilver.quic.PathFailureReason
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.recordForTest
import io.kuicksilver.quic.recovery.SentFrames
import io.kuicksilver.quic.recovery.SpaceId
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.tls.TlsRole
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
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

/**
 * A Packet Too Big about a datagram of this connection (RFC 8899 section 4.6, RFC 9000 section 14.2.1), [payload] bytes of UDP payload
 * already at least 1200: true when it passes as a hint for the active path's DPLPMTUD. It must be about the active path (the socket
 * it came on and the destination it quotes), quote the start of one of our packets there (a short header with the peer ID that path
 * uses, or a long header with our ID as source), and claim a size this path did send something larger than. ICMP is spoofable:
 * even then it only settles probes or asks for confirmation ([Pmtud.onPtb]).
 */
internal fun ConnectionCore.acceptPacketTooBig(
    quote: ByteArray,
    len: Int,
    to: InetSocketAddress,
    payload: Int,
    socket: PathId,
): Boolean {
    if (!config.pmtudIcmpHints || len < 1) return false
    val p = paths.active
    val m = p.pmtud ?: return false
    if (p.socket != socket || !p.isRemote(to) || p.largestSent <= payload) return false
    val first = quote[0].toInt() and 0xff
    val ours =
        if (first and 0x80 == 0) {
            val d = dcidFor(p) ?: return false
            // at least one byte past the ID: with a zero-length peer ID the first byte alone would do, which any datagram matches
            len >= 1 + d.length + 1 && d.contentEquals(quote, 1, d.length)
        } else {
            // version(4) | dcid len | dcid | scid len | scid: the source is our ID, the destination the peer's
            if (len < 6) return false
            val dl = quote[5].toInt() and 0xff
            if (len < 7 + dl) return false
            val sl = quote[6 + dl].toInt() and 0xff
            len >= 7 + dl + sl && remoteCid.length == dl && remoteCid.contentEquals(quote, 6, dl) && localCid.length == sl &&
                localCid.contentEquals(quote, 7 + dl, sl)
        }
    if (!ours) return false
    m.onPtb(payload, now)
    return true
}

/** The socket refused a datagram of [size] bytes as larger than the MTU the kernel knows (EMSGSIZE): settles a probe of that size. */
internal fun ConnectionCore.onEmsgsize(size: Int) {
    if (!config.pmtudIcmpHints) return
    paths.active.pmtud?.onEmsgsize(size, now)
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
        if (m.takeBlackHole(now)) setMtu(p, m.current) // 1200, or the size of a validated Packet Too Big under confirmation
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

/**
 * RETIRE_CONNECTION_ID: the ID keeps routing for 3 x PTO (RFC 9000 section 5.1.2); one for an ID already gone, or one whose
 * replacement waits because the peer retires faster than we replace (ConnectionIdManager.fill), costs a glitch token.
 */
internal fun ConnectionCore.onRetireConnectionId(seq: Long) {
    if (!cids.onPeerRetired(seq, now + pto() * 3)) glitch(0x19)
}

/**
 * The validation timeout RFC 9000 section 8.2.4 recommends: "three times the larger of the current PTO or the PTO for the new path
 * (using kInitialRtt, as defined in [QUIC-RECOVERY])". The new path's PTO is RFC 9002's before any sample (section 6.2.2: smoothed_rtt
 * = kInitialRtt, rttvar = kInitialRtt / 2), so 3 x kInitialRtt plus the peer's max_ack_delay once the handshake is confirmed: 3.07 s
 * with the default 333 ms. The configured initial RTT, never an RTT remembered for the first path: "the new path could have a longer
 * round-trip time".
 */
internal fun ConnectionCore.validationTimeout(): Duration {
    val current = pto()
    val k = config.newPathInitialRtt
    val v4 = k * 2
    val fresh =
        k + (if (v4 > 1.milliseconds) v4 else 1.milliseconds) + (if (loss.handshakeConfirmed) loss.peerMaxAckDelay else Duration.ZERO)
    return (if (current > fresh) current else fresh) * 3
}

/** False for a 1-RTT datagram from a new address the server must not follow: migration disabled, or a loopback/link-local address when the connection is not on one. */
internal fun ConnectionCore.migrationAllowedFrom(from: InetSocketAddress): Boolean {
    if (!config.allowMigration) return false
    if (config.allowMigrationToLoopback) return true
    val special = AddressClass.isLoopback(from) || AddressClass.isLinkLocal(from)
    return !special || AddressClass.isLoopback(path.remote) || AddressClass.isLinkLocal(path.remote)
}

/** Both local ends are the same IP, or both unknown (the socket does not report destinations). */
private fun sameLocal(
    a: InetSocketAddress?,
    b: InetSocketAddress?,
): Boolean = a === b || (a != null && b != null && AddressClass.ipBytes(a).contentEquals(AddressClass.ipBytes(b)))

private fun ConnectionCore.sameIp(
    a: InetSocketAddress,
    b: InetSocketAddress,
): Boolean = AddressClass.ipBytes(a).contentEquals(AddressClass.ipBytes(b))

/**
 * RFC 9000 section 9.4: "On confirming a peer's ownership of its new address, an endpoint MUST immediately reset the congestion
 * controller and round-trip time estimator for the new path to initial values ... unless the only change in the peer's address is
 * its port number". A handshake-time change of the active path's address from [old] to another IP (a move, a return, the
 * candidate's adoption) starts [p] over: a fresh congestion controller and pacer, the initial RTT of a new path, and 1200 bytes with
 * DPLPMTUD started again ([initServerPath] does the same for a path the client opens; a port-only change keeps everything, as
 * [Path.inheritFrom]). What is in flight stays with the controller that counted it.
 */
private fun ConnectionCore.resetForNewIp(
    p: Path,
    old: InetSocketAddress,
) {
    if (sameIp(old, p.remote)) return
    p.cc = config.congestionController()
    p.pacer =
        io.kuicksilver.quic.recovery
            .Pacer()
    p.rtt =
        io.kuicksilver.quic.recovery
            .RttEstimator(config.newPathInitialRtt)
    if (p === paths.active) loss.rtt = p.rtt
    setMtu(p, 1200)
    if (p.pmtud != null) p.pmtud = Pmtud(upperBound = pmtudUpperBound(), start = 1200)
}

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
    if (p != null && p.handshakeCandidate) {
        // the handshake-time candidate's address: the server does not move there on a packet's source (an off-path copy carries the
        // same packets, RFC 9000 section 9.3.3), only once the address answers its own PATH_CHALLENGE (adoptHandshakeCandidate)
        p.lastReceivedAt = now
        if (nonProbing && pn > largestNonProbingPn) largestNonProbingPn = pn
        return
    }
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
        // a new client address: our end is the address its datagram reached; one the socket could not tell keeps the current source
        p.local = serverLocal(receiver.local) ?: active.local
        p.amplification.onReceived(datagramBytes)
        // NAT rebinding keeps the congestion state (same network); the old address probes on a controller of its own. A move to our
        // preferred address changes the server's end of the path: fresh congestion state and RTT (RFC 9000 section 9.4); so does a
        // rebinding that reached another of our addresses (conservative: the path's other end may be another network path too)
        if (socket == active.socket && sameIp(from, active.remote) && sameLocal(p.local, active.local)) {
            p.inheritFrom(active, config.congestionController())
        }
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
        if (p.socket == PREFERRED_SOCKET && active.socket != PREFERRED_SOCKET) {
            // RFC 9000 section 9.6.1: non-probing packets go out from the preferred address only once the client's address is validated
            // there; until then they keep leaving the original socket
            if (p.state == PathState.Validated) moveToPreferredSocket(p) else p.preferredMovePending = true
        } else if (p.state != PathState.Failed &&
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

/**
 * Server: the client moved to our preferred address and [p], on the preferred socket, is validated (RFC 9000 section 9.6): the
 * connection moves there and the original path closes, so nothing leaves the old socket any more.
 */
private fun ConnectionCore.moveToPreferredSocket(p: Path) {
    if (dcidFor(p) == null) {
        p.preferredMovePending = true // no spare ID of the client's yet: on the next non-probing packet
        return
    }
    p.preferredMovePending = false
    val old = paths.active
    switchPath(p, PathChangeReason.PreferredAddress, challengeOld = false)
    if (old !== paths.active && old.socket != PREFERRED_SOCKET) {
        paths.remove(old)
        releasePathCid(old)
    }
}

/**
 * Server: the preferred-address sockets went down (the endpoint degrades, docs/guide/quic.md). A connection whose active path is there
 * is closed with INTERNAL_ERROR (the close may not reach the client: no socket is left on that address); a path there still under
 * validation or waiting for the move is given up and the connection stays on its original path (RFC 9000 section 9.6.1). True when
 * something changed.
 */
internal fun ConnectionCore.preferredSocketDown(): Boolean {
    if (paths.active.socket == PREFERRED_SOCKET) {
        fail(TransportError.INTERNAL_ERROR, 0, "the server's preferred-address socket failed", null)
        return true
    }
    val gone = paths.all.filter { it.socket == PREFERRED_SOCKET }
    for (p in gone) {
        if (p.state != PathState.Failed) onPathFailed(p)
        paths.remove(p)
        releasePathCid(p)
    }
    return gone.isNotEmpty()
}

/**
 * Client, once the handshake is confirmed (RFC 9000 section 9.6): a path to the server's preferred address of the family in use,
 * under validation with the server's sequence-1 ID. Once only; nothing when `QuicConfig.followPreferredAddress` is off, the server
 * offers no address of this family, uses zero-length IDs, or points a client that reached it on a public address at a local one
 * (or any connection at an unspecified, multicast or broadcast address: threat-model 3.14).
 */
internal fun ConnectionCore.startPreferredProbe() {
    if (preferredProbeStarted) return
    preferredProbeStarted = true
    if (!config.followPreferredAddress) return
    val tp = peerTp ?: return
    if (!tp.preferredAddressPresent || remoteCid.length == 0) return
    val active = paths.active
    val v4 = AddressClass.ipBytes(active.remote).size == 4
    val target = (if (v4) tp.preferredIpv4 else tp.preferredIpv6) ?: return
    if (active.isRemote(target)) return
    if (AddressClass.isUnsafeDestination(target, originLocal = AddressClass.isLocalNetwork(active.remote))) return
    if (AddressClass.isReflectivePort(target.port)) return // a server must not aim our probes at a DNS, NTP or other reflector
    val p = paths.add(active.socket, target, config.congestionController(), config.newPathInitialRtt, evict = false) ?: return
    p.amplification.validated = true // our own probe toward the server: nothing to amplify against
    p.preferred = true
    startValidation(p)
}

/** Client: a preferred-address path still under validation is closed (an application's own migration replaces it; never retried). */
internal fun ConnectionCore.abandonPreferredProbe() {
    val p = paths.all.firstOrNull { it.preferred && it !== paths.active } ?: return
    paths.remove(p)
    releasePathCid(p)
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
private val PATH_IDLE_TIMEOUT: Duration = 5.seconds

internal fun ConnectionCore.startValidation(p: Path) {
    p.revalidateAt = TimeMark.NEVER
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
 * Section 9.3.3: "In response to an apparent migration, endpoints MUST validate the previously active path using a PATH_CHALLENGE
 * frame." The validation starts at once, but its first PATH_CHALLENGE leaves no sooner than one PTO after the latest one sent on
 * that path (section 8.2.1: "An endpoint SHOULD NOT probe a new path with packets containing a PATH_CHALLENGE frame more frequently
 * than it would send an Initial packet"). Without that gap, an observer racing copies of the client's datagrams from a second
 * address, with both alive, made every answer to a challenge the next apparent migration and the next challenge: an endless
 * exchange, one round per round trip, that only the AEAD confidentiality limit ended. quic-go keeps its probes of a path behind a
 * backoff (path_manager.go:93, :114-116) and switches only to validated paths; ngtcp2 does not validate a path again within ten
 * minutes of validating it (lib/ngtcp2_conn.c:9128, :14653), which skips the section 9.3.3 challenge altogether.
 */
private fun ConnectionCore.revalidatePreviousPath(p: Path) {
    val last = p.lastChallengeAt
    if (last != TimeMark.NEVER && now - last < pto()) {
        // the path keeps its state (it stays a fallback and may give its slot up as before); the validation starts at that time
        p.revalidateAt = last + pto()
    } else {
        startValidation(p)
    }
}

/** [revalidatePreviousPath]'s deferred validation of [p] is due: it starts unless the path is active again or already validating. */
internal fun ConnectionCore.onRevalidateDue(p: Path) {
    p.revalidateAt = TimeMark.NEVER
    if (p === paths.active) return
    if (p.state == PathState.Validated) {
        startValidation(p)
    } else if (p.state != PathState.Validating) {
        releasePathCid(p)
    }
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
    dropHandshakeCandidate() // a migration after the handshake supersedes a handshake-time rebind still being decided
    val oldPeer = cids.currentPeer
    paths.active = p
    p.peerProbed = false
    loss.rtt = p.rtt
    loss.activePath = p.id.value
    if (old.remote != p.remote) onRemoteChanged?.invoke(old.remote, p.remote)
    // RFC 9000 section 9.3.3: probe the previous path too, against off-path forwarding
    if (challengeOld && old.state == PathState.Validated) revalidatePreviousPath(old)
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
        // a deferred revalidation (revalidatePreviousPath) counts as a validation under way: retiring the ID now would have the client
        // issue a new one at once, and under a copy race every switch would cost a NEW_CONNECTION_ID that the race turns into the
        // next switch
        if (old.state == PathState.Validating || old.revalidateAt != TimeMark.NEVER) {
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
    // the handshake-time candidate: the client did not choose this address change (a NAT rebinding), so the current ID may go there
    // too (section 9.5: "it MAY continue to use the current connection ID"); the client has no spare IDs to give before the handshake
    if (p.handshakeCandidate) return remoteCid
    p.peerCid?.let {
        if (cids.isActive(it)) return it.cid
        p.peerCid = null
    }
    cids.takePathPeer()?.let {
        p.peerCid = it
        return it.cid
    }
    // the current ID only toward a new client address from the same local address (a NAT rebinding the client did not choose, section
    // 9.5 MAY); "MUST NOT reuse a connection ID when sending from more than one local address": a path that took another address of
    // ours (its first datagram reached it) waits for a spare one
    return if (role == TlsRole.Server && p.socket == paths.active.socket && sameLocal(p.local, paths.active.local) &&
        !p.peerChangedDcid
    ) {
        remoteCid
    } else {
        null
    }
}

/** Fresh unpredictable data for the PATH_CHALLENGE about to go out on [p] (RFC 9000 sections 8.2.1 and 13.3). */
internal fun ConnectionCore.newChallengeData(p: Path): Long {
    var d = random.nextLong()
    while (d == 0L || p.answers(d)) d = random.nextLong()
    p.onChallengeSent(d)
    p.lastChallengeAt = now
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
    if (p !== paths.active) {
        // RFC 9000 section 9.6.1: a preferred address that does not validate is given up; the connection stays where it was
        if (p.preferred) paths.remove(p)
        return
    }
    val back = paths.fallback(p)
    if (back != null) {
        // RFC 9000 section 9.3.2: the most recently validated path
        switchPath(back, PathChangeReason.ValidationFailed, challengeOld = false)
    } else {
        silentClose(QuicException.ConnectionLost.NoViablePath())
    }
}

/**
 * PATH_CHALLENGE from [from]: answered once, back on the network path it came by (RFC 9000 section 8.2.2), from the local address it
 * reached. Every one is answered; past three waiting each costs a glitch token, and past [Paths.MAX_RESPONSES] the connection closes
 * (threat-model 3.2): a flood ends the connection, never a challenge left unanswered on an open one.
 */
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
        p.local = serverLocal(receiver.local) ?: paths.active.local // unknown destination: the current source
        p.amplification.onReceived(datagramBytes)
        if (role == TlsRole.Server) initServerPath(p, paths.active)
    }
    if (role == TlsRole.Server && p !== paths.active) {
        notePeerDcid(p)
        p.peerProbed = true
    }
    if (paths.responses >= Paths.FREE_RESPONSES) glitch(0x1a)
    val at = serverLocal(receiver.local)
    val own = p.local
    if (!paths.queueResponse(data, p, if (at != null && own != null && at != own) at else null)) {
        throw QuicWireException(TransportError.PROTOCOL_VIOLATION, 0x1a, "more than ${Paths.MAX_RESPONSES} PATH_RESPONSEs owed")
    }
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
            if (p.handshakeCandidate) {
                // decided once the packet's frames are all in (finishPathResponses): when it also answers the active address's
                // challenge, the active address keeps the path
                p.state = PathState.Validated
                p.challengePending = false
                p.challengeDeadline = TimeMark.NEVER
                p.nextChallengeAt = TimeMark.NEVER
                candidateAnswered = true
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
            if (p === paths.active) {
                handshakeFallback = null
                // the client answered on the active address: a handshake-time rebind is decided, the other address is dropped and the
                // path stays here for the rest of the handshake
                if (handshakeCandidate != null) {
                    dropHandshakeCandidate()
                    handshakeMovesFrozen = true
                }
            }
            // a client gives back the ID of a path it only probed; a server keeps the one it answers a client's probe with, since the
            // client probes to migrate there next, and the switch must not need another spare ID (RFC 9000 section 9.5)
            val preferredMove = role == TlsRole.Server && p.preferredMovePending && p !== paths.active
            val toPreferred = role == TlsRole.Client && p.preferred && p !== paths.active
            if (p !== paths.active && !preferredMove && !toPreferred && (role == TlsRole.Client || !p.peerProbed)) releasePathCid(p)
            events += ConnectionEvent.PathValidated(p.id)
            if (preferredMove) {
                moveToPreferredSocket(p)
                return
            }
            if (toPreferred) {
                // RFC 9000 section 9.6.2: the move happens on the validated path, which keeps the sequence-1 ID it probed with
                val old = paths.active
                switchPath(p, PathChangeReason.PreferredAddress, challengeOld = false)
                movedToPreferred = true
                if (old !== paths.active) {
                    paths.remove(old)
                    releasePathCid(old)
                }
                return
            }
            // a client validated on a new IP gets a token for it (ngtcp2's NGTCP2_PATH_VALIDATION_FLAG_NEW_TOKEN)
            if (role == TlsRole.Server && p === paths.active) issueNewToken(p.remote)
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
 * Two candidates (0.3.0): the first move also keeps the address it left as a path of its own, the candidate
 * ([ConnectionCore.handshakeCandidate], [openHandshakeCandidate]), with that address's budget and a validation of its own (section
 * 9.3.3: the previously active path is validated). From then on the two addresses of that rebind each keep their validation,
 * whichever of them the active path has: a newer packet from the candidate's address swaps them ([swapWithHandshakeCandidate]), so a
 * challenge sent to one address stays answerable however often copies move the path. The first address to answer its own
 * challenge data decides, wherever the answer came from: the active one keeps the path ([onPathResponse]), the candidate's takes it
 * ([adoptHandshakeCandidate]). A server reads no 1-RTT packet before its handshake completes (RFC 9001 section 5.7), so the
 * candidate outlives the completion until it is decided, fails its validation, or a 1-RTT migration supersedes it ([switchPath]). A
 * third address moves the active path by the rules above but never becomes the candidate. Before, an off-path observer that raced
 * copies of a really rebound client's datagrams from its old address kept taking the path back there, the challenge sent to the
 * new address was forgotten each time, and the handshake failed at its timeout.
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
    // with the keys already there, an Initial completes nothing: it moves the path only once the current address went quiet for a PTO;
    // until then a client that never got our ServerHello may be there: it gets the flight's retransmissions too (openHandshakeMirror)
    if (initial && haveKeys && now - lastReceivedOnActivePath < pto()) {
        openHandshakeMirror(from)
        return
    }
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
private fun ConnectionCore.applyHandshakeMove(
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
    val k = handshakeCandidate?.takeIf { it.isRemote(from) }
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
    if (k != null) {
        // back to the candidate's address: it brings its own budget and validation, and the address left becomes the candidate
        handshakeCredit = null
        swapWithHandshakeCandidate(p, k)
        // one that was never challenged is now, as a new address would be (or, with the ClientHello's completion, left to the
        // client's Handshake packet)
        if (p.state != PathState.Validating && p.state != PathState.Validated && !completesClientHello) startValidation(p)
        resetForNewIp(p, old)
        lastReceivedOnActivePath = now
        onRemoteChanged?.invoke(old, from)
        qlog?.metricsUpdated(stats, now)
        return
    }
    openHandshakeCandidate(p, from)
    p.remote = from
    resetForNewIp(p, old)
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
private fun ConnectionCore.validateHandshakeAddress(p: Path) {
    if (handshakeFallback?.path === p) handshakeFallback = null
    p.amplification.validated = true
    if (p.state == PathState.Validating) {
        // a PATH_CHALLENGE sent to the address stays outstanding (a client that had no 1-RTT keys yet dropped it; it answers a repeat),
        // so the path keeps validating with a fresh deadline that settles it instead of failing it
        p.handshakeValidated = true
        p.challengeDeadline = now + validationTimeout()
    } else if (p.state != PathState.Validated) {
        if (handshakeCandidate != null) {
            confirmStillThere(p)
        } else {
            p.state = PathState.Validated
            p.validatedAt = now
            paths.lastValidated = p
        }
    }
}

/**
 * [p], the active path, has an address the client was reached at, while the other address of a handshake-time rebind is still under
 * validation: having been reached proves the address, not that the client is still there (an off-path copy of a later datagram
 * carries the same proof, RFC 9000 section 9.3.3). It answers a PATH_CHALLENGE of its own too, and is settled as validated if no
 * answer comes within the period ([settleHandshakeValidated]); the first address to answer its own challenge decides.
 */
private fun ConnectionCore.confirmStillThere(p: Path) {
    startValidation(p)
    p.handshakeValidated = true
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
    if (p === paths.active) dropHandshakeCandidate()
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
 * 8.2.4 period, 3 x the larger of both PTOs, as for any path validation). This can happen after the handshake completed too: a
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
    restoreHandshakeAddress(fallback, resendAtOnce = true, reverting = true)
    dropHandshakeCandidate()
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
    reverting: Boolean = false,
) {
    handshakeFallback = null
    pendingHandshakeMove = null
    handshakeCredit = null
    val p = fallback.path
    val old = p.remote
    val k = handshakeCandidate?.takeIf { fallback.isAddress(it.remote) }
    val reached: Boolean
    if (k != null) {
        // the candidate holds this address with what came from it and was sent to it since the move, its PATH_CHALLENGEs included
        swapWithHandshakeCandidate(p, k)
        resetForNewIp(p, old)
        if (reverting) dropHandshakeCandidate() // its validation started with the move: it had the same period
        reached = fallback.addressValidated || fallback.reached || p.amplification.validated
        if (reached) p.amplification.validated = true
    } else {
        p.remote = fallback.remote
        resetForNewIp(p, old)
        reached = fallback.addressValidated || fallback.reached
        p.amplification.restore(fallback.received + fallback.receivedSince, fallback.sent, reached)
    }
    if (p.state == PathState.Validating && p.challengeDeadline > now) {
        // the candidate's challenge to this address is still outstanding: its answer validates the address; one reached before
        // settles at the deadline rather than failing (as validateHandshakeAddress)
        if (fallback.validated || reached) p.handshakeValidated = true
    } else if ((fallback.validated || reached) && handshakeCandidate != null && !reverting) {
        confirmStillThere(p)
    } else if (fallback.validated || reached) {
        clearValidation(p)
        p.state = PathState.Validated
        p.validatedAt = if (fallback.validated) fallback.validatedAt else now
        paths.lastValidated = p
    } else {
        clearValidation(p)
        p.state = PathState.Unknown // validated by the client's Handshake packet or acknowledgements from here on
        p.validatedAt = TimeMark.NEVER
    }
    // the flight went to the other address too: from here on only this one has it
    handshakeFlightTo = fallback.remote
    handshakeFlightElsewhere = false
    lastReceivedOnActivePath = now
    handshakeRestores++
    if (!resendAtOnce) return onRestored(old, fallback)
    resendInFlightAtOnce()
    onRestored(old, fallback)
}

/** No PATH_CHALLENGE of [p]'s current validation is pending, repeated or awaited any more. */
private fun clearValidation(p: Path) {
    p.forgetChallenges()
    p.challengePending = false
    p.handshakeValidated = false
    p.challengeDeadline = TimeMark.NEVER
    p.nextChallengeAt = TimeMark.NEVER
    p.challengeRetries = 0
}

/** The active address changed back to where the client is: what went to the other address goes here now, not after the PTO backoff (RFC 9002 section 6.2.4 probes). */
private fun ConnectionCore.resendInFlightAtOnce() {
    handshakeResendsAtOnceForTest++
    for (space in SpaceId.entries) {
        if (spaceDiscarded[space.ordinal] || loss.space(space).ackElicitingInFlight <= 0) continue
        if (probePending[space.ordinal] < 1) probePending[space.ordinal] = 1
        requeueForProbe(space, Int.MAX_VALUE)
    }
}

/** True for one of the two client addresses of the first handshake-time rebind: no other address becomes the candidate. */
private fun ConnectionCore.isRebindAddress(a: InetSocketAddress): Boolean {
    val from = handshakeRebindFrom ?: return false
    val to = handshakeRebindTo ?: return false
    return sameAddress(a, from) || sameAddress(a, to)
}

private fun sameAddress(
    a: InetSocketAddress,
    b: InetSocketAddress,
): Boolean = a == b || (a.port == b.port && AddressClass.ipKey(a) == AddressClass.ipKey(b))

/**
 * Server, the first handshake-time move of the connection, before the active path [p] leaves its address for [to]: the address left
 * becomes the candidate, a path of its own under validation (RFC 9000 section 9.3.3: "In response to an apparent migration, endpoints
 * MUST validate the previously active path using a PATH_CHALLENGE frame"). It takes that address's anti-amplification accounting
 * with it (section 8.1 counts per address; what arrives from the address later is credited to it) and sends nothing but 1-RTT
 * PATH_CHALLENGEs of 1200 bytes there. From then on the two addresses keep a validation each, whichever the active path has
 * ([swapWithHandshakeCandidate]); the first to answer its own challenge data decides ([adoptHandshakeCandidate], [onPathResponse]).
 * Once per connection: a later rebind follows the rules of 0.2.1 alone.
 *
 * None of quic-go, quiche, msquic and ngtcp2 has a counterpart: msquic drops packets from another address until the handshake is
 * confirmed (src/core/path.c:420-427); ngtcp2 and quic-go consider a new client address only for 1-RTT packets, so they keep
 * sending the handshake to the first one (ngtcp2 lib/ngtcp2_conn.c:9969-9985, quic-go connection.go:1249), and ngtcp2 then keeps a
 * single validation with one fallback path (lib/ngtcp2_conn.c:9037-9052).
 */
private fun ConnectionCore.openHandshakeCandidate(
    p: Path,
    to: InetSocketAddress,
) {
    if (handshakeRebindFrom != null) return
    handshakeRebindFrom = p.remote
    handshakeRebindTo = to
    val k = paths.add(p.socket, p.remote, config.congestionController(), config.newPathInitialRtt, evict = false, now = now) ?: return
    k.local = p.local
    k.handshakeCandidate = true
    k.amplification.restore(p.amplification.received, p.amplification.sent, p.amplification.validated)
    k.state = p.state
    k.validatedAt = p.validatedAt
    handshakeCandidate = k
    challengeLeftAddress(k)
}

/**
 * The candidate [k] holds the address the active path just left: a validated one is validated again (section 9.3.3, as [switchPath]
 * does for a validated previous path), a validation under way goes on. An address nothing was validated on stays as it is until the
 * active path returns there: the client could not read a 1-RTT PATH_CHALLENGE there anyway (no ServerHello reached it), and
 * challenging every address a copied datagram came from would only spend budget.
 */
private fun ConnectionCore.challengeLeftAddress(k: Path) {
    k.handshakeValidated = false
    if (k.state == PathState.Validated || (k.state != PathState.Validating && k.amplification.validated)) startValidation(k)
}

/**
 * Server, an Initial from [from] that the path does not follow (the current address sent something within a PTO), before the client
 * showed any handshake keys (no Handshake packet came from it yet): the client may have rebound before our ServerHello reached it,
 * while an off-path observer keeps the old address fresh with copies of its datagrams (RFC 9000 section 9.3.3). It cannot answer a
 * PATH_CHALLENGE there (no 1-RTT keys); only the flight itself gets it going. [from] becomes the candidate without moving the path,
 * and at every PTO of the Initial or Handshake space the flight is retransmitted there as well as to the active address, within
 * [from]'s own 3x budget (section 8.1: "MUST NOT send more than three times as many bytes as the number of bytes it has received"
 * counts per address; section 9: the client sent a non-probing packet from it). The active path does not move, so an Initial forged
 * from any address, which anyone who saw the client's first one can make (Initial keys are public), costs no more than a fresh
 * Initial would (3x what it carried) and takes nothing away from the client's own address. Once a Handshake packet shows the client
 * has its keys ([onClientHandshakeKeys]) the retransmissions stop: a candidate that got some is validated like any other (its
 * PATH_CHALLENGE answered by its own data decides after the handshake), one that got none is dropped.
 *
 * None of the references follows a client address during the handshake at all (see [openHandshakeCandidate]); they lose this
 * handshake even without an observer.
 */
private fun ConnectionCore.openHandshakeMirror(from: InetSocketAddress) {
    if (handshakeRebindFrom != null || clientHandshakeKeysSeen || state != io.kuicksilver.quic.ConnectionState.Handshaking) return
    // never a flight toward a DNS, NTP or other reflector port (RFC 9000 section 21.5.6), however its Initial claims to come from there
    if (AddressClass.isReflectivePort(from.port)) return
    val p = paths.active
    val k = paths.add(p.socket, from, config.congestionController(), config.newPathInitialRtt, evict = false, now = now) ?: return
    k.local = p.local // handshake-time moves follow the client's address only; our end stays the one its first Initial reached
    handshakeRebindFrom = p.remote
    handshakeRebindTo = from
    k.handshakeCandidate = true
    k.amplification.onReceived((handshakeCredit?.takeIf { it.from == from }?.bytes ?: 0L).toInt())
    handshakeCredit = null
    handshakeCandidate = k
    handshakeMirror = true
}

/** Server: a Handshake packet was decrypted, so the client holds handshake keys: the flight is no longer retransmitted to a second address. */
internal fun ConnectionCore.onClientHandshakeKeys() {
    clientHandshakeKeysSeen = true
    if (!handshakeMirror) return
    handshakeMirror = false
    handshakeMirrorDue = false
    val k = handshakeCandidate ?: return
    val to = handshakeRebindTo
    if (to == null || !k.isRemote(to)) return // the path moved there already: the candidate holds the other address
    if (!handshakeMirrorSent) {
        // the client got the flight where the path is: nothing came of the second address
        dropHandshakeCandidate()
        handshakeRebindFrom = null
        handshakeRebindTo = null
    } else if (k.state != PathState.Validating) {
        startValidation(k) // the client may have read the flight there: it answers a challenge of its own from there
    }
}

/**
 * The active path [p] takes the candidate [k]'s address and [k] the address [p] leaves, each with its own budget and validation
 * ([Path.swapAddressWith]). An address that is not one of the first rebind's two never becomes the candidate: it is dropped. The
 * address left is validated if it is not already being validated (section 9.3.3).
 */
private fun ConnectionCore.swapWithHandshakeCandidate(
    p: Path,
    k: Path,
) {
    p.swapAddressWith(k)
    if (isRebindAddress(k.remote)) challengeLeftAddress(k) else dropHandshakeCandidate()
}

/**
 * The candidate [k] answered its own PATH_CHALLENGE (the data matched; where the PATH_RESPONSE came from proves nothing, section
 * 8.2.3): the client is at that address now. Unless the active address already answered its own, the active path takes [k]'s
 * address, validated; nothing a handshake-time packet carries moves it again before the handshake completes, everything in flight
 * is resent there at once, and the other address is dropped. This is the fallback of section 9.3.2 taken as soon as the address
 * is known to work, rather than at the move's deadline.
 */
private fun ConnectionCore.adoptHandshakeCandidate(k: Path) {
    val p = paths.active
    if (p.state == PathState.Validated || p.id != PathId.Initial) {
        dropHandshakeCandidate()
        return
    }
    val old = p.remote
    p.swapAddressWith(k)
    resetForNewIp(p, old)
    p.amplification.validated = true
    clearValidation(p)
    p.state = PathState.Validated
    p.validatedAt = now
    paths.lastValidated = p
    handshakeFallback = null
    pendingHandshakeMove = null
    handshakeCredit = null
    handshakeMovesFrozen = true
    handshakeFlightTo = p.remote
    handshakeFlightElsewhere = false
    lastReceivedOnActivePath = now
    dropHandshakeCandidate()
    resendInFlightAtOnce()
    events += ConnectionEvent.PathValidated(p.id)
    issueNewToken(p.remote)
    onRemoteChanged?.invoke(old, p.remote)
    qlog?.metricsUpdated(stats, now)
}

/**
 * End of a packet's frames: a candidate that answered its own PATH_CHALLENGE in it is adopted ([adoptHandshakeCandidate]) unless the
 * same packet also validated the active address, which then keeps the path (its answer dropped the candidate already).
 */
internal fun ConnectionCore.finishPathResponses() {
    if (!candidateAnswered) return
    candidateAnswered = false
    val k = handshakeCandidate ?: return
    if (k.state == PathState.Validated) adoptHandshakeCandidate(k)
}

/**
 * Ends the handshake-time candidate, if any: its path is removed (no event: the application never saw it). A handshake that
 * completed while it was still open left the active address to it (confirmHandshake): one still unvalidated then counts as
 * validated by the handshake, as it would have at completion.
 */
internal fun ConnectionCore.dropHandshakeCandidate() {
    val k = handshakeCandidate ?: return
    handshakeCandidate = null
    handshakeMirror = false
    handshakeMirrorDue = false
    k.handshakeCandidate = false
    if (k.state != PathState.Closed) paths.remove(k)
    releasePathCid(k)
    val a = paths.active
    if (handshakeConfirmedAt != null && a.id == PathId.Initial && handshakeFallback?.path !== a && a.state == PathState.Unknown) {
        a.state = PathState.Validated
        a.validatedAt = now
        paths.lastValidated = a
    }
}

private fun ConnectionCore.onRestored(
    old: InetSocketAddress,
    fallback: HandshakeFallback,
) {
    onRemoteChanged?.invoke(old, fallback.remote)
    qlog?.metricsUpdated(stats, now)
}
