// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.CongestionController
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.recovery.Pacer
import io.kuicksilver.quic.recovery.RttEstimator
import kotlin.time.Duration

/**
 * One network path of a connection (RFC 9000 section 9): the peer address as seen from a local socket, with
 * its own congestion controller, RTT estimator, pacer, anti-amplification budget, MTU and validation state.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal class Path(
    val id: PathId,
    remote: InetSocketAddress,
    val socket: PathId,
    var cc: CongestionController,
    initialRtt: Duration,
) {
    /** The peer's address; its IP key is kept beside it because a host name and its IP literal must count as one address (Kotlin/Native compares the strings). */
    var remote: InetSocketAddress = remote
        set(value) {
            field = value
            remoteKey = AddressClass.ipKey(value)
            addressEpoch++
        }

    /** Counts changes of [remote]: a packet sent in this epoch went to the current address ([io.kuicksilver.quic.recovery.SentPacket.addressEpoch]). */
    var addressEpoch: Int = 0
        private set
    var remoteKey: AddressClass.IpKey = AddressClass.ipKey(remote)
        private set

    /** True when [a] is this path's peer: equal as ktor sees it, or the same port and the same IP once host names are resolved. */
    fun isRemote(a: InetSocketAddress): Boolean = remote == a || (remote.port == a.port && remoteKey == AddressClass.ipKey(a))

    /**
     * Server: our address on this path, the one the client sent to, learned from the datagram that opened the path on a wildcard
     * socket that reports destinations ([io.kuicksilver.quic.PacketBatch.localAddress]); every datagram of the path leaves from it,
     * so a reply on a multi-address host or a VIP comes from the address the client knows. Fixed when the path is made, as
     * quinn-proto's `FourTuple::local_ip` and quic-go's `sendConn` packet info: only a client migrates (RFC 9000 section 9), so a
     * datagram from the path's client address that reached another of our addresses (the client's own, or an attacker's copy) is
     * processed on this path and changes nothing here. Null where the socket cannot tell (the portable sockets, a specific bind) and
     * on a client, whose source the kernel picks (quinn-proto's `local_ip` is `None` for clients).
     */
    var local: InetSocketAddress? = null

    var state: PathState = PathState.Unknown
    val amplification = AmplificationLimit()

    /** Datagram size in use; 1200 until PMTUD raises it. */
    var mtu: Int = 1200

    /** Client: the path to the server's preferred address (RFC 9000 section 9.6), switched to once validated. */
    var preferred: Boolean = false

    /**
     * Server: this path is the handshake-time candidate (see `ConnectionCore.onHandshakeAddressChange`): the client address of a
     * handshake-time rebind that the active path does not have at the moment, validated on its own (RFC 9000 sections 8.2 and 9.3.3).
     * It sends nothing but PATH_CHALLENGE (and PATH_RESPONSE) to that address, with the active path's connection ID, and is never
     * reported to the application.
     */
    var handshakeCandidate: Boolean = false

    /** Server: the client's non-probing packets arrived on this preferred-socket path before its validation finished (RFC 9000 section 9.6.1). */
    var preferredMovePending: Boolean = false

    /** The largest packet sent on this path: a Packet Too Big that claims a smaller one was too large is about another path, or forged. */
    var largestSent: Int = 0
    var rtt: RttEstimator = RttEstimator(initialRtt)
    var pacer: Pacer = Pacer()

    /** The data of the latest PATH_CHALLENGE sent in this validation (0 before the first). */
    var challenge: Long = 0
        private set

    /** The last [SENT_CHALLENGES] challenges of this validation: a PATH_RESPONSE to any of them validates (as quic-go). */
    private val sentChallenges = LongArray(SENT_CHALLENGES)
    private val sentUndersized = BooleanArray(SENT_CHALLENGES)
    private var sentChallengeCount = 0

    /** Records [data] as the next PATH_CHALLENGE of this validation (RFC 9000 section 13.3: a different payload each time). */
    fun onChallengeSent(data: Long) {
        challenge = data
        sentChallenges[sentChallengeCount % SENT_CHALLENGES] = data
        sentUndersized[sentChallengeCount % SENT_CHALLENGES] = false
        sentChallengeCount++
    }

    /** The last challenge went out in a datagram below 1200 bytes (the anti-amplification limit, RFC 9000 section 8.2.1). */
    fun markLastChallengeUndersized() {
        if (sentChallengeCount > 0) sentUndersized[(sentChallengeCount - 1) % SENT_CHALLENGES] = true
    }

    /** True when [data] answers one of the recent challenges of this validation. */
    fun answers(data: Long): Boolean = indexOf(data) >= 0

    /** True when [data] answers a challenge that was sent in a datagram below 1200 bytes. */
    fun answeredUndersized(data: Long): Boolean {
        val i = indexOf(data)
        return i >= 0 && sentUndersized[i]
    }

    private fun indexOf(data: Long): Int {
        for (i in 0 until minOf(sentChallengeCount, SENT_CHALLENGES)) if (sentChallenges[i] == data) return i
        return -1
    }

    /** A new validation: earlier challenges no longer count (RFC 9000 section 8.2.3 ties a response to its own validation). */
    fun forgetChallenges() {
        challenge = 0
        sentChallengeCount = 0
    }

    /** When the latest PATH_CHALLENGE went out on this path (any validation); [TimeMark.NEVER] before the first. */
    var lastChallengeAt: TimeMark = TimeMark.NEVER

    /** A validation of this path asked for less than a PTO after its latest PATH_CHALLENGE starts at this time (`revalidatePreviousPath`). */
    var revalidateAt: TimeMark = TimeMark.NEVER

    /** A PATH_CHALLENGE must go out on this path at the next poll. */
    var challengePending: Boolean = false

    /** Validation gives up at this time (RFC 9000 section 8.2.4: 3 x the larger of the PTO and a new path's PTO). */
    var challengeDeadline: TimeMark = TimeMark.NEVER

    /** The next PATH_CHALLENGE repeat while validating: one PTO after the first, then doubling (RFC 9002 section 6.2.1 applied to probes). */
    var nextChallengeAt: TimeMark = TimeMark.NEVER

    /** PATH_CHALLENGE repeats sent in the current validation; the gap before the next one is PTO x 2^min(retries, 6). */
    var challengeRetries: Int = 0

    /** When a packet from the peer last arrived on this path (its creation for a path we opened); the oldest is evicted first. */
    var lastReceivedAt: TimeMark = TimeMark.NEVER

    /** After a failed validation the path is not probed again before this time. */
    var standbyUntil: TimeMark = TimeMark.NEVER

    /** When validation last succeeded; the latest validated path is the fallback (RFC 9000 section 9.3.2). */
    var validatedAt: TimeMark = TimeMark.NEVER

    /** What the socket of this path can do (ECN marking, GSO...). */
    var caps: io.kuicksilver.quic.IoCapabilities = io.kuicksilver.quic.IoCapabilities.Portable

    /** ECN validation of this path (RFC 9000 section 13.4.2); every new path validates afresh. */
    val ecn = EcnValidator()

    /** DPLPMTUD of this path; null without `df` on the socket or with `QuicConfig.pmtud = false` (then the MTU stays 1200). */
    var pmtud: Pmtud? = null
    var ecnFailureReported: Boolean = false

    /** The address was validated by a client Handshake packet (RFC 9000 section 8.1) while a PATH_CHALLENGE sent during the handshake is still unanswered: its deadline settles the path instead of failing it. */
    var handshakeValidated: Boolean = false

    /**
     * A client path under validation that has no peer connection ID of its own and found none spare (RFC 9000 section 9.5): no
     * PATH_CHALLENGE goes out, and [challengeDeadline] is when the wait for a NEW_CONNECTION_ID gives up.
     */
    var awaitingCid: Boolean = false

    /**
     * Server: the client's packets on this path carry another of our IDs than those on the active path, a deliberate migration (RFC
     * 9000 section 9.5): our current ID must not follow it there.
     */
    var peerChangedDcid: Boolean = false

    /** Server: the client probed this path (a PATH_CHALLENGE from it while another path was active), typically to migrate there. */
    var peerProbed: Boolean = false

    /** The peer connection ID this path's packets carry while it is not the active path (RFC 9000 section 9.5: never the active path's); null until it first sends. */
    var peerCid: ConnectionIdManager.Peer? = null

    /** Takes [from]'s congestion state and leaves [from] with [fresh]: probes to the old address never sit on the new path's window. */
    fun inheritFrom(
        from: Path,
        fresh: CongestionController,
    ) {
        cc = from.cc
        rtt = from.rtt
        pacer = from.pacer
        mtu = from.mtu
        from.cc =
            fresh
        from.pacer = Pacer()
    }

    /**
     * Exchanges the peer address with [other], together with everything bound to that address rather than to the path: its
     * anti-amplification accounting (RFC 9000 section 8.1 counts per address), its validation (state, challenges sent and their
     * schedule and pace, section 8.2) and when it was validated. Congestion state, RTT, MTU, DPLPMTUD, ECN and connection IDs stay
     * with the path; the caller starts them over when the active path's IP changes (`ConnectionCore.resetForNewIp`, section 9.4). Used
     * by a handshake-time rebind between the active path and the candidate: each address keeps its own validation.
     */
    fun swapAddressWith(other: Path) {
        val r = remote
        remote = other.remote
        other.remote = r
        val received = amplification.received
        val sent = amplification.sent
        val validated = amplification.validated
        amplification.restore(other.amplification.received, other.amplification.sent, other.amplification.validated)
        other.amplification.restore(received, sent, validated)
        val st = state
        state = other.state
        other.state = st
        val at = validatedAt
        validatedAt = other.validatedAt
        other.validatedAt = at
        val hv = handshakeValidated
        handshakeValidated = other.handshakeValidated
        other.handshakeValidated = hv
        val c = challenge
        challenge = other.challenge
        other.challenge = c
        for (i in 0 until SENT_CHALLENGES) {
            val d = sentChallenges[i]
            sentChallenges[i] = other.sentChallenges[i]
            other.sentChallenges[i] = d
            val u = sentUndersized[i]
            sentUndersized[i] = other.sentUndersized[i]
            other.sentUndersized[i] = u
        }
        val n = sentChallengeCount
        sentChallengeCount = other.sentChallengeCount
        other.sentChallengeCount = n
        val pending = challengePending
        challengePending = other.challengePending
        other.challengePending = pending
        val deadline = challengeDeadline
        challengeDeadline = other.challengeDeadline
        other.challengeDeadline = deadline
        val next = nextChallengeAt
        nextChallengeAt = other.nextChallengeAt
        other.nextChallengeAt = next
        val retries = challengeRetries
        challengeRetries = other.challengeRetries
        other.challengeRetries = retries
        val lastAt = lastChallengeAt
        lastChallengeAt = other.lastChallengeAt
        other.lastChallengeAt = lastAt
        val revalidate = revalidateAt
        revalidateAt = other.revalidateAt
        other.revalidateAt = revalidate
    }

    override fun toString(): String = "Path(${id.value}, $remote, $state)"

    private companion object {
        const val SENT_CHALLENGES = 8
    }
}

/** The paths of a connection: at most [maxPaths], one active; the queue of PATH_RESPONSEs to send (at most 3). */
@OptIn(ExperimentalKuicksilverApi::class)
internal class Paths(
    first: Path,
    private val maxPaths: Int = 4,
) {
    val all = ArrayList<Path>(2).also { it += first }
    var active: Path = first

    /** The most recent path that passed validation, to fall back to (RFC 9000 section 9.3.2). */
    var lastValidated: Path = first
    private var nextId = 1

    /** Path ids below this were issued (and those not in [all] since closed or evicted); ids are never reused. */
    val issuedIds: Int get() = nextId

    /**
     * PATH_RESPONSEs owed, in arrival order (RFC 9000 section 8.2.2: "MUST respond by echoing the data contained in the PATH_CHALLENGE
     * frame in a PATH_RESPONSE frame"): every challenge is queued and answered once. [responseFrom] is the local address the challenge
     * reached when that is not its path's own (a server on a wildcard socket with several addresses), null for the path's: the response
     * "MUST be sent on the network path where the PATH_CHALLENGE was received", so such a one leaves from that address. The queue is
     * drained by every poll; past [FREE_RESPONSES] waiting each challenge costs a glitch token, and at [MAX_RESPONSES] the connection
     * closes (ConnectionCore.onPathChallenge), so a flood ends the connection rather than going unanswered or growing memory.
     */
    var responseData = LongArray(4)
    var responsePath = arrayOfNulls<Path>(4)
    var responseFrom = arrayOfNulls<InetSocketAddress>(4)
    var responses = 0

    /** Told about a path dropped to make room for a new one (the core retires its peer connection ID). */
    var onEvicted: ((Path) -> Unit)? = null

    fun byRemote(
        socket: PathId,
        a: InetSocketAddress,
    ): Path? {
        for (i in 0 until all.size) {
            val p = all[i]
            if (p.socket == socket &&
                p.isRemote(a)
            ) {
                return p
            }
        }
        return null
    }

    fun byId(id: PathId): Path? {
        for (i in 0 until all.size) if (all[i].id == id) return all[i]
        return null
    }

    /**
     * A new path for [remote]; null when four paths exist and none of them can be dropped. The active and the last validated path
     * always stay; a path neither validating nor active goes first, then the validating path heard from longest ago, provided nothing
     * arrived on it since [abandonValidatingHeardBefore] (null: validating paths stay) — RFC 9000 section 8.2.4 lets a migration
     * abandon the validation of an older path.
     */
    fun add(
        socket: PathId?,
        remote: InetSocketAddress,
        cc: CongestionController,
        initialRtt: Duration,
        evict: Boolean = true,
        now: TimeMark = TimeMark.NEVER,
        abandonValidatingHeardBefore: TimeMark? = null,
    ): Path? {
        if (all.size >=
            maxPaths
        ) {
            if (!evict) return null
            val victim = victim(abandonValidatingHeardBefore) ?: return null
            remove(victim)
            onEvicted?.invoke(victim)
        } // remove(): its queued PATH_RESPONSEs go too
        val id = PathId(nextId++)
        val p = Path(id, remote, socket ?: id, cc, initialRtt)
        p.lastReceivedAt = now
        all += p
        return p
    }

    private fun victim(abandonValidatingHeardBefore: TimeMark?): Path? {
        var best: Path? = null
        for (i in 0 until all.size) {
            val p = all[i]
            if (p === active || p === lastValidated) continue
            if (p.state != PathState.Validating) return p
            if (abandonValidatingHeardBefore != null &&
                p.lastReceivedAt < abandonValidatingHeardBefore &&
                (best == null || p.lastReceivedAt < best.lastReceivedAt)
            ) {
                best = p
            }
        }
        return best
    }

    /** The most recently validated path other than [except], if any. */
    fun fallback(except: Path): Path? {
        var best: Path? = null
        for (i in 0 until all.size) {
            val p = all[i]
            if (p !== except &&
                p.state == PathState.Validated &&
                (best == null || p.validatedAt > best.validatedAt)
            ) {
                best = p
            }
        }
        return best
    }

    fun remove(p: Path) {
        all.remove(p)
        p.state = PathState.Closed
        dropResponses { it === p }
    }

    /** Removes the queued responses whose path [drop] selects. */
    private inline fun dropResponses(drop: (Path) -> Boolean) {
        var w = 0
        for (i in 0 until responses) {
            if (drop(responsePath[i]!!)) continue
            responseData[w] = responseData[i]
            responsePath[w] = responsePath[i]
            responseFrom[w] = responseFrom[i]
            w++
        }
        for (i in w until responses) {
            responsePath[i] = null
            responseFrom[i] = null
        }
        responses = w
    }

    /**
     * Queues a PATH_RESPONSE for [path], to leave from [from] (null: the path's own local address); false when [MAX_RESPONSES]
     * are already waiting (the caller closes the connection).
     */
    fun queueResponse(
        data: Long,
        path: Path,
        from: InetSocketAddress? = null,
    ): Boolean {
        if (responses >= MAX_RESPONSES) return false
        if (responses == responseData.size) {
            val n = minOf(responses * 2, MAX_RESPONSES)
            responseData = responseData.copyOf(n)
            responsePath = responsePath.copyOf(n)
            responseFrom = responseFrom.copyOf(n)
        }
        responseData[responses] = data
        responsePath[responses] = path
        responseFrom[responses] = from
        responses++
        return true
    }

    /** A response waits for [path] from its own local address. */
    fun hasResponseFor(path: Path): Boolean {
        for (i in 0 until responses) if (responsePath[i] === path && responseFrom[i] == null) return true
        return false
    }

    /** Removes and returns the first queued response for [path] from its own local address, or null. */
    fun takeResponseFor(path: Path): Long? = take(path, null)

    /** Removes and returns the first queued response for [path] owed from the local address [from], or null. */
    fun takeResponseFrom(
        path: Path,
        from: InetSocketAddress,
    ): Long? = take(path, from)

    private fun take(
        path: Path,
        from: InetSocketAddress?,
    ): Long? {
        for (i in 0 until responses) {
            if (responsePath[i] === path && responseFrom[i] == from) {
                val d = responseData[i]
                for (k in i until responses - 1) {
                    responseData[k] = responseData[k + 1]
                    responsePath[k] = responsePath[k + 1]
                    responseFrom[k] = responseFrom[k + 1]
                }
                responses--
                responsePath[responses] = null
                responseFrom[responses] = null
                return d
            }
        }
        return null
    }

    /** The index of the first response owed from another local address than its path's ([responseFrom] set), or -1. */
    fun nextStrayResponse(): Int {
        for (i in 0 until responses) if (responseFrom[i] != null) return i
        return -1
    }

    /** Drops the responses owed to [path] from [from] (none can be sent: no budget, no connection ID, no room). */
    fun dropResponsesFrom(
        path: Path,
        from: InetSocketAddress,
    ) {
        while (take(path, from) != null) {}
    }

    /** The next path owed a probe datagram of its own; the active path comes first when its PATH_CHALLENGE is pending, so the first datagram on a rebound path is the probe and not a coalesced flight or a PMTU probe (RFC 9000 section 9.1). */
    fun nextProbe(): Path? {
        if (active.challengePending) return active
        for (i in 0 until all.size) {
            val p = all[i]
            if (p !== active &&
                (p.challengePending || hasResponseFor(p))
            ) {
                return p
            }
        }
        return null
    }

    internal companion object {
        /** Responses that may wait at once before each further PATH_CHALLENGE costs a glitch token. */
        const val FREE_RESPONSES = 3

        /** Responses that may wait at once at all (with glitch protection off as well): the next challenge closes the connection. */
        const val MAX_RESPONSES = 1024
    }
}
