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
        }
    var remoteKey: AddressClass.IpKey = AddressClass.ipKey(remote)
        private set

    /** True when [a] is this path's peer: equal as ktor sees it, or the same port and the same IP once host names are resolved. */
    fun isRemote(a: InetSocketAddress): Boolean = remote == a || (remote.port == a.port && remoteKey == AddressClass.ipKey(a))

    var state: PathState = PathState.Unknown
    val amplification = AmplificationLimit()

    /** Datagram size in use; 1200 until PMTUD raises it. */
    var mtu: Int = 1200
    var rtt: RttEstimator = RttEstimator(initialRtt)
    var pacer: Pacer = Pacer()

    /** The PATH_CHALLENGE data in flight, when [challengePending] or [state] is Validating. */
    var challenge: Long = 0

    /** A PATH_CHALLENGE must go out on this path at the next poll. */
    var challengePending: Boolean = false

    /** Validation gives up at this time (RFC 9000 section 8.2.4: max(3 x PTO, 6 x initial RTT)). */
    var challengeDeadline: TimeMark = TimeMark.NEVER

    /** The next PATH_CHALLENGE repeat while validating: one PTO after the first, then doubling (RFC 9002 section 6.2.1 applied to probes). */
    var nextChallengeAt: TimeMark = TimeMark.NEVER

    /** PATH_CHALLENGE repeats sent in the current validation; the gap before the next one is PTO x 2^min(retries, 6). */
    var challengeRetries: Int = 0

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

    override fun toString(): String = "Path(${id.value}, $remote, $state)"
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
    val responseData = LongArray(3)
    val responsePath = arrayOfNulls<Path>(3)
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

    /** A new path for [remote]; null when four paths exist and none of them can be dropped (the active and the last validated stay). */
    fun add(
        socket: PathId?,
        remote: InetSocketAddress,
        cc: CongestionController,
        initialRtt: Duration,
        evict: Boolean = true,
    ): Path? {
        if (all.size >=
            maxPaths
        ) {
            if (!evict) return null
            val victim =
                all.firstOrNull { it !== active && it !== lastValidated && it.state != PathState.Validating } ?: return null
            remove(victim)
            onEvicted?.invoke(victim)
        } // remove(): its queued PATH_RESPONSEs go too
        val id = PathId(nextId++)
        val p = Path(id, remote, socket ?: id, cc, initialRtt)
        all += p
        return p
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
        var i = 0
        while (i <
            responses
        ) {
            if (responsePath[i] ===
                p
            ) {
                for (k in i until responses - 1) {
                    responseData[k] = responseData[k + 1]
                    responsePath[k] = responsePath[k + 1]
                }
                responses--
                responsePath[responses] =
                    null
            } else {
                i++
            }
        }
    }

    /** Queues a PATH_RESPONSE for [path]; false when three are already waiting (the caller spends a glitch token). */
    fun queueResponse(
        data: Long,
        path: Path,
    ): Boolean {
        if (responses >=
            responseData.size
        ) {
            return false
        }
        responseData[responses] = data
        responsePath[responses] = path
        responses++
        return true
    }

    fun hasResponseFor(path: Path): Boolean {
        for (i in 0 until responses) if (responsePath[i] === path) return true
        return false
    }

    /** Removes and returns the first queued response for [path], or null. */
    fun takeResponseFor(path: Path): Long? {
        for (i in 0 until responses) {
            if (responsePath[i] ===
                path
            ) {
                val d = responseData[i]
                for (k in i until responses - 1) {
                    responseData[k] = responseData[k + 1]
                    responsePath[k] =
                        responsePath[k + 1]
                }
                responses--
                responsePath[responses] = null
                return d
            }
        }
        return null
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
}
