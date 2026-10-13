// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.tls.ResetKey
import kotlin.random.Random

/** Where an endpoint routes incoming datagrams by connection ID (EndpointCore implements it). */
@OptIn(ExperimentalKuicksilverApi::class)
internal interface CidRegistrar {
    fun add(
        cid: ConnectionId,
        core: ConnectionCore,
    )

    fun remove(cid: ConnectionId)
}

@OptIn(ExperimentalKuicksilverApi::class)
internal object NoopRegistrar : CidRegistrar {
    override fun add(
        cid: ConnectionId,
        core: ConnectionCore,
    ) {}

    override fun remove(cid: ConnectionId) {}
}

/**
 * Connection IDs in both directions (RFC 9000 section 5.1): the IDs we issued to the peer (up to min(peer limit, 8))
 * and the IDs the peer gave us (at most our `active_connection_id_limit`). Our stateless reset tokens come from the
 * endpoint's [ResetKey] (random when there is none); the peer's tokens are kept per ID and checked only for IDs we used
 * and did not retire (section 10.3.1).
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal class ConnectionIdManager(
    private val localLimit: Int,
    private val retiredCap: Int,
    private val cidLength: Int,
    private val random: Random,
    private val registrar: CidRegistrar,
    private val resetKey: ResetKey? = null,
) {
    class Local(
        val seq: Long,
        val cid: ConnectionId,
        val token: ByteArray,
    ) {
        var sent = false
        var retirePriorTo = 0L
    }

    class Peer(
        val seq: Long,
        val cid: ConnectionId,
        var token: ByteArray?,
    ) {
        var used = false

        /** Reserved by a path other than the active one (RFC 9000 section 9.5). */
        var heldByPath = false
    }

    private fun tokenFor(cid: ConnectionId): ByteArray {
        val out = ByteArray(16)
        val key = resetKey ?: return out.also { random.nextBytes(it) }
        val b = PacketBuffer.allocate(cid.length)
        try {
            cid.copyTo(b, 0)
            key.token(b, 0, cid.length, out, 0)
        } finally {
            b.close()
        }
        return out
    }

    /** The reset token of our handshake ID (the server's `stateless_reset_token`). */
    fun localToken(seq: Long): ByteArray? = local.firstOrNull { it.seq == seq }?.token

    /** The peer's `stateless_reset_token` transport parameter belongs to its sequence-0 ID. */
    fun setPeerResetToken(
        seq: Long,
        token: ByteArray,
    ) {
        peer.firstOrNull { it.seq == seq }?.token = token.copyOf()
    }

    /** True when the datagram `[0, end)` ends with the token of a peer ID we used and did not retire (RFC 9000 section 10.3.1). */
    fun matchesPeerToken(
        buf: PacketBuffer,
        end: Int,
    ): Boolean {
        var hit = false
        for (i in peer.indices) {
            val p = peer[i]
            val t =
                p.token ?: continue
            if (p.used &&
                io.kuicksilver.quic.endpoint.StatelessReset
                    .matches(buf, end, t)
            ) {
                hit = true
            }
        }
        return hit
    }

    internal fun markUsedForTest(seq: Long) {
        peer.firstOrNull { it.seq == seq }?.used = true
    }

    internal fun peerTokensForTest(): List<kotlin.Pair<ConnectionId, ByteArray?>> = peer.map { it.cid to it.token }

    private val local = ArrayList<Local>()
    private val peer = ArrayList<Peer>()

    /** The peer ID our packets carry; null falls back to the lowest sequence. */
    private var current: Peer? = null

    /** Our IDs the peer retired, still routed until their deadline (RFC 9000 section 5.1.2: packets in flight may carry them). */
    private val retiredLocal = ArrayList<Local>()
    private val retiredUntil = ArrayList<TimeMark>()
    private var nextLocalSeq = 0L
    private var target = 1
    private var retirePriorTo = 0L
    private var largestPeerSeq = -1L
    private val pendingRetire = ArrayList<Long>()
    private val unackedRetire = ArrayList<Long>()
    var core: ConnectionCore? = null
    var retiredByPeer: Int = 0
        private set

    val localCount: Int get() = local.size
    val peerCount: Int get() = peer.size

    /** The ID we used in the handshake (sequence 0), registered by whoever created the connection. */
    fun adoptInitialLocalCid(cid: ConnectionId) {
        if (local.isEmpty()) {
            local +=
                Local(0, cid, tokenFor(cid)).also {
                    it.sent = true
                    nextLocalSeq = 1
                }
        }
    }

    /** Sequence 0 of the peer: adopted from the first Initial; replaced while it is still the only one (an ACK-only Initial before the ServerHello may carry a provisional SCID, msquic). */
    fun adoptInitialPeerCid(cid: ConnectionId) {
        if (peer.isEmpty() ||
            (peer.size == 1 && peer[0].seq == 0L && peer[0].token == null)
        ) {
            peer.clear()
            val p = Peer(0, cid, null)
            peer += p
            current = p
            largestPeerSeq =
                0
        }
    }

    /** How new local IDs are made; the endpoint sets the server CID format with its routing byte, clients keep random bytes. */
    var generator: ((Random) -> ConnectionId)? = null

    private fun newLocalCid(): ConnectionId = generator?.invoke(random) ?: ConnectionId(ByteArray(cidLength).also { random.nextBytes(it) })

    /** The peer's `active_connection_id_limit`: issue IDs up to min(limit, 8) in total. */
    fun setPeerLimit(limit: Long) {
        target = minOf(limit, 8L).toInt()
        fill()
    }

    private fun fill() {
        while (local.size < target) {
            val cid = newLocalCid()
            local += Local(nextLocalSeq++, cid, tokenFor(cid))
            core?.let { registrar.add(cid, it) }
        }
    }

    /** True when [buf] holds one of our active IDs at [off]. */
    fun localMatches(
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): Boolean {
        for (i in 0 until local.size) if (local[i].cid.contentEquals(buf, off, len)) return true
        for (i in 0 until
            retiredLocal.size) {
            if (retiredLocal[i].cid.contentEquals(buf, off, len)) return true
        }
        return false
    } // indexed: no iterator per packet (allocation gate)

    /** The highest retire_prior_to we sent: a lost NEW_CONNECTION_ID below it is not retransmitted (RFC 9000 section 19.15). */
    private var issuedRetirePriorTo = 0L

    /** Issues one more ID that asks the peer to retire every earlier one (test hook for retire_prior_to). */
    fun issueRetiringOlder() {
        val cid = newLocalCid()
        val l = Local(nextLocalSeq++, cid, tokenFor(cid))
        l.retirePriorTo = l.seq
        if (l.seq > issuedRetirePriorTo) issuedRetirePriorTo = l.seq
        local +=
            l
        core?.let { registrar.add(cid, it) }
    }

    /** Test hook: NEW_CONNECTION_ID frames wait while set (a peer that issues its IDs late, or whose frames are delayed). */
    var holdNewCidsForTest = false

    /** NEW_CONNECTION_ID frames not yet sent. */
    fun nextNewCidToSend(): Local? {
        if (holdNewCidsForTest) return null
        for (i in local.indices) if (!local[i].sent) return local[i]
        return null
    }

    /**
     * NEW_CONNECTION_ID for [seq] was lost: it is sent again unless we have since asked the peer to retire it (RFC 9000 section 5.1.2).
     * Such an ID may never reach the peer, which then never retires it: it keeps routing until [dropAt] (3 x PTO, in case the frame
     * arrived after all) and then leaves the registry like an ID the peer retired.
     */
    fun onNewCidLost(
        seq: Long,
        dropAt: TimeMark,
    ) {
        val i = local.indexOfFirst { it.seq == seq }
        if (i < 0) return
        if (seq >= issuedRetirePriorTo) {
            local[i].sent = false
            return
        }
        retiredLocal += local.removeAt(i)
        retiredUntil += dropAt
        fill()
    }

    fun hasPendingFrames(): Boolean {
        if (pendingRetire.isNotEmpty()) return true
        if (holdNewCidsForTest) return false
        for (i in local.indices) if (!local[i].sent) return true
        return false
    }

    /** The peer retired our ID [seq]: it keeps routing until [until] (3 x PTO), then leaves the registry; a replacement is issued at once. */
    fun onPeerRetired(
        seq: Long,
        until: TimeMark,
    ): Boolean {
        if (seq >=
            nextLocalSeq
        ) {
            throw QuicWireException(TransportError.PROTOCOL_VIOLATION, 0x19, "RETIRE_CONNECTION_ID for an unissued sequence")
        }
        val i = local.indexOfFirst { it.seq == seq }
        if (i < 0) {
            // still in its grace period: a retransmission, or an ID we dropped after its NEW_CONNECTION_ID was declared lost
            for (k in 0 until retiredLocal.size) if (retiredLocal[k].seq == seq) return true
            return false // already gone: nothing to do (a glitch)
        }
        retiredLocal += local.removeAt(i)
        retiredUntil += until
        retiredByPeer++
        fill()
        return true
    }

    /** Earliest deadline of a retired ID, or NEVER. */
    fun nextRetiredExpiry(): TimeMark {
        var t = TimeMark.NEVER
        for (i in retiredUntil.indices) {
            if (retiredUntil[i] <
                t
            ) {
                t = retiredUntil[i]
            }
        }
        return t
    }

    /** Drops retired IDs whose grace period passed. */
    fun expireRetired(now: TimeMark) {
        var i = 0
        while (i <
            retiredLocal.size
        ) {
            if (retiredUntil[i] <=
                now
            ) {
                registrar.remove(retiredLocal[i].cid)
                retiredLocal.removeAt(i)
                retiredUntil.removeAt(i)
            } else {
                i++
            }
        }
    }

    /** Moves our packets to an unused peer ID (RFC 9000 section 9.5); the one in use is retired, or with [retireOld] false left to the caller (a path that keeps probing with it). False when the peer gave us no spare. */
    fun rotatePeerCid(retireOld: Boolean = true): Boolean {
        val old = current ?: return false
        val next = unusedPeer() ?: return false
        if (retireOld) {
            peer.remove(old)
            queueRetire(old.seq)
        }
        current = next
        next.used = true
        return true
    }

    private fun unusedPeer(): Peer? {
        var next: Peer? = null
        for (i in peer.indices) {
            val p = peer[i]
            if (p !== current && !p.used &&
                (next == null || p.seq < next.seq)
            ) {
                next = p
            }
        }
        return next
    }

    /** True when the peer gave us an ID no path used yet: a new path can be probed without linking it to another (RFC 9000 section 9.5). */
    fun hasSparePeer(): Boolean = unusedPeer() != null

    /** The peer ID our packets on the active path carry. */
    val currentPeer: Peer? get() = current

    /** An unused peer ID reserved for a path other than the active one (RFC 9000 section 9.5); null when the peer gave us no spare. */
    fun takePathPeer(): Peer? {
        val p = unusedPeer() ?: return null
        p.used = true
        p.heldByPath = true
        return p
    }

    /** True while [p] is one of the peer's active IDs (a retire_prior_to may have removed it). */
    fun isActive(p: Peer): Boolean {
        for (i in peer.indices) if (peer[i] === p) return true
        return false
    }

    /** The path that held [p] became the active one: our packets carry it from now on. */
    fun makeCurrent(p: Peer) {
        p.heldByPath = false
        p.used = true
        current = p
    }

    /** A path no longer needs [p]: it is retired (never the current one). Never throws: with the retirement backlog full the ID just stays unused (it is marked used). */
    fun releasePathPeer(p: Peer) {
        p.heldByPath = false
        if (p === current || !isActive(p) || pendingRetire.size + unackedRetire.size + 1 > retiredCap) return
        peer.remove(p)
        pendingRetire += p.seq
    }

    /** True when the frame was a repeat of a known sequence number (a glitch when it is not a retransmission). */
    fun onNewConnectionId(
        seq: Long,
        retire: Long,
        buf: PacketBuffer,
        off: Int,
        len: Int,
        tokenOff: Int,
    ): Boolean {
        val existing = peer.firstOrNull { it.seq == seq }
        if (existing !=
            null
        ) {
            if (!existing.cid.contentEquals(
                    buf,
                    off,
                    len,
                )
            ) {
                throw QuicWireException(TransportError.PROTOCOL_VIOLATION, 0x18, "NEW_CONNECTION_ID reuses a sequence number")
            }
            return true
        }
        if (seq <= largestPeerSeq && seq < retirePriorTo) {
            queueRetire(seq)
            return false
        } // already retired by a later frame
        if (retire > retirePriorTo) {
            retirePriorTo = retire
            val it = peer.iterator()
            while (it.hasNext()) {
                val p = it.next()
                if (p.seq < retire) {
                    it.remove()
                    queueRetire(p.seq)
                }
            }
        }
        if (seq < retirePriorTo) {
            queueRetire(seq)
            return false
        }
        if (peer.size + 1 >
            localLimit
        ) {
            throw QuicWireException(TransportError.CONNECTION_ID_LIMIT_ERROR, 0x18, "more than $localLimit active connection IDs")
        }
        peer +=
            Peer(
                seq,
                ConnectionId(ByteArray(len).also { buf.copyTo(it, off, 0, len) }),
                ByteArray(16).also { buf.copyTo(it, tokenOff, 0, 16) },
            )
        if (seq >
            largestPeerSeq
        ) {
            largestPeerSeq = seq
        }
        return false
    }

    private fun queueRetire(seq: Long) {
        if (pendingRetire.size + unackedRetire.size + 1 >
            retiredCap
        ) {
            throw QuicWireException(TransportError.CONNECTION_ID_LIMIT_ERROR, 0x18, "more than $retiredCap retirements outstanding")
        }
        pendingRetire += seq
    }

    /** RETIRE_CONNECTION_ID frames to send now (they move to the unacknowledged set). */
    fun takeRetireFrames(): List<Long> {
        val l = pendingRetire.toList()
        unackedRetire += l
        pendingRetire.clear()
        return l
    }

    fun onRetireAcked(seq: Long) {
        unackedRetire.remove(seq)
    }

    fun onRetireLost(seq: Long) {
        if (unackedRetire.remove(seq)) pendingRetire += seq
    }

    internal fun localForTest(seq: Long) = local.firstOrNull { it.seq == seq }

    /** The peer ID to put in our packets: the lowest active one. */
    fun activePeerCid(): ConnectionId {
        current?.let {
            if (isActive(it)) {
                it.used = true
                return it.cid
            }
        }
        var best: Peer? = null
        for (i in peer.indices) {
            val p = peer[i]
            if (best == null || (best.heldByPath && !p.heldByPath) ||
                (best.heldByPath == p.heldByPath && p.seq < best.seq)
            ) {
                best = p
            }
        } // not one a probing path holds, when there is a choice
        best?.let {
            it.used = true
            it.heldByPath = false
        }
        current = best
        return best?.cid ?: ConnectionId.EMPTY
    }
}
