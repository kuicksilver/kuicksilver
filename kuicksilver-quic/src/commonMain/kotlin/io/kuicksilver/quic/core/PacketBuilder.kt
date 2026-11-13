// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.crypto.PacketProtection
import io.kuicksilver.quic.recordForTest
import io.kuicksilver.quic.recovery.SentFrames
import io.kuicksilver.quic.recovery.SpaceId
import io.kuicksilver.quic.stream.ControlKind
import io.kuicksilver.quic.stream.SendRange
import io.kuicksilver.quic.wire.FrameEncoder
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketNumbers
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.VarInt
import io.kuicksilver.quic.wire.WireWriter
import io.kuicksilver.tls.PacketProtector
import io.kuicksilver.tls.TlsRole

/** Assembles datagrams: one packet per space with keys, coalesced, padded and protected in place (RFC 9000 sections 12–14). */
@OptIn(ExperimentalKuicksilverApi::class)
internal class PacketBuilder(
    private val c: ConnectionCore,
) {
    var pacerWakeup: TimeMark = TimeMark.NEVER

    /**
     * The last poll left nothing to send on the active path (no data, flow control holds it, or no keys to send it with yet):
     * with room in the window, the window is under-used (RFC 9002 section 7.8). False when a poll stopped with data left, for the window, the pacer, the send
     * quantum or a full batch: the sender "would have fully utilized the congestion window without pacing delay".
     */
    var appLimited: Boolean = true
    private var writer: WireWriter? = null
    private val mask = ByteArray(5)
    private val range = SendRange()
    private val scratch = ByteArray(2048)
    private var congested = false

    /** Set while a probe datagram for a path other than the active one is built: only PATH_CHALLENGE/PATH_RESPONSE and padding go in (RFC 9000 section 9.1). */
    private var probeTarget: Path? = null

    /** With [probeTarget]: the packet carries only the responses owed from this other local address (Paths.responseFrom). */
    private var strayFrom: io.ktor.network.sockets.InetSocketAddress? = null

    /** The ECN codepoint of the datagram being built (per path validation state). */
    private var currentMark: io.kuicksilver.quic.Ecn = io.kuicksilver.quic.Ecn.NotEct

    /**
     * Set while a datagram below 1200 bytes is built (a server's anti-amplification budget): its Initial packet may carry an ACK
     * but nothing ack-eliciting, since a datagram with an ack-eliciting Initial must reach 1200 bytes (RFC 9000 section 14.1) and
     * the server must not send more than the budget (section 8.1). CRYPTO and PTO probes of the Initial space wait for budget.
     */
    private var initialAckOnly = false

    /**
     * Set while a DPLPMTUD probe is built: a 1-RTT packet of PING and padding. It counts in flight and waits for room in the
     * window and for the pacer ("PMTU probes consume congestion window", RFC 9000 section 14.4; RFC 9002 section 7); only its
     * loss is no congestion signal.
     */
    private var pmtuProbe = false

    fun poll(
        out: PacketBatch,
        now: TimeMark,
    ): Int {
        var count = 0
        var bytes = 0
        pacerWakeup = TimeMark.NEVER
        // probes of other paths first: a PATH_CHALLENGE or PATH_RESPONSE must go to its own address (RFC 9000 section 8.2)
        if (c.writeKeys[3] != null && c.closeFrame == null) {
            // a PATH_RESPONSE "MUST be sent on the network path where the PATH_CHALLENGE was received" (section 8.2.2): one that reached
            // another of our addresses than its path's leaves from that address, in a datagram of its own
            while (count < out.capacity) {
                val i = c.paths.nextStrayResponse()
                if (i < 0) break
                val target = c.paths.responsePath[i]!!
                val from = c.paths.responseFrom[i]!!
                var limit = minOf(out.segmentSize, target.mtu)
                if (!target.amplification.validated) {
                    val budget = target.amplification.budget()
                    if (budget < 64) {
                        c.paths.dropResponsesFrom(target, from)
                        continue
                    }
                    limit = minOf(limit.toLong(), budget).toInt()
                }
                // section 9.5: "MUST NOT reuse a connection ID when sending from more than one local address": a peer ID no path
                // used, retired after this datagram; with none to spare, or no room to retire it, the responses are dropped
                val peer = if (c.cids.canRetireOneMore()) c.cids.takePathPeer() else null
                if (peer == null) {
                    c.paths.dropResponsesFrom(target, from)
                    continue
                }
                val dcid = peer.cid
                probeTarget = target
                strayFrom = from
                currentMark = target.ecn.markFor()
                val n =
                    try {
                        buildPacket(out.buffer(count), 0, limit, SpaceId.Application, now, padToEnd = true, target = target, dcid = dcid)
                    } finally {
                        probeTarget = null
                        strayFrom = null
                        c.cids.releasePathPeer(peer)
                    }
                if (pnExhausted) return exhausted(count)
                if (n == 0) {
                    c.paths.dropResponsesFrom(target, from)
                    continue
                }
                out.setLength(count, n)
                out.setAddress(count, target.remote)
                out.setPath(count, target.socket)
                out.setLocalAddress(count, from)
                out.setEcn(count, currentMark)
                count++
                bytes += n
                c.bytesSent += n
                target.amplification.onSent(n)
            }
            while (count < out.capacity) {
                val target = c.paths.nextProbe() ?: break
                var limit = minOf(out.segmentSize, target.mtu)
                if (!target.amplification.validated) {
                    val budget = target.amplification.budget()
                    if (budget <
                        64
                    ) {
                        target.challengePending = false
                        while (c.paths.takeResponseFor(target) !=
                            null
                        ) {}
                        continue
                    }
                    limit = minOf(limit.toLong(), budget).toInt()
                }
                val dcid = c.dcidFor(target)
                if (dcid == null) {
                    target.challengePending = false
                    while (c.paths.takeResponseFor(target) != null) {}
                    // no unused peer ID for this path: sending would link it to the active one (RFC 9000 section 9.5); a client probe
                    // waits for a NEW_CONNECTION_ID
                    if (c.role == TlsRole.Client && target.state == PathState.Validating) c.awaitPeerCid(target)
                    continue
                }
                probeTarget = target
                currentMark = target.ecn.markFor()
                val n =
                    try {
                        buildPacket(out.buffer(count), 0, limit, SpaceId.Application, now, padToEnd = true, target = target, dcid = dcid)
                    } finally {
                        probeTarget =
                            null
                    }
                if (pnExhausted) return exhausted(count)
                if (n == 0) {
                    target.challengePending = false
                    continue
                }
                out.setLength(count, n)
                out.setAddress(count, target.remote)
                out.setPath(count, target.socket)
                out.setLocalAddress(count, target.local)
                out.setEcn(count, currentMark)
                count++
                bytes +=
                    n
                c.bytesSent += n
                target.amplification.onSent(n)
            }
        }
        // a DPLPMTUD probe when one is due: PING + PADDING to exactly the probe size on the active path (RFC 8899 section 4.1)
        if (count < out.capacity && c.writeKeys[3] != null && c.closeFrame == null && c.state == ConnectionState.Confirmed &&
            c.path.state != PathState.Validating
        ) {
            c.path.pmtud?.let { m ->
                // no PMTU probes to an address under validation
                val size = m.nextProbeSize(now, c.pto())
                val held =
                    if (size <= 0 || size > out.segmentSize) {
                        false
                    } else if (c.cc.bytesInFlight + size > c.cc.cwnd) {
                        true // the next send opportunity asks again
                    } else {
                        val t = c.pacer.nextSendTime(now, size, c.cc, c.rtt.smoothed)
                        if (t != TimeMark.NEVER) pacerWakeup = t
                        t != TimeMark.NEVER
                    }
                if (held) m.deferProbe()
                if (!held && size > 0 &&
                    size <= out.segmentSize
                ) {
                    pmtuProbe = true
                    currentMark = c.path.ecn.markFor()
                    val n =
                        try {
                            buildPacket(out.buffer(count), 0, size, SpaceId.Application, now, padToEnd = true)
                        } finally {
                            pmtuProbe =
                                false
                        }
                    if (pnExhausted) return exhausted(count)
                    if (n >
                        0
                    ) {
                        out.setLength(count, n)
                        out.setAddress(count, c.path.remote)
                        out.setPath(count, c.path.socket)
                        out.setLocalAddress(count, c.path.local)
                        out.setEcn(count, currentMark)
                        count++
                        c.bytesSent +=
                            n
                        c.pmtudProbesSentForTest++
                        m.onProbeSent(c.loss.space(SpaceId.Application).nextPn - 1, n)
                    }
                }
            }
        }
        while (count < out.capacity && bytes < c.cc.sendQuantum) {
            val buf = out.buffer(count)
            var limit = minOf(out.segmentSize, c.path.mtu)
            if (!c.amplification.validated) {
                val budget = c.amplification.budget()
                if (budget <
                    64
                ) {
                    break
                }
                limit = minOf(limit.toLong(), budget).toInt()
            }
            currentMark = c.path.ecn.markFor()
            val n = buildDatagram(buf, limit, now)
            if (pnExhausted) return exhausted(count)
            if (n == 0) break
            out.setLength(count, n)
            out.setAddress(count, c.path.remote)
            out.setPath(count, c.path.socket)
            out.setLocalAddress(count, c.path.local)
            out.setEcn(count, currentMark)
            count++
            bytes +=
                n
            c.bytesSent += n
            c.amplification.onSent(n)
            if (c.closeFrame != null && c.closeSent) break
        }
        if (c.handshakeMirrorDue && count < out.capacity && c.closeFrame == null) count += mirrorFlight(out, count, now)
        if (pnExhausted) return exhausted(count)
        // one send quantum went out with window and data left: ask for the next poll when the pacer allows the next datagram (at
        // once without pacing), or the rest would wait for the peer's next packet and the sender would look application-limited
        if (!congested && bytes >= c.cc.sendQuantum && c.closeFrame == null &&
            c.cc.cwnd - c.cc.bytesInFlight >= MIN_WINDOW_DATAGRAM &&
            hasData(SpaceId.Application) && pacerWakeup == TimeMark.NEVER
        ) {
            pacer(now)
            if (pacerWakeup == TimeMark.NEVER) pacerWakeup = now
        }
        // data that waits for 1-RTT keys (or 0-RTT ones) cannot use the window: it does not count as data left
        if (c.closeFrame == null) appLimited = (c.writeKeys[3] == null && !zeroRtt) || !hasData(SpaceId.Application)
        // the sender ran out of data with room in the window and no pacing delay: the next rate samples show the application's pace
        if (!congested && count < out.capacity && bytes < c.cc.sendQuantum && c.closeFrame == null && appLimited) {
            (c.cc as? io.kuicksilver.quic.Bbr)?.onAppLimited()
        }
        return count
    }

    /**
     * Server, a PTO of the Initial or Handshake space fired while the handshake candidate is mirrored
     * ([io.kuicksilver.quic.core.openHandshakeMirror]): what the flight has in flight is retransmitted to the candidate's address
     * too, in new packets (RFC 9002 section 6.2.4 probes carry data again, never the same packet), each datagram a full 1200 bytes
     * (RFC 9000 section 14.1) and within that address's 3x budget (section 8.1). Returns the datagrams added at [first].
     */
    private fun mirrorFlight(
        out: PacketBatch,
        first: Int,
        now: TimeMark,
    ): Int {
        val k = c.handshakeCandidate
        val to = c.handshakeRebindTo
        if (k == null || to == null || !c.handshakeMirror || !k.isRemote(to) || c.state != ConnectionState.Handshaking) {
            c.handshakeMirrorDue = false
            return 0
        }
        // no room in this batch: at the next poll
        if (first >= out.capacity) return 0
        val levels = intArrayOf(0, 2)
        // data the active path has not sent yet goes there first (it would be pulled behind the retransmitted ranges): once it has
        if (levels.any { c.cryptoStreams.send[it].hasUnsent }) return 0
        c.handshakeMirrorDue = false
        // nothing is queued unless at least one full datagram can go there now; more budget comes only with what X sends
        if (!(k.amplification.validated || k.amplification.budget() >= 1200)) return 0
        val saved = Array(2) { c.cryptoStreams.send[levels[it]].saveRetransmit() }
        try {
            // what the flight has outstanding, queued again for this address only: the active path's own probes are not affected
            // (no packet is marked as taken by a probe) and the queue is put back as it was afterwards
            for (space in arrayOf(SpaceId.Initial, SpaceId.Handshake)) {
                if (c.spaceDiscarded[space.ordinal]) continue
                for (sent in c.loss.space(space).sent) {
                    val f = sent.frames
                    for (i in 0 until f.cryptoCount) c.cryptoStreams.send[f.cryptoLevel[i]].onLost(f.cryptoOffset[i], f.cryptoLength[i])
                }
            }
            initialAckOnly = false
            mirroring = true
            var count = first
            while (count < out.capacity) {
                val budget = if (k.amplification.validated) Long.MAX_VALUE else k.amplification.budget()
                if (budget < 1200) break
                val limit = minOf(out.segmentSize.toLong(), k.mtu.toLong(), budget).toInt()
                val buf = out.buffer(count)
                val hs = !c.spaceDiscarded[SpaceId.Handshake.ordinal] && c.cryptoStreams.send[2].hasRetransmit
                val init = !c.spaceDiscarded[SpaceId.Initial.ordinal] && c.cryptoStreams.send[0].hasRetransmit
                if (!hs && !init) break
                var pos = 0
                if (init) pos += buildPacket(buf, 0, limit, SpaceId.Initial, now, padToEnd = !hs, target = k, padIfNoRoomAfter = hs)
                if (pnExhausted) return count - first
                if (hs) pos += buildPacket(buf, pos, limit, SpaceId.Handshake, now, padToEnd = true, target = k)
                if (pnExhausted) return count - first
                if (pos == 0) break
                out.setLength(count, pos)
                out.setAddress(count, k.remote)
                out.setPath(count, k.socket)
                out.setLocalAddress(count, k.local)
                out.setEcn(count, io.kuicksilver.quic.Ecn.NotEct)
                count++
                c.bytesSent += pos
                k.amplification.onSent(pos)
                c.handshakeMirrorSent = true
            }
            return count - first
        } finally {
            mirroring = false
            for (i in levels.indices) c.cryptoStreams.send[levels[i]].restoreRetransmit(saved[i])
        }
    }

    /** Set while [mirrorFlight] builds: its packets carry no ACK frame (acknowledgements go to the active address). */
    private var mirroring = false

    /** Set when a packet number space has no number left to send (RFC 9000 section 12.3). */
    private var pnExhausted = false

    /**
     * A space ran out of packet numbers while a datagram was built: that datagram is dropped unsent and the connection closes
     * silently (RFC 9000 section 12.3); the [count] datagrams completed before stay in the batch.
     */
    private fun exhausted(count: Int): Int {
        c.silentClose(QuicException.ConnectionLost.Internal("packet numbers exhausted (RFC 9000 section 12.3)"))
        return count
    }

    /** A client before 1-RTT keys sends Application data in 0-RTT packets (RFC 9001 section 4.6.1). */
    private val zeroRtt: Boolean get() = c.role == TlsRole.Client && c.zeroRttWritable

    private fun spaceLevel(space: SpaceId): Int =
        when (space) {
            SpaceId.Initial -> 0
            SpaceId.Handshake -> 2
            SpaceId.Application -> if (zeroRtt) 1 else 3
        }

    private fun packetType(space: SpaceId): PacketType =
        when (space) {
            SpaceId.Initial -> PacketType.Initial
            SpaceId.Handshake -> PacketType.Handshake
            SpaceId.Application -> if (zeroRtt) PacketType.ZeroRtt else PacketType.OneRtt
        }

    private fun hasAckToSend(
        space: SpaceId,
        now: TimeMark,
    ): Boolean {
        val a = c.loss.space(space).ack
        if (!a.hasRanges) return false
        val d = a.ackDeadline(c.config.maxAckDelay)
        if (d == TimeMark.NEVER) return false
        return a.ackRequired || d <= now
    }

    private fun hasData(space: SpaceId): Boolean {
        val level = spaceLevel(space)
        if (c.cryptoStreams.send[level].hasPending || c.probePending[space.ordinal] > 0) return true
        if (level == 2 && c.testInjectDatagramInHandshake) return true
        c.testInjectCrypto?.let { if (it.first == level) return true }
        if (c.testInjectFrames.firstOrNull()?.first == level) return true
        if (space != SpaceId.Application) return false
        return c.sendHandshakeDone || c.sendNewToken || c.path.challengePending || c.paths.hasResponseFor(c.path) ||
            c.testInjectPathChallenges > 0 ||
            c.testInjectPathResponse != null ||
            c.streams.hasControlFrames() ||
            c.streams.hasStreamData() ||
            c.cids.hasPendingFrames() ||
            c.timers.keepAlivePending ||
            c.testInjectHandshakeDone ||
            c.testInjectDatagramFrame ||
            c.testInjectNewCids > 0 ||
            c.testInjectMaxData > 0 ||
            c.testInjectDataBlocked > 0 ||
            c.testInjectRepeatNewCid > 0 ||
            c.testInjectDatagramBytes > 0 ||
            (c.datagramSender?.hasPending() == true && c.datagramPayloadLimit >= 0)
    }

    private fun wantsToSend(
        space: SpaceId,
        now: TimeMark,
    ): Boolean {
        if (c.spaceDiscarded[space.ordinal] || c.writeKeys[spaceLevel(space)] == null) return false
        if (c.closeFrame != null) return spaceLevel(space) != 1 && !c.closeSentIn[space.ordinal] // no CONNECTION_CLOSE (0x1c) in 0-RTT
        if (space == SpaceId.Initial && initialAckOnly) return hasAckToSend(space, now)
        if (spaceLevel(space) == 1) {
            return !congested &&
                (
                    c.streams.hasControlFrames() || c.streams.hasStreamData() || c.testInjectFrames.firstOrNull()?.first == 1 ||
                        c.probePending[SpaceId.Application.ordinal] > 0
                ) // a probe of 0-RTT data in flight goes as a 0-RTT PING when nothing is left to resend
        }
        if (hasAckToSend(space, now)) return true
        // path validation is not congestion controlled (RFC 9000 section 9.1): a rebind while the window is full must still be challenged
        if (space == SpaceId.Application && (c.path.challengePending || c.paths.hasResponseFor(c.path))) return true
        return !congested && hasData(space)
    }

    private fun buildDatagram(
        buf: PacketBuffer,
        limit: Int,
        now: TimeMark,
    ): Int {
        // RFC 9002 section 7: no packet may take bytes_in_flight above the window. The datagram goes only while it fits; with less
        // room than [limit] but at least [MIN_WINDOW_DATAGRAM] it is cut to the room, so a window that a jumbo MTU outgrew (RFC 8899
        // section 3 item 7 keeps the window from growing with the MTU) still carries data. Below that the window is full
        val probing = probeDue()
        val room = c.cc.cwnd - c.cc.bytesInFlight
        val maxLen = if (probing || room >= limit || room < MIN_WINDOW_DATAGRAM) limit else room.toInt()
        congested = !probing && room < maxLen
        initialAckOnly = c.role == TlsRole.Server && maxLen < 1200
        // "Probe packets MUST NOT be blocked by the congestion controller" (RFC 9002 section 7.5): the pacer neither; they still
        // spend its credit when sent
        if (!congested && !probing) pacer(now)
        var pos = 0
        var needPad = false
        var lastBuilt: SpaceId? = null
        val spaces = SpaceId.entries
        for (i in spaces.indices) {
            val space = spaces[i]
            if (!wantsToSend(space, now)) continue
            var last = true
            for (j in i + 1 until spaces.size) {
                if (wantsToSend(spaces[j], now)) {
                    last = false
                    break
                }
            }
            // RFC 9000 section 14.1: a client expands every datagram carrying an Initial packet to 1200 bytes, a server every one
            // carrying an ack-eliciting Initial packet, with PADDING frames or by coalescing (section 12.2). The last packet pads
            // the datagram; an earlier one pads itself when a following packet could no longer fit behind it
            val initialNeedsPad = space == SpaceId.Initial && !initialAckOnly && (c.role == TlsRole.Client || hasData(SpaceId.Initial))
            val pad = needPad || initialNeedsPad
            val n = buildPacket(buf, pos, maxLen, space, now, padToEnd = last && pad, padIfNoRoomAfter = !last && pad)
            if (n == 0) continue
            if (space == SpaceId.Initial && (c.role == TlsRole.Client || lastWasAckEliciting)) needPad = true
            pos += n
            lastBuilt = space
        }
        // the space expected to close the datagram sent nothing after all: one more packet of the last long-header space, padded
        // to the end; the packet before it left room for it ([MIN_COALESCED_PACKET]). A 1-RTT packet is always the last one
        if (needPad && pos in 1 until 1200 && maxLen >= 1200 && lastBuilt != null && lastBuilt != SpaceId.Application) {
            pos += buildPacket(buf, pos, maxLen, lastBuilt, now, padToEnd = true)
        }
        return pos
    }

    /**
     * A PTO probe is owed in a space that can still send it (RFC 9002 sections 6.2.4, 7.5): only then is the datagram exempt from
     * the congestion window. A count left in a discarded space, or one without write keys, exempts nothing.
     */
    private fun probeDue(): Boolean {
        val pending = c.probePending
        for (i in pending.indices) {
            if (pending[i] > 0 && !c.spaceDiscarded[i] && c.writeKeys[spaceLevel(SpaceId.entries[i])] != null) return true
        }
        return false
    }

    private fun pacer(now: TimeMark) {
        val t = c.pacer.nextSendTime(now, c.path.mtu, c.cc, c.rtt.smoothed)
        if (t != TimeMark.NEVER) {
            pacerWakeup = t
            congested = true
        }
    }

    private var lastWasAckEliciting = false

    /** Random bits for the spin bit, drawn 64 at a time; [spinBitsLeft] of them are unused. */
    private var spinBits = 0L
    private var spinBitsLeft = 0

    /**
     * The spin bit of the next short header. We never spin (latency spin is disabled), so RFC 9000 section 17.4 applies: "It is
     * RECOMMENDED that endpoints set the spin bit to a random value either chosen independently for each packet or chosen
     * independently for each connection ID": a fresh random bit per packet.
     */
    private fun nextSpinBit(): Boolean {
        if (spinBitsLeft == 0) {
            spinBits = c.random.nextLong()
            spinBitsLeft = 64
        }
        spinBitsLeft--
        val bit = spinBits and 1L != 0L
        spinBits = spinBits ushr 1
        return bit
    }

    /**
     * Re-encodes the ACK frame at `[from, to)` of [buf] with longer variable-length integers (RFC 9000 section 16: values "do not need
     * to be encoded on the minimum number of bytes necessary, with the sole exception of the Frame Type field") until it grew by at
     * least [grow] bytes, by no more than [room], or every field is 8 bytes long; returns where it now ends.
     */
    private fun stretchAck(
        buf: PacketBuffer,
        from: Int,
        to: Int,
        grow: Int,
        room: Int,
    ): Int {
        val values = LongArray(to - from)
        val sizes = IntArray(to - from)
        var n = 0
        var at = from + 1 // the frame type stays one byte
        while (at < to) {
            val len = 1 shl ((buf[at].toInt() and 0xff) ushr 6)
            var v = (buf[at].toLong() and 0x3f)
            for (i in 1 until len) v = (v shl 8) or (buf[at + i].toLong() and 0xff)
            values[n] = v
            sizes[n++] = len
            at += len
        }
        var need = minOf(grow, room)
        var left = room
        for (i in 0 until n) {
            if (need <= 0) break
            val s = sizes[i]
            var target = 8
            for (t in intArrayOf(2, 4, 8)) {
                if (t > s && t - s >= need) {
                    target = t
                    break
                }
            }
            if (target <= s || target - s > left) continue
            left -= target - s
            need -= target - s
            sizes[i] = target
        }
        at = from + 1
        for (i in 0 until n) at = VarInt.writeFixed(buf, at, values[i], sizes[i])
        return at
    }

    private fun buildPacket(
        buf: PacketBuffer,
        start: Int,
        maxLen: Int,
        space: SpaceId,
        now: TimeMark,
        padToEnd: Boolean,
        target: Path = c.path,
        dcid: io.kuicksilver.quic.wire.ConnectionId = c.remoteCid,
        padIfNoRoomAfter: Boolean = false,
    ): Int {
        var padToEnd = padToEnd
        var ackFrom = -1 // where this packet's ACK frame starts and ends ([stretchAck])
        var ackTo = -1
        val level = spaceLevel(space)
        val key = c.writeKeys[level] ?: return 0
        if (level == 3 && c.oneRttWriteKeyExhausted) return 0 // RFC 9001 section 6.6: "MUST stop using those keys"
        val sp = c.loss.space(space)
        if (maxLen - 16 - start < 48) return 0 // no room for a header, the sample and a frame
        // RFC 9000 section 12.3: at packet number 2^62-1 the connection closes without a CONNECTION_CLOSE or any further packet.
        // takePn may skip one number, so the space is spent once the next would be 2^62-2
        if (sp.nextPn >= MAX_PACKET_NUMBER - 1) {
            pnExhausted = true
            return 0
        }
        // taken (commitPn) only once the packet is built: one that does not fit or has nothing to carry costs no number
        val pn = sp.peekPn(c.random)
        val pnLen = PacketNumbers.encodedLength(pn, sp.largestAcked)
        val type = packetType(space)
        val token = if (type == PacketType.Initial && c.role == TlsRole.Client) (c.retryToken ?: c.initialToken) else null
        val headerLen =
            if (type != PacketType.OneRtt) {
                // flags, version, both connection IDs with their lengths, the Initial's token, the 2-byte Length, the number
                7 + c.remoteCid.length + c.localCid.length + 2 + pnLen +
                    (if (type == PacketType.Initial) VarInt.size((token?.size ?: 0).toLong()) + (token?.size ?: 0) else 0)
            } else {
                1 + dcid.length + pnLen
            }
        // the header and at least 4 bytes of payload (the header-protection sample) before the tag; 20-byte connection IDs and
        // a small anti-amplification budget left the long header itself without room (it threw while being written)
        if (maxLen - 16 - start < headerLen + 4) return 0
        val w =
            writer?.also {
                it.buf = buf
                it.pos = start
                it.limit = maxLen - 16
            }
                ?: WireWriter(buf, start, maxLen - 16).also { writer = it }
        var lengthOff = -1
        if (type !=
            PacketType.OneRtt
        ) {
            lengthOff =
                PacketHeaderCodec.writeLong(
                    w,
                    // RFC 9369 section 4.1: "The client MUST NOT send 0-RTT packets using the negotiated version"
                    if (type == PacketType.ZeroRtt) c.originalVersion else c.version,
                    type,
                    c.remoteCid,
                    c.localCid,
                    token,
                    pnLen,
                    false,
                )
        } else {
            PacketHeaderCodec.writeShort(
                w,
                dcid,
                pnLen,
                spin = nextSpinBit(),
                keyPhase = c.keyPhase?.phase ?: false,
                greaseFixedBit =
                    c.peerGreaseQuicBit && c.config.greaseQuicBit && c.random.nextBoolean(),
            )
        }
        val pnOff = w.pos
        w.zero(pnLen)
        val payloadStart = w.pos
        check(w.remaining >= 4 && pnOff - start == headerLen - pnLen) { "header of ${pnOff - start + pnLen} bytes, $headerLen expected" }
        val p = sp.newSentPacket()
        val frames = p.frames
        frames.clear()
        var ackEliciting = false
        val close = c.closeFrame
        if (close != null) {
            // Initial/Handshake copies omit the reason (RFC 9000 section 10.2.3)
            val reason = if (type == PacketType.OneRtt) close.reason else ByteArray(0)
            val app = close.application && type == PacketType.OneRtt
            val code =
                if (app) {
                    close.code
                } else if (close.application) {
                    0x0c
                } else {
                    close.code
                }
            // a CONNECTION_CLOSE cannot be split between packets, "any limits on packet size will also limit the space available
            // for a reason phrase" (RFC 9000 section 19.19): a reason that does not fit the room left (an anti-amplification
            // budget, section 8.1) is cut, on a character boundary, never the frame; a packet without room even for a bare frame
            // is not built (it takes no packet number) and the space still owes its copy
            val bare = FrameEncoder.connectionCloseOverhead(app, code, close.frameType, 0)
            if (w.remaining < bare) {
                sp.release(p)
                return 0
            }
            var reasonLength = reason.size
            if (FrameEncoder.connectionCloseOverhead(app, code, close.frameType, reasonLength) > w.remaining) {
                val room = w.remaining - bare // bare counts a 1-byte reason length; up to 63 bytes keep it
                reasonLength = utf8Prefix(reason, if (room <= 63) room else room - 1)
            }
            val sentReason = if (reasonLength == reason.size) reason else reason.copyOf(reasonLength)
            FrameEncoder.connectionClose(w, app, code, close.frameType, sentReason)
            c.closeSentIn[space.ordinal] = true
        } else if (pmtuProbe) {
            FrameEncoder.ping(w)
            frames.flags = frames.flags or SentFrames.PING or SentFrames.PMTU_PROBE
            ackEliciting =
                true // RFC 8899: PING and padding only
            // a probe of another path: only PATH_CHALLENGE / PATH_RESPONSE, expanded to 1200 bytes (RFC 9000 sections 8.2.1, 9.1)
        } else if (probeTarget != null) {
            val stray = strayFrom
            if (stray == null &&
                target.challengePending &&
                w.remaining >= 9
            ) {
                FrameEncoder.pathChallenge(w, c.newChallengeData(target))
                frames.flags =
                    frames.flags or SentFrames.PATH_CHALLENGE
                frames.pathChallenge = target.challenge
                target.challengePending = false
                ackEliciting =
                    true
                c.challengedAddressesForTest.recordForTest(target.remote)
                c.pathChallengesSentForTest++
                c.challengeDataSentForTest.recordForTest(target.challenge)
            }
            while (w.remaining >=
                9
            ) {
                val r =
                    (if (stray == null) c.paths.takeResponseFor(target) else c.paths.takeResponseFrom(target, stray)) ?: break
                FrameEncoder.pathResponse(w, r)
                frames.flags =
                    frames.flags or SentFrames.PATH_RESPONSE
                ackEliciting = true
                c.pathResponsesSentForTest++
            }
        } else {
            val a = sp.ack
            // a test probe (testInjectPathChallenges) carries no ACK: a probing-only packet, RFC 9000 section 9.1
            if (a.hasRanges && (hasAckToSend(space, now) || hasData(space)) && !mirroring &&
                c.testInjectPathChallenges == 0 && type != PacketType.ZeroRtt &&
                (!c.testAckOnlyAfterAckEliciting || a.ackElicitingPending)
            ) {
                val o = a.ackOverhead(now, c.config.ackDelayExponent)
                if (o <=
                    w.remaining
                ) {
                    ackFrom = w.pos
                    a.writeAck(w, now, c.config.ackDelayExponent)
                    ackTo = w.pos
                    frames.ackLargest = a.largestReceived
                    if (space ==
                        SpaceId.Application
                    ) {
                        c.keyPhase?.onAckSent()
                    }
                }
            }
            // PATH_CHALLENGE / PATH_RESPONSE of the active path: outside the congestion window (RFC 9000 section 9.1)
            if (type == PacketType.OneRtt) {
                if (target.challengePending &&
                    w.remaining >= 9
                ) {
                    FrameEncoder.pathChallenge(w, c.newChallengeData(target))
                    frames.flags =
                        frames.flags or SentFrames.PATH_CHALLENGE
                    frames.pathChallenge = target.challenge
                    target.challengePending =
                        false
                    ackEliciting = true
                    padToEnd = true
                    c.challengedAddressesForTest.recordForTest(target.remote)
                    c.pathChallengesSentForTest++
                    c.challengeDataSentForTest.recordForTest(target.challenge)
                } // RFC 9000 section 8.2.1: expanded to 1200 bytes
                while (w.remaining >=
                    9
                ) {
                    val r =
                        c.paths.takeResponseFor(target) ?: break
                    FrameEncoder.pathResponse(w, r)
                    frames.flags =
                        frames.flags or SentFrames.PATH_RESPONSE
                    ackEliciting = true
                    padToEnd = true
                    c.pathResponsesSentForTest++
                } // section 8.2.2
            }
            if (!congested && !(space == SpaceId.Initial && initialAckOnly)) {
                val cs = c.cryptoStreams.send[level]
                while (cs.hasPending) {
                    val overhead = FrameEncoder.cryptoOverhead(cs.nextOffset, w.remaining)
                    val space =
                        w.remaining - overhead
                    if (space <= 0) break
                    if (!cs.nextRange(space, range) || range.length == 0) break
                    w.u8(0x06)
                    w.varint(range.offset)
                    w.varint(range.length.toLong())
                    val tmp =
                        if (range.length <=
                            scratch.size
                        ) {
                            scratch
                        } else {
                            ByteArray(range.length)
                        }
                    ; cs.copy(range.offset, tmp, 0, range.length)
                    w.bytes(tmp, 0, range.length)
                    frames.addCrypto(level, range.offset, range.length)
                    cs.markSent(range.offset, range.length)
                    ackEliciting = true
                }
                c.testInjectCrypto?.let { (l, off, len) ->
                    if (l == level &&
                        w.remaining > 16
                    ) {
                        val n = minOf(len, w.remaining - 14)
                        w.u8(0x06)
                        w.varint(off)
                        w.varint(n.toLong())
                        w.zero(n)
                        ackEliciting =
                            true
                        c.testInjectCrypto = if (n == len) null else Triple(l, off + n, len - n)
                    }
                }
                while (true) {
                    val inject = c.testInjectFrames.firstOrNull() ?: break
                    if (inject.first != level || inject.second.size > w.remaining) break
                    w.bytes(inject.second, 0, inject.second.size)
                    c.testInjectFrames.removeFirst()
                    ackEliciting = true
                }
                if (type == PacketType.Handshake && c.testInjectDatagramInHandshake &&
                    w.remaining >= 4
                ) {
                    FrameEncoder.datagram(w, buf, 0, 2, withLength = true)
                    c.testInjectDatagramInHandshake = false
                    ackEliciting =
                        true
                }
                if (c.probePending[space.ordinal] >
                    0
                ) {
                    if (!ackEliciting) {
                        FrameEncoder.ping(w)
                        frames.flags = frames.flags or SentFrames.PING
                        ackEliciting = true
                    }
                    c.probePending[space.ordinal]--
                }
                if (type == PacketType.OneRtt) {
                    if (c.sendHandshakeDone &&
                        w.remaining >= 1
                    ) {
                        FrameEncoder.handshakeDone(w)
                        frames.flags = frames.flags or SentFrames.HANDSHAKE_DONE
                        c.sendHandshakeDone =
                            false
                        c.handshakeDoneSent = true
                        ackEliciting = true
                    }
                    // RFC 9000 section 19.7: the token travels in a 1-RTT packet, here after HANDSHAKE_DONE (the client confirms first)
                    val token = c.newToken
                    if (c.sendNewToken && token != null && w.remaining >= 1 + 2 + token.size) {
                        FrameEncoder.newToken(w, token)
                        frames.addId(SentFrames.ID_NEW_TOKEN, c.newTokenSeq)
                        c.sendNewToken = false
                        if (!c.handshakeDoneSent) c.newTokenAfterHandshakeDoneForTest = false
                        c.newTokenSendsForTest.recordForTest(token)
                        ackEliciting = true
                    }
                    if (c.testInjectHandshakeDone &&
                        w.remaining >= 1
                    ) {
                        FrameEncoder.handshakeDone(w)
                        c.testInjectHandshakeDone = false
                        ackEliciting = true
                    }
                    if (c.testInjectDatagramFrame &&
                        w.remaining >= 4
                    ) {
                        FrameEncoder.datagram(w, buf, 0, 2, withLength = true)
                        c.testInjectDatagramFrame = false
                        ackEliciting =
                            true
                    }
                    if (c.timers.keepAlivePending &&
                        w.remaining >= 1
                    ) {
                        FrameEncoder.ping(w)
                        frames.flags = frames.flags or SentFrames.PING
                        c.timers.keepAlivePending =
                            false
                        ackEliciting = true
                    }
                    while (w.remaining >=
                        1 + 8 + 8 + 1 + 20 + 16
                    ) {
                        val l =
                            c.cids.nextNewCidToSend() ?: break
                        FrameEncoder.newConnectionId(w, l.seq, l.retirePriorTo, l.cid.toByteArray(), l.token)
                        frames.addId(SentFrames.ID_NEW_CONNECTION_ID, l.seq)
                        l.sent =
                            true
                        ackEliciting = true
                    }
                    if (c.cids.hasPendingFrames() &&
                        w.remaining >= 9
                    ) {
                        for (seq in c.cids.takeRetireFrames()) {
                            if (w.remaining <
                                9
                            ) {
                                c.cids.onRetireLost(seq)
                                continue
                            }
                            FrameEncoder.retireConnectionId(w, seq)
                            frames.addId(SentFrames.ID_RETIRE_CONNECTION_ID, seq)
                            ackEliciting =
                                true
                        }
                    }
                    while (c.testInjectRepeatNewCid > 0 &&
                        w.remaining >= 50
                    ) {
                        val l =
                            c.cids.localForTest(1) ?: break
                        FrameEncoder.newConnectionId(w, l.seq, l.retirePriorTo, l.cid.toByteArray(), l.token)
                        c.testInjectRepeatNewCid--
                        ackEliciting =
                            true
                    }
                    while (c.testInjectMaxData > 0 &&
                        w.remaining >= 2
                    ) {
                        FrameEncoder.maxData(w, 0)
                        c.testInjectMaxData--
                        ackEliciting = true
                    }
                    while (c.testInjectDataBlocked > 0 &&
                        w.remaining >= 9
                    ) {
                        FrameEncoder.dataBlocked(w, c.testInjectDataBlocked.toLong())
                        c.testInjectDataBlocked--
                        ackEliciting = true
                    }
                    while (c.testInjectNewCids > 0 &&
                        w.remaining >= 50
                    ) {
                        val seq =
                            100L + c.testInjectNewCids
                        FrameEncoder.newConnectionId(w, seq, 0, ByteArray(8) { seq.toByte() }, ByteArray(16))
                        c.testInjectNewCids--
                        ackEliciting =
                            true
                    }
                    while (c.testInjectPathChallenges > 0 &&
                        w.remaining >= 9
                    ) {
                        FrameEncoder.pathChallenge(w, 0x1000L + c.testInjectPathChallenges)
                        c.testInjectPathChallenges--
                        ackEliciting =
                            true
                        padToEnd = true
                    }
                    c.testInjectPathResponse?.let {
                        if (w.remaining >=
                            9
                        ) {
                            FrameEncoder.pathResponse(w, it)
                            c.testInjectPathResponse = null
                            ackEliciting = true
                        }
                    }
                    if (writeControlFrames(w, frames)) ackEliciting = true
                    // a datagram with an urgency (DatagramSender.nextUrgency) lets strictly more urgent stream data go first
                    // (RFC 9218 section 10 as WebTransport applies it to datagrams, draft-ietf-webtrans-http3-16 section 3.4)
                    c.datagramSender?.takeIf { it.hasPending() }?.nextUrgency()?.let { u ->
                        if (u >= 0) {
                            while (w.remaining > 8 && c.streams.writeStreamFrame(w, frames, below = u)) ackEliciting = true
                        }
                    }
                    c.datagramSender?.let { s ->
                        val max = c.datagramPayloadLimit // 0: an empty datagram still goes (a peer limit of 2)
                        if (max >= 0 &&
                            w.remaining > 3
                        ) {
                            c.datagramWriter.bind(w, frames, max)
                            try {
                                s.onTransmit(c.datagramWriter)
                            } finally {
                                c.datagramWriter.unbind()
                            }
                            if (c.datagramWriter.wrote) {
                                ackEliciting =
                                    true
                            }
                        }
                    } // RFC 9221: datagrams before stream data, inside the congestion window
                    if (c.testInjectDatagramBytes > 0 &&
                        w.remaining > c.testInjectDatagramBytes + 4
                    ) {
                        FrameEncoder.datagram(w, ByteArray(c.testInjectDatagramBytes), 0, c.testInjectDatagramBytes)
                        c.testInjectDatagramBytes =
                            0
                        ackEliciting = true
                    }
                    while (w.remaining > 8 && c.streams.writeStreamFrame(w, frames)) ackEliciting = true
                }
                if (type == PacketType.ZeroRtt) {
                    // 0-RTT carries stream data and its control frames only: no ACK, CRYPTO, connection IDs or path frames (RFC 9000 section 12.4)
                    if (writeControlFrames(w, frames)) ackEliciting = true
                    while (w.remaining > 8 && c.streams.writeStreamFrame(w, frames)) ackEliciting = true
                }
            }
        }
        val payloadBytes = w.pos - payloadStart
        if (payloadBytes == 0 && close == null && !padToEnd) {
            sp.release(p)
            return 0
        }
        var padded = false
        // RFC 9000 section 14.1: this packet must reach 1200 bytes with PADDING frames when no further packet fits behind it
        if (padIfNoRoomAfter && maxLen >= 1200 && maxLen - (w.pos + 16) < MIN_COALESCED_PACKET) padToEnd = true
        if (padToEnd && maxLen >= 1200) {
            w.zero(w.remaining)
            padded = true
        } else if (pnLen + (w.pos - payloadStart) < 4) {
            w.zero(4 - pnLen - (w.pos - payloadStart))
            padded = true
        }
        // RFC 9000 section 10.3: "SHOULD ensure that all packets it sends are at least 22 bytes longer than the minimum connection
        // ID length that it requests the peer to include in its packets, adding PADDING frames as necessary", so that the peer's
        // Stateless Reset (one byte shorter) looks like a packet to us. A long header always is: it carries our ID as its SCID
        // beside 28 bytes or more. An ACK-only packet grows by longer varints in its ACK frame instead (section 16): PADDING would
        // put it in flight (RFC 9002 section 2), outside the window it is sent past, and a peer that acknowledges only
        // ack-eliciting packets (section 13.2.1) would never take it out again
        if (type == PacketType.OneRtt) {
            val short = c.localCid.length + 22 - (w.pos + 16 - start)
            if (short > 0) {
                if (!ackEliciting && !padded && close == null && ackFrom >= 0 && ackTo == w.pos) {
                    w.pos = stretchAck(buf, ackFrom, ackTo, short, w.remaining)
                } else {
                    w.zero(minOf(short, w.remaining))
                    padded = true
                }
            }
        }
        val payloadEnd = w.pos
        if (lengthOff >= 0) VarInt.writeFixed(buf, lengthOff, (pnLen + (payloadEnd - payloadStart) + 16).toLong(), 2)
        val end = PacketProtection.protect(buf, start, pnOff, pnLen, payloadEnd, pn, key, mask)
        // RFC 9000 section 8.2.1: a challenge the amplification limit kept below 1200 bytes does not validate the path MTU
        if (frames.flags and SentFrames.PATH_CHALLENGE != 0 && end < 1200) target.markLastChallengeUndersized()
        if (type == PacketType.OneRtt) c.onOneRttPacketSealed(pn)
        if (type == PacketType.ZeroRtt) {
            c.zeroRttPacketsSealed++ // its confidentiality limit (zeroRttWritable)
            if (c.zeroRttFirstPn < 0) c.zeroRttFirstPn = pn
            c.zeroRttLastPn = pn // what an acknowledgment after a rejection must not cover (ZeroRtt.checkAckAfterRejection)
        }
        p.zeroRtt = type == PacketType.ZeroRtt
        sp.commitPn(pn)
        p.pn = pn
        p.timeSent = now
        p.size = end - start
        p.ackEliciting = ackEliciting
        p.inFlight = ackEliciting || padded // a PMTU probe too: "PMTU probes consume congestion window" (RFC 9000 section 14.4)
        p.pathId = target.id.value
        p.addressEpoch = target.addressEpoch
        p.cc = target.cc
        p.ecnMarked = currentMark != io.kuicksilver.quic.Ecn.NotEct
        // a test packet must be one loss detection can declare lost (appendix A.4: "if marked packets are all declared lost"):
        // ACK-only packets are never stored, so they would keep a black-holed path in the Unknown state forever
        if (p.ecnMarked && close == null && (ackEliciting || p.inFlight)) target.ecn.onSent(true)
        lastWasAckEliciting = ackEliciting
        // the path the packet travels on owns its congestion state (RFC 9000 section 9.4): a probe lost on a dead path never inflates the active window
        if (close ==
            null
        ) {
            c.loss.onPacketSent(space, p, now)
            if (p.size > target.largestSent) target.largestSent = p.size // what a Packet Too Big about this path may claim was too large
            // where the server's handshake flight went decides which address a client Handshake packet validates (RFC 9000 section 8.1)
            if (space != SpaceId.Application && frames.cryptoCount > 0 && c.role == TlsRole.Server) c.onHandshakeFlightSent(target)
            if (p.inFlight) {
                target.cc.onPacketSent(now, p.size)
                // the delivery-rate snapshot (draft-ietf-ccwg-bbr section 4.1.2.2)
                (target.cc as? io.kuicksilver.quic.Bbr)?.onPacketStamped(p, now)
                target.pacer.onSent(now, p.size)
            }
            if (ackEliciting) {
                c.timers.lastAckElicitingSent =
                    now
                if (!c.timers.ackElicitingSentSinceReceive) {
                    c.timers.ackElicitingSentSinceReceive = true
                    c.timers.lastActivity = now
                }
            }
        } else {
            sp.release(p)
            c.timers.lastCloseSent =
                now
        }
        c.packetsSent++
        c.qlog?.packetSent(space, pn, end - start, if (close == null) frames else null, now)
        if (space == SpaceId.Handshake && c.role == TlsRole.Client && !c.spaceDiscarded[0]) c.discardInitialPending = true
        return end - start
    }

    /** Queued stream control frames (RESET_STREAM, MAX_DATA, ...): allowed in 0-RTT and 1-RTT packets alike. True when one was written. */
    private fun writeControlFrames(
        w: WireWriter,
        frames: SentFrames,
    ): Boolean {
        var ackEliciting = false
        while (true) {
            val cf = c.streams.takeControlFrame() ?: break
            if (c.streams.controlOverhead(cf) > w.remaining) {
                c.streams.pushBackControlFrame(cf)
                break
            }
            when (cf.kind) {
                ControlKind.ResetStream -> {
                    FrameEncoder.resetStream(w, cf.id, cf.a, cf.b)
                    frames.addId(SentFrames.ID_RESET_STREAM, cf.id, cf.a, cf.b)
                }

                ControlKind.ResetStreamAt -> {
                    c.streams.tamperResetStreamAtForTest?.invoke(cf)
                    FrameEncoder.resetStreamAt(w, cf.id, cf.a, cf.b, cf.c)
                    frames.addId(SentFrames.ID_RESET_STREAM_AT, cf.id, cf.a, cf.b, cf.c)
                }

                ControlKind.StopSending -> {
                    FrameEncoder.stopSending(w, cf.id, cf.a)
                    frames.addId(SentFrames.ID_STOP_SENDING, cf.id, cf.a)
                }

                ControlKind.MaxStreamData -> {
                    FrameEncoder.maxStreamData(w, cf.id, cf.a)
                    frames.addId(SentFrames.ID_MAX_STREAM_DATA, cf.id, cf.a)
                }

                ControlKind.StreamDataBlocked -> {
                    FrameEncoder.streamDataBlocked(w, cf.id, cf.a)
                    frames.addId(SentFrames.ID_STREAM_DATA_BLOCKED, cf.id, cf.a)
                }

                ControlKind.DataBlocked -> {
                    FrameEncoder.dataBlocked(w, cf.a)
                    frames.flags =
                        frames.flags or SentFrames.DATA_BLOCKED
                }

                ControlKind.MaxData -> {
                    FrameEncoder.maxData(w, cf.a)
                    frames.flags = frames.flags or SentFrames.MAX_DATA
                }

                ControlKind.MaxStreamsBidi -> {
                    FrameEncoder.maxStreams(w, true, cf.a)
                    frames.flags =
                        frames.flags or SentFrames.MAX_STREAMS_BIDI
                }

                ControlKind.MaxStreamsUni -> {
                    FrameEncoder.maxStreams(w, false, cf.a)
                    frames.flags =
                        frames.flags or SentFrames.MAX_STREAMS_UNI
                }

                ControlKind.StreamsBlockedBidi -> {
                    FrameEncoder.streamsBlocked(w, true, cf.a)
                    frames.flags =
                        frames.flags or SentFrames.STREAMS_BLOCKED_BIDI
                }

                ControlKind.StreamsBlockedUni -> {
                    FrameEncoder.streamsBlocked(w, false, cf.a)
                    frames.flags =
                        frames.flags or SentFrames.STREAMS_BLOCKED_UNI
                }
            }
            c.streams.releaseControlFrame(cf)
            ackEliciting = true
        }
        return ackEliciting
    }
}

/**
 * The room a packet coalesced behind another one may need (RFC 9000 section 12.2): a long header with two 20-byte connection
 * IDs, a 2-byte Length and a 4-byte packet number (53 bytes), the 4 bytes that keep the header protection sample inside the
 * packet (RFC 9001 section 5.4.2) and the 16-byte AEAD tag.
 */
private const val MIN_COALESCED_PACKET = 73

/**
 * The smallest datagram the window is cut to when less than a full one fits (RFC 9002 section 7): what any packet may need
 * (RFC 9000 section 14.1: a datagram with an Initial packet, a PATH_CHALLENGE), and the smallest maximum datagram size. A
 * window with less room than this (or than one datagram, when that is smaller) is full.
 */
internal const val MIN_WINDOW_DATAGRAM = 1200

/** The packet number at which a sender must stop (RFC 9000 section 12.3: 2^62-1). */
private const val MAX_PACKET_NUMBER = (1L shl 62) - 1
