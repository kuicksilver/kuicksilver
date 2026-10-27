// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.PathState
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
    private var writer: WireWriter? = null
    private val mask = ByteArray(5)
    private val range = SendRange()
    private val scratch = ByteArray(2048)
    private var congested = false

    /** Set while a probe datagram for a path other than the active one is built: only PATH_CHALLENGE/PATH_RESPONSE and padding go in (RFC 9000 section 9.1). */
    private var probeTarget: Path? = null

    /** The ECN codepoint of the datagram being built (per path validation state). */
    private var currentMark: io.kuicksilver.quic.Ecn = io.kuicksilver.quic.Ecn.NotEct

    /**
     * Set while a datagram below 1200 bytes is built (a server's anti-amplification budget): its Initial packet may carry an ACK
     * but nothing ack-eliciting, since a datagram with an ack-eliciting Initial must reach 1200 bytes (RFC 9000 section 14.1) and
     * the server must not send more than the budget (section 8.1). CRYPTO and PTO probes of the Initial space wait for budget.
     */
    private var initialAckOnly = false

    /** Set while a DPLPMTUD probe is built: a 1-RTT packet of PING and padding, outside congestion control (RFC 9000 section 14.4). */
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
                if (n == 0) {
                    target.challengePending = false
                    continue
                }
                out.setLength(count, n)
                out.setAddress(count, target.remote)
                out.setPath(count, target.socket)
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
                val size = m.nextProbeSize(now)
                if (size > 0 &&
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
                    if (n >
                        0
                    ) {
                        out.setLength(count, n)
                        out.setAddress(count, c.path.remote)
                        out.setPath(count, c.path.socket)
                        out.setEcn(count, currentMark)
                        count++
                        c.bytesSent +=
                            n
                        c.pmtudProbesSentForTest++
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
            if (n == 0) break
            out.setLength(count, n)
            out.setAddress(count, c.path.remote)
            out.setPath(count, c.path.socket)
            out.setEcn(count, currentMark)
            count++
            bytes +=
                n
            c.bytesSent += n
            c.amplification.onSent(n)
            if (c.closeFrame != null && c.closeSent) break
        }
        // one send quantum went out with window and data left: ask for the next poll when the pacer allows the next datagram (at
        // once without pacing), or the rest would wait for the peer's next packet and the sender would look application-limited
        if (!congested && bytes >= c.cc.sendQuantum && c.closeFrame == null && c.cc.bytesInFlight < c.cc.cwnd &&
            hasData(SpaceId.Application) && pacerWakeup == TimeMark.NEVER
        ) {
            pacer(now)
            if (pacerWakeup == TimeMark.NEVER) pacerWakeup = now
        }
        // the sender ran out of data with room in the window and no pacing delay: the next rate samples show the application's pace
        if (!congested && count < out.capacity && bytes < c.cc.sendQuantum && c.closeFrame == null && !hasData(SpaceId.Application)) {
            (c.cc as? io.kuicksilver.quic.Bbr)?.onAppLimited()
        }
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
        return c.sendHandshakeDone || c.path.challengePending || c.paths.hasResponseFor(c.path) || c.testInjectPathChallenges > 0 ||
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
            (c.datagramSender?.hasPending() == true && c.maxDatagramPayload > 0)
    }

    private fun wantsToSend(
        space: SpaceId,
        now: TimeMark,
    ): Boolean {
        if (c.spaceDiscarded[space.ordinal] || c.writeKeys[spaceLevel(space)] == null) return false
        if (c.closeFrame != null) return spaceLevel(space) != 1 && !c.closeSentIn[space.ordinal] // no CONNECTION_CLOSE (0x1c) in 0-RTT
        if (space == SpaceId.Initial && initialAckOnly) return hasAckToSend(space, now)
        if (spaceLevel(space) == 1) {
            return !congested && (c.streams.hasControlFrames() || c.streams.hasStreamData() || c.testInjectFrames.firstOrNull()?.first == 1)
        }
        if (hasAckToSend(space, now)) return true
        // path validation is not congestion controlled (RFC 9000 section 9.1): a rebind while the window is full must still be challenged
        if (space == SpaceId.Application && (c.path.challengePending || c.paths.hasResponseFor(c.path))) return true
        return !congested && hasData(space)
    }

    private fun buildDatagram(
        buf: PacketBuffer,
        maxLen: Int,
        now: TimeMark,
    ): Int {
        congested = c.cc.bytesInFlight >= c.cc.cwnd && c.probePending.all { it == 0 }
        initialAckOnly = c.role == TlsRole.Server && maxLen < 1200
        if (!congested) pacer(now)
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

    private fun pacer(now: TimeMark) {
        val t = c.pacer.nextSendTime(now, c.path.mtu, c.cc, c.rtt.smoothed)
        if (t != TimeMark.NEVER) {
            pacerWakeup = t
            congested = true
        }
    }

    private var lastWasAckEliciting = false

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
        val level = spaceLevel(space)
        val key = c.writeKeys[level] ?: return 0
        val sp = c.loss.space(space)
        if (maxLen - 16 - start < 48) return 0 // no room for a header, the sample and a frame
        val pn = sp.takePn(c.random)
        val pnLen = PacketNumbers.encodedLength(pn, sp.largestAcked)
        val w =
            writer?.also {
                it.buf = buf
                it.pos = start
                it.limit = maxLen - 16
            }
                ?: WireWriter(buf, start, maxLen - 16).also { writer = it }
        val type = packetType(space)
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
                    if (type == PacketType.Initial &&
                        c.role == TlsRole.Client
                    ) {
                        (c.retryToken ?: c.testInitialToken)
                    } else {
                        null
                    },
                    pnLen,
                    false,
                )
        } else {
            PacketHeaderCodec.writeShort(
                w,
                dcid,
                pnLen,
                spin = false,
                keyPhase = c.keyPhase?.phase ?: false,
                greaseFixedBit =
                    c.peerGreaseQuicBit && c.config.greaseQuicBit && c.random.nextBoolean(),
            )
        }
        val pnOff = w.pos
        w.zero(pnLen)
        val payloadStart = w.pos
        if (w.remaining < 4) return 0
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
            // the frame is what the closing state exists to deliver (RFC 9000 section 10.2.1): a reason that does not fit the room
            // left (an anti-amplification budget, section 8.1) is cut, on a character boundary (section 19.19), never the frame; a
            // packet without room even for a bare frame is not built, and the space still owes its copy
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
            if (target.challengePending &&
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
                    c.paths.takeResponseFor(target) ?: break
                FrameEncoder.pathResponse(w, r)
                frames.flags =
                    frames.flags or SentFrames.PATH_RESPONSE
                ackEliciting = true
                c.pathResponsesSentForTest++
            }
        } else {
            val a = sp.ack
            // a test probe (testInjectPathChallenges) carries no ACK: a probing-only packet, RFC 9000 section 9.1
            if (a.hasRanges && (hasAckToSend(space, now) || hasData(space)) &&
                c.testInjectPathChallenges == 0 && type != PacketType.ZeroRtt
            ) {
                val o = a.ackOverhead(now, c.config.ackDelayExponent)
                if (o <=
                    w.remaining
                ) {
                    a.writeAck(w, now, c.config.ackDelayExponent)
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
                    c.datagramSender?.let { s ->
                        val max = c.maxDatagramPayload
                        if (max > 0 &&
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
        val payloadEnd = w.pos
        if (lengthOff >= 0) VarInt.writeFixed(buf, lengthOff, (pnLen + (payloadEnd - payloadStart) + 16).toLong(), 2)
        val end = PacketProtection.protect(buf, start, pnOff, pnLen, payloadEnd, pn, key, mask)
        // RFC 9000 section 8.2.1: a challenge the amplification limit kept below 1200 bytes does not validate the path MTU
        if (frames.flags and SentFrames.PATH_CHALLENGE != 0 && end < 1200) target.markLastChallengeUndersized()
        if (type == PacketType.OneRtt) c.onOneRttPacketSealed(pn)
        p.zeroRtt = type == PacketType.ZeroRtt
        p.pn = pn
        p.timeSent = now
        p.size = end - start
        p.ackEliciting = ackEliciting
        p.inFlight =
            (ackEliciting || padded) && !pmtuProbe
        p.pathId = target.id.value
        p.addressEpoch = target.addressEpoch
        p.cc = target.cc // a PMTU probe is tracked for loss but never counts toward the window (RFC 9000 section 14.4)
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
