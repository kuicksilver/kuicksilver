// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.crypto.PacketProtection
import io.kuicksilver.quic.recovery.SpaceId
import io.kuicksilver.quic.stream.ReassemblyFull
import io.kuicksilver.quic.wire.AckFrameView
import io.kuicksilver.quic.wire.FrameDecoder
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.quic.wire.VersionNegotiationPacket
import io.kuicksilver.quic.wire.WireReader
import io.kuicksilver.tls.TlsRole

/** The receive path of a connection: header parsing, key selection, decryption, frames handed to [FrameDispatcher] (RFC 9000 sections 12–13). */
@OptIn(ExperimentalKuicksilverApi::class)
internal class PacketReceiver(
    private val c: ConnectionCore,
) {
    internal companion object {
        /**
         * The largest Retry token a client takes (RFC 9000 sections 17.2.5.2, 14.1): with 20-byte connection IDs its Initial still
         * leaves room for CRYPTO in 1200 bytes. A larger token cannot be sent, so its Retry is dropped.
         */
        const val MAX_RETRY_TOKEN = 1024
    }

    private val hv = PacketHeaderView()
    private val mask = ByteArray(5)
    private val ackView = AckFrameView()
    private val frames = FrameDispatcher(c, this)
    internal val reader = WireReader(PacketBuffer.allocate(1), 0, 0)
    internal var now = TimeMark(0)
    internal var space = SpaceId.Initial
    private var packetType = PacketType.Initial
    internal var level = 0

    /** A packet held for its keys, with the context of the datagram it arrived in (restored when it is fed again). */
    private class Buffered(
        val level: Int,
        val bytes: ByteArray,
        val from: InetSocketAddress,
        val socket: PathId,
        val ecn: io.kuicksilver.quic.Ecn,
        val datagramLength: Int,
    )

    private val buffered = ArrayList<Buffered>()
    val bufferedCount: Int get() = buffered.size

    /** Bytes of packets held for keys that have not arrived yet. */
    val bufferedBytes: Long get() {
        var n = 0L
        for (b in buffered) n += b.bytes.size
        return n
    }

    internal var socket: PathId = PathId.Initial
    internal var from: InetSocketAddress? = null
    internal var datagramLength = 0

    /** Datagrams handed to [onDatagram] so far: tells packets of one datagram from those of the next. */
    internal var datagramSeq = 0L
    private var datagramEcn: io.kuicksilver.quic.Ecn = io.kuicksilver.quic.Ecn.NotEct

    /** The accounting of a received datagram without looking inside it. */
    fun countOnly(
        length: Int,
        from: InetSocketAddress,
        socket: PathId,
    ) {
        c.bytesReceived += length
        c.paths
            .byRemote(socket, from)
            ?.amplification
            ?.onReceived(length) // per-path bytes; RFC 9000 sections 8.1 and 9.3.1: an unvalidated path has a 3x budget
    }

    fun onDatagram(
        data: PacketBuffer,
        length: Int,
        from: InetSocketAddress,
        socket: PathId,
        ecn: io.kuicksilver.quic.Ecn,
        now: TimeMark,
    ) {
        this.now = now
        this.socket = socket
        this.from = from
        datagramLength = length
        datagramSeq++
        if (c.role == TlsRole.Client && c.paths.byRemote(socket, from) == null) {
            c.datagramsDropped++
            return
        } // RFC 9000 section 9: a client discards packets from an unknown server address
        countOnly(length, from, socket)
        datagramEcn = ecn // a socket that cannot read marks delivers NotEct itself (ADR-0006)
        var off = 0
        var processed = false
        var firstDcidOff = -1
        var firstDcidLen = 0
        while (off < length) {
            if (!PacketHeaderCodec.parse(data, off, length, c.localCid.length, hv)) break
            if (firstDcidOff < 0) {
                firstDcidOff = hv.dcidOff
                firstDcidLen = hv.dcidLen
            } else if (!sameBytes(data, firstDcidOff, firstDcidLen, hv.dcidOff, hv.dcidLen)) {
                // RFC 9000 section 12.2: "Receivers SHOULD ignore any subsequent packets with a different Destination Connection ID
                // than the first packet in the datagram"
                if (hv.packetEnd <= off) break
                off = hv.packetEnd
                continue
            }
            if (hv.isVersionNegotiation) {
                if (c.localCid.contentEquals(data, hv.dcidOff, hv.dcidLen) &&
                    c.odcid.contentEquals(data, hv.scidOff, hv.scidLen)
                ) {
                    c.onVersionNegotiation(
                        VersionNegotiationPacket.versions(
                            data,
                            hv.scidOff + hv.scidLen,
                            length,
                        ),
                    )
                } else {
                    c.datagramsDropped++
                }
                return
            }
            if (hv.unsupportedVersion) break
            if (hv.type == PacketType.Initial && off == 0 && c.role == TlsRole.Server && length < 1200) return // RFC 9000 section 14.1
            if (processPacket(data, from)) processed = true
            if (hv.packetEnd <= off) break
            off = hv.packetEnd
        }
        if (!processed && length >= io.kuicksilver.quic.endpoint.StatelessReset.MIN_SIZE) {
            // RFC 9000 section 10.3: a reset looks like an undecryptable packet, and "endpoints MUST treat any packet ending in a valid
            // stateless reset token as a Stateless Reset, as other QUIC versions might allow the use of a long header"
            c.checkStatelessReset(data, length, now)
        }
    }

    private fun sameBytes(
        data: PacketBuffer,
        aOff: Int,
        aLen: Int,
        bOff: Int,
        bLen: Int,
    ): Boolean {
        if (aLen != bLen) return false
        for (i in 0 until aLen) if (data[aOff + i] != data[bOff + i]) return false
        return true
    }

    private fun matchesLocalCid(data: PacketBuffer): Boolean {
        if (c.localCid.contentEquals(data, hv.dcidOff, hv.dcidLen) || c.cids.localMatches(data, hv.dcidOff, hv.dcidLen)) return true
        if ((hv.type != PacketType.Initial && hv.type != PacketType.ZeroRtt) || c.role != TlsRole.Server) return false
        // RFC 9000 section 7.2: a client's Initials (and 0-RTT packets) carry the original DCID or, after a Retry, our Retry SCID
        return c.odcid.contentEquals(data, hv.dcidOff, hv.dcidLen) || c.retryScid?.contentEquals(data, hv.dcidOff, hv.dcidLen) == true
    }

    /** Returns true when the packet was decrypted and processed. */
    private fun processPacket(
        data: PacketBuffer,
        from: InetSocketAddress,
    ): Boolean {
        val type = hv.type ?: return false
        if (type == PacketType.Retry) {
            onRetry(data)
            return false
        }
        if (!matchesLocalCid(data)) return false
        // RFC 9000 section 7.2: after the server's first Initial its Source Connection ID is fixed; a long-header packet with another one belongs to a stranger
        // (msquic answers a retransmitted Initial from a second connection instance) and is discarded before any key is tried
        if (c.role == TlsRole.Client && type != PacketType.OneRtt && remoteCidSet &&
            peerScid?.contentEquals(data, hv.scidOff, hv.scidLen) == false
        ) {
            // msquic acknowledges the ClientHello from an Initial whose SCID is still the client's DCID and chooses its own only with the ServerHello: until Initial CRYPTO arrived, a new SCID is adopted, not discarded
            if (initialCryptoSeen) {
                c.datagramsDropped++
                return false
            }
            remoteCidSet = false
            c.loss
                .space(SpaceId.Initial)
                .ack
                .forgetAll() // what the provisional instance sent is not ours to acknowledge
        }
        space =
            when (type) {
                PacketType.Initial -> SpaceId.Initial
                PacketType.Handshake -> SpaceId.Handshake
                else -> SpaceId.Application
            }
        level =
            when (type) {
                PacketType.Initial -> 0
                PacketType.ZeroRtt -> 1
                PacketType.Handshake -> 2
                else -> 3
            }
        packetType = type
        if (c.spaceDiscarded[space.ordinal]) return false
        // RFC 9000 section 17.2/17.3.1: not a valid packet of this version unless we allowed it (RFC 9287)
        if (!hv.fixedBitSet && !c.config.greaseQuicBit) return false
        // section 17.2.2: a server Initial carries no token
        if (type == PacketType.Initial && c.role == TlsRole.Client && hv.tokenLen != 0) return false
        // the preferred socket carries 1-RTT packets of connections that moved there, nothing else (RFC 9000 section 9.6)
        if (socket == io.kuicksilver.quic.PREFERRED_SOCKET && type != PacketType.OneRtt) return false
        // migration off, or to loopback/link-local (threat-model 3.14)
        if (type == PacketType.OneRtt && c.role == TlsRole.Server && !c.path.isRemote(from) && !c.migrationAllowedFrom(from)) return false
        // RFC 9369 section 4.1: a server takes 0-RTT only in the original version, whatever the negotiated one
        if (type == PacketType.ZeroRtt && hv.version != c.originalVersion.version) return false
        if (type != PacketType.OneRtt && hv.version != c.version.version) {
            val profile = VersionProfile.of(hv.version) ?: return false
            if (c.role == TlsRole.Client) {
                if (!c.switchClientVersion(profile)) return false
            } else if (!((type == PacketType.Initial || type == PacketType.ZeroRtt) && hv.version == c.originalVersion.version)) {
                return false
            }
        }
        val key =
            if (type == PacketType.Initial && c.role == TlsRole.Server && hv.version == c.originalVersion.version &&
                c.initialReadOriginal != null
            ) {
                c.initialReadOriginal
            } else {
                c.readKeys[level]
            }
        if (key == null) {
            // 0-RTT waits for its key only on a server that accepts it, and only until the handshake shows whether it was accepted
            if (type == PacketType.ZeroRtt &&
                (c.role != TlsRole.Server || c.serverEarly == null || c.state != ConnectionState.Handshaking)
            ) {
                return false
            }
            if (buffered.size >= c.config.limits.undecryptablePackets) {
                c.datagramsDropped++
                return false
            }
            val bytes = ByteArray(hv.packetEnd - hv.pnOffset + (hv.pnOffset - headerStart()))
            val start = headerStart()
            data.copyTo(bytes, start, 0, bytes.size)
            buffered += Buffered(level, bytes, from, socket, datagramEcn, datagramLength)
            return false
        }
        val sp = c.loss.space(space)
        val kp = if (type == PacketType.OneRtt) c.keyPhase else null
        val pn: Long
        if (kp != null) {
            // RFC 9001 section 6: header protection first (its key never changes), then the Key Phase bit picks the AEAD key
            pn =
                PacketProtection.removeHeaderProtection(
                    data,
                    headerStart(),
                    hv.pnOffset,
                    hv.packetEnd,
                    sp.ack.largestReceived,
                    kp.hpRead,
                    mask,
                )
            if (pn < 0) return false
            val bit = data[headerStart()].toInt() and 0x04 != 0
            val aead = kp.readKey(bit, pn) ?: return false
            if (!PacketProtection.openPayload(data, headerStart(), hv.pnOffset, hv.packetEnd, pn, aead)) {
                c.onAuthenticationFailure(aead.aead)
                return false
                // discarded silently (RFC 9000 section 12.2): anyone who sees a connection ID can forge these, so they must not spend glitch
                // tokens
            }
            try {
                kp.onAuthenticated(bit, pn, now, c.pto())
            } catch (
                e: QuicWireException,
            ) {
                c.fail(e.code, e.frameType, e.message ?: "", e)
                return true
            }
        } else {
            pn = PacketProtection.removeHeaderProtection(data, headerStart(), hv.pnOffset, hv.packetEnd, sp.ack.largestReceived, key, mask)
            if (pn < 0) return false
            if (!PacketProtection.openPayload(data, headerStart(), hv.pnOffset, hv.packetEnd, pn, key)) {
                if (type !=
                    PacketType.Initial
                ) {
                    c.onAuthenticationFailure(key.aead)
                }
                return false
            }
        }
        if (sp.ack.isDuplicate(pn)) {
            c.duplicatesDropped++
            return false
        }
        if (data[headerStart()].toInt() and (if (type == PacketType.OneRtt) 0x18 else 0x0c) !=
            0
        ) {
            c.fail(TransportError.PROTOCOL_VIOLATION, 0, "reserved header bits set", null)
            return true
        } // sections 17.2 and 17.3.1: checked once both protections are off
        val pnLen = (data[headerStart()].toInt() and 0x03) + 1
        reader.buf = data
        reader.pos = hv.pnOffset + pnLen
        reader.limit = hv.packetEnd - 16
        if (c.role == TlsRole.Client && type == PacketType.Initial &&
            !remoteCidSet
        ) {
            val scid =
                io.kuicksilver.quic.wire
                    .ConnectionId(ByteArray(hv.scidLen).also { data.copyTo(it, hv.scidOff, 0, hv.scidLen) })
            c.onPeerInitialCid(scid)
            peerScid =
                scid
            remoteCidSet = true
        }
        c.anyPeerPacket = true
        c.timers.lastActivity = now
        c.timers.ackElicitingSentSinceReceive = false
        if (c.path.isRemote(from) && socket == c.path.socket) {
            c.lastReceivedOnActivePath = now
        } else if ((type == PacketType.Initial || type == PacketType.Handshake) && c.role == TlsRole.Server &&
            c.state == ConnectionState.Handshaking
        ) {
            // only the highest-numbered packet of its space moves the path: a delayed older one from the old address does not move it
            // back (RFC 9000 section 9.3); every one counts toward its address's budget until a failed move freezes the path (then no
            // other address matters before the handshake completes)
            c.onHandshakeAddressChange(
                socket,
                from,
                datagramLength,
                datagramSeq,
                initial = type == PacketType.Initial,
                newest = pn > sp.ack.largestReceived,
            ) // a NAT rebinding in the middle of the handshake (interop rebind cases)
        }
        // which of our IDs the peer used: a server answers a new address with its current ID only if that did not change (RFC 9000
        // section 9.5)
        if (type == PacketType.OneRtt && c.role == TlsRole.Server) c.rxDcidSeq = c.cids.localSeqOf(data, hv.dcidOff, hv.dcidLen)
        val ackEliciting =
            try {
                FrameDecoder.decode(reader, type, frames, ackView)
            } catch (_: ReassemblyFull) {
                // not acknowledged, so the peer resends its frames in a new packet (RFC 9000 section 13.1: all frames must be
                // processed before a packet is acknowledged). The frames ahead of the refused one were applied (a DATAGRAM delivered, a
                // PATH_CHALLENGE answered): the packet number counts as seen, so a duplicate or a replay is not processed again (section
                // 12.3). Refusing the packet before any frame runs would need the whole packet decoded twice, and a STREAM frame
                // ahead in the same packet may free or take the room a later one needs.
                sp.ack.onPacketRefused(pn)
                c.datagramsDropped++
                return true
            } catch (e: QuicWireException) {
                // RFC 9000 section 19.19: "the type of frame that triggered the error"; the stream and flow-control layers below the
                // dispatcher do not know which frame called them, the decoder does
                val frameType = if (reader.frameType != 0L) reader.frameType else e.frameType
                c.fail(
                    e.code,
                    frameType,
                    e.message ?: "",
                    e,
                )
                return true
            }
        c.packetsReceived++
        c.qlog?.packetReceived(space, pn, hv.packetEnd - headerStart(), now)
        sp.ack.onEcn(datagramEcn) // RFC 9000 section 13.4.1 / 21.10: only processed packets move the ECN counts
        // PING-only packets beyond a PTO pair (RFC 9002 section 6.2.4: two probes, both PING when nothing is left to resend) within one RTT
        // are a glitch
        if (type == PacketType.OneRtt && reader.pingOnly) {
            if (lastPingOnly == TimeMark.NEVER || now - lastPingOnly >= c.rtt.smoothed) {
                lastPingOnly = now
                pingOnlyInRtt = 1
            } else if (++pingOnlyInRtt >
                2
            ) {
                try {
                    c.glitch(0x01)
                } catch (e: QuicWireException) {
                    c.fail(e.code, e.frameType, e.message ?: "", e)
                    return true
                }
            }
        }
        sp.ack.onPacketReceived(pn, ackEliciting, now, ce = datagramEcn == io.kuicksilver.quic.Ecn.Ce)
        if (type == PacketType.Handshake &&
            c.role == TlsRole.Server
        ) {
            c.onInitialPathValidated(from)
            if (!c.spaceDiscarded[0]) c.discardInitialPending = true
        }
        if (type == PacketType.OneRtt) {
            c.onPathPacket(socket, from, pn, !reader.probingOnly, datagramLength)
            c.onFirstOneRttFromClient()
        }
        return true
    }

    private var remoteCidSet = c.role == TlsRole.Server

    /** The server's Source Connection ID taken from its first Initial (client only); later long-header packets must carry it. */
    private var peerScid: io.kuicksilver.quic.wire.ConnectionId? = null

    /** True once an Initial packet with CRYPTO data was processed: from then on the peer's SCID is final (RFC 9000 section 7.2). */
    internal var initialCryptoSeen = false
    private var lastPingOnly: TimeMark = TimeMark.NEVER
    private var pingOnlyInRtt = 0

    /** RFC 9000 section 17.2.5.2: a client takes exactly one Retry, before any other server packet, with a non-empty token, a new SCID and a valid tag (RFC 9001 section 5.8). */
    private fun onRetry(data: PacketBuffer) {
        if (c.role != TlsRole.Client || c.anyPeerPacket || c.retryScid != null || c.state != ConnectionState.Handshaking) return
        // RFC 9369 section 4.1: a Retry uses the version of the Initial it answers; "The client ignores Retry packets using other versions."
        if (hv.version != c.version.version) return
        if (!c.localCid.contentEquals(data, hv.dcidOff, hv.dcidLen) || hv.tokenLen == 0) return
        // the token rides in every later Initial: one that cannot fit a 1200-byte Initial with room for CRYPTO is unusable
        if (hv.tokenLen > MAX_RETRY_TOKEN) return
        if (c.odcid.contentEquals(data, hv.scidOff, hv.scidLen)) return
        if (!io.kuicksilver.quic.wire.RetryPacket
                .verify(data, headerStart(), hv.packetEnd, c.odcid, c.crypto)
        ) {
            return
        }
        val scid =
            io.kuicksilver.quic.wire
                .ConnectionId(ByteArray(hv.scidLen).also { data.copyTo(it, hv.scidOff, 0, hv.scidLen) })
        val token = ByteArray(hv.tokenLen).also { data.copyTo(it, hv.tokenOff, 0, hv.tokenLen) }
        c.onRetry(scid, token)
        c.tlsDirty = true
    }

    private fun headerStart(): Int = if (hv.type == PacketType.OneRtt) hv.dcidOff - 1 else hv.dcidOff - 6

    /**
     * Packets kept until their keys arrived are fed again (they already counted toward the amplification budget). Each one is processed
     * under the socket, source, ECN mark and length of its own datagram, not of the datagram that brought the keys (RFC 9000 section
     * 13.4.1: the ECN counts follow the datagram the packet arrived in); the current datagram's context is restored afterwards.
     */
    fun replayBuffered(level: Int) {
        if (buffered.none { it.level == level }) return
        val again = buffered.filter { it.level == level }
        buffered.removeAll { it.level == level }
        val savedSocket = socket
        val savedFrom = from
        val savedLength = datagramLength
        val savedEcn = datagramEcn
        try {
            for (b in again) {
                val buf = PacketBuffer.allocate(b.bytes.size)
                try {
                    buf.copyFrom(b.bytes, 0, 0, b.bytes.size)
                    socket = b.socket
                    from = b.from
                    datagramLength = b.datagramLength
                    datagramEcn = b.ecn
                    var off = 0
                    while (off <
                        b.bytes.size
                    ) {
                        if (!PacketHeaderCodec.parse(buf, off, b.bytes.size, c.localCid.length, hv)) break
                        processPacket(buf, b.from)
                        if (hv.packetEnd <=
                            off
                        ) {
                            break
                        }
                        off = hv.packetEnd
                    }
                } finally {
                    buf.close()
                }
            }
        } finally {
            socket = savedSocket
            from = savedFrom
            datagramLength = savedLength
            datagramEcn = savedEcn
        }
    }

    /** After a Version Negotiation restart: forget buffered packets and the peer CID learned so far. */
    fun reset() {
        buffered.clear()
        remoteCidSet = c.role == TlsRole.Server
        peerScid = null
        initialCryptoSeen = false
    }

    /** Whether the packet being decoded is a 0-RTT one (its STREAM frames mark their streams as received early). */
    internal val inZeroRtt: Boolean get() = packetType == PacketType.ZeroRtt

    fun dropBufferedLevel(level: Int) {
        buffered.removeAll { it.level == level }
    }

    fun dropBuffered(space: SpaceId) {
        val level =
            if (space ==
                SpaceId.Initial
            ) {
                0
            } else if (space == SpaceId.Handshake) {
                2
            } else {
                3
            }
        ; buffered.removeAll { it.level == level }
    }
}
