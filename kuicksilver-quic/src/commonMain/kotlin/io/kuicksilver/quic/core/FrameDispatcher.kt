// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.wire.AckFrameView
import io.kuicksilver.quic.wire.FrameHandler
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.tls.TlsRole

/** Frame dispatch of the receive path: each decoded frame of a [PacketReceiver] packet goes to its handler in the connection (RFC 9000 section 12.4). */
@OptIn(ExperimentalKuicksilverApi::class)
internal class FrameDispatcher(
    private val c: ConnectionCore,
    private val r: PacketReceiver,
) : FrameHandler {
    private var lastDataBlocked = -1L
    private var lastStreamDataBlockedId = -1L
    private var lastStreamDataBlockedLimit = -1L
    private val lastStreamsBlocked = longArrayOf(-1L, -1L)

    private fun violation(msg: String): Nothing = throw QuicWireException(TransportError.PROTOCOL_VIOLATION, r.reader.frameType, msg)

    override fun padding(count: Int) {}

    override fun ping() {}

    override fun ack(ack: AckFrameView) {
        c.loss.onAck(r.space, ack, r.now)
        c.checkPmtuBlackHoles()
    }

    override fun resetStream(
        id: Long,
        code: Long,
        finalSize: Long,
    ) {
        c.streams.onResetStream(id, code, finalSize)
    }

    override fun stopSending(
        id: Long,
        code: Long,
    ) {
        c.streams.onStopSending(id, code)
    }

    override fun crypto(
        offset: Long,
        data: PacketBuffer,
        off: Int,
        len: Int,
    ) {
        if (r.level == 0) r.initialCryptoSeen = true
        c.cryptoStreams.onData(r.level, offset, data, off, len, c.handshake.done)
        c.cryptoStreams.deliver(r.level) { bytes, n ->
            c.handshake.provide(r.level, bytes, n)
            c.tlsDirty = true
        }
    }

    override fun newToken(
        token: PacketBuffer,
        off: Int,
        len: Int,
    ) {
        if (c.role == TlsRole.Server) violation("NEW_TOKEN from a client")
    }

    // ---- glitches: frames that cost work and change nothing spend a token (RFC 9000 section 21.9); duplicate STREAM/CRYPTO data does not: an honest sender
    // retransmits what a lost ACK left unconfirmed (RFC 9002 section 6.2.4), and a 10 MiB transfer at 5% loss showed hundreds of such repeats ----
    override fun stream(
        id: Long,
        offset: Long,
        data: PacketBuffer,
        off: Int,
        len: Int,
        fin: Boolean,
    ) {
        c.streams.onStream(id, offset, data, off, len, fin)
        if (r.inZeroRtt) c.streams.markReceivedEarly(id)
    }

    // a MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS that raises nothing is an honest retransmission or reordering (quic-go repeats MAX_STREAMS per packet until acknowledged: 1040 of them in one multiplexing run); it costs nothing and spends nothing
    override fun maxData(max: Long) {
        c.streams.onMaxData(max)
    }

    override fun maxStreamData(
        id: Long,
        max: Long,
    ) {
        c.streams.onMaxStreamData(id, max)
    }

    override fun maxStreams(
        bidi: Boolean,
        max: Long,
    ) {
        c.streams.onMaxStreams(bidi, max)
    }

    override fun dataBlocked(limit: Long) {
        if (limit == lastDataBlocked) c.glitch(0x14)
        lastDataBlocked = limit
    }

    override fun streamDataBlocked(
        id: Long,
        limit: Long,
    ) {
        if (id == lastStreamDataBlockedId &&
            limit == lastStreamDataBlockedLimit
        ) {
            c.glitch(0x15)
        }
        lastStreamDataBlockedId = id
        lastStreamDataBlockedLimit = limit
    }

    override fun streamsBlocked(
        bidi: Boolean,
        limit: Long,
    ) {
        val i = if (bidi) 0 else 1
        if (limit ==
            lastStreamsBlocked[i]
        ) {
            c.glitch(r.reader.frameType)
        }
        lastStreamsBlocked[i] = limit
        c.streams.onStreamsBlocked(bidi, limit)
    }

    override fun newConnectionId(
        seq: Long,
        retirePriorTo: Long,
        cid: PacketBuffer,
        cidOff: Int,
        cidLen: Int,
        resetTokenOff: Int,
    ) {
        c.onNewConnectionId(seq, retirePriorTo, cid, cidOff, cidLen, resetTokenOff)
    }

    override fun retireConnectionId(seq: Long) {
        c.onRetireConnectionId(seq)
    }

    override fun pathChallenge(data: Long) {
        c.onPathChallenge(data, r.socket, r.from!!, r.datagramLength)
    }

    override fun pathResponse(data: Long) {
        c.onPathResponse(data)
    }

    override fun connectionClose(
        application: Boolean,
        code: Long,
        frameType: Long,
        reason: PacketBuffer,
        off: Int,
        len: Int,
    ) {
        val bytes = ByteArray(minOf(len, 1024))
        reason.copyTo(bytes, off, 0, bytes.size)
        c.peerClosed(application, code, frameType, bytes)
    }

    override fun handshakeDone() {
        if (c.role == TlsRole.Server) violation("HANDSHAKE_DONE from a client")
        if (!c.handshakeDoneReceived) {
            c.handshakeDoneReceived = true
            c.confirmHandshake()
        }
    }

    override fun datagram(
        data: PacketBuffer,
        off: Int,
        len: Int,
    ) {
        val max = c.config.maxDatagramFrameSize
        if (max == 0L) violation("DATAGRAM frame without max_datagram_frame_size")
        val lengthField =
            if (r.reader.frameType == 0x31L) {
                io.kuicksilver.quic.wire.VarInt
                    .size(len.toLong())
            } else {
                0 // type 0x30 has no Length field
            }
        // RFC 9221 section 3: the whole frame, header included
        if (len + 1 + lengthField > max) violation("DATAGRAM frame larger than our max_datagram_frame_size $max")
        c.onDatagramFrame(data, off, len)
    }
}
