// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kuicksilver.quic.TransportError

/** Frame types of RFC 9000 section 19 and RFC 9221. */
internal object FrameType {
    const val PADDING = 0x00L
    const val PING = 0x01L
    const val ACK = 0x02L
    const val ACK_ECN = 0x03L
    const val RESET_STREAM = 0x04L
    const val STOP_SENDING = 0x05L
    const val CRYPTO = 0x06L
    const val NEW_TOKEN = 0x07L
    const val STREAM = 0x08L
    const val MAX_DATA = 0x10L
    const val MAX_STREAM_DATA = 0x11L
    const val MAX_STREAMS_BIDI = 0x12L
    const val MAX_STREAMS_UNI = 0x13L
    const val DATA_BLOCKED = 0x14L
    const val STREAM_DATA_BLOCKED = 0x15L
    const val STREAMS_BLOCKED_BIDI = 0x16L
    const val STREAMS_BLOCKED_UNI = 0x17L
    const val NEW_CONNECTION_ID = 0x18L
    const val RETIRE_CONNECTION_ID = 0x19L
    const val PATH_CHALLENGE = 0x1aL
    const val PATH_RESPONSE = 0x1bL
    const val CONNECTION_CLOSE = 0x1cL
    const val CONNECTION_CLOSE_APP = 0x1dL
    const val HANDSHAKE_DONE = 0x1eL
    const val DATAGRAM = 0x30L
    const val DATAGRAM_LEN = 0x31L
    const val MAX_STREAMS_LIMIT: Long = 1L shl 60
}

/** Decodes the frames of one packet payload (RFC 9000 section 12.4) into a [FrameHandler] without allocating per frame. */
internal object FrameDecoder {
    private const val I = 1
    private const val Z = 2
    private const val H = 4
    private const val O = 8

    private fun allowedIn(type: Long): Int =
        when (type) {
            FrameType.PADDING, FrameType.PING, FrameType.CONNECTION_CLOSE -> I or Z or H or O

            FrameType.ACK, FrameType.ACK_ECN, FrameType.CRYPTO -> I or H or O

            FrameType.NEW_TOKEN, FrameType.PATH_RESPONSE, FrameType.HANDSHAKE_DONE -> O

            in FrameType.STREAM..0x0fL,
            FrameType.RESET_STREAM,
            FrameType.STOP_SENDING,
            FrameType.MAX_DATA,
            FrameType.MAX_STREAM_DATA,
            FrameType.MAX_STREAMS_BIDI,
            FrameType.MAX_STREAMS_UNI,
            FrameType.DATA_BLOCKED,
            FrameType.STREAM_DATA_BLOCKED,
            FrameType.STREAMS_BLOCKED_BIDI,
            FrameType.STREAMS_BLOCKED_UNI,
            FrameType.NEW_CONNECTION_ID,
            FrameType.RETIRE_CONNECTION_ID,
            FrameType.PATH_CHALLENGE, FrameType.CONNECTION_CLOSE_APP, FrameType.DATAGRAM, FrameType.DATAGRAM_LEN,
            -> Z or O

            else -> 0
        }

    private fun bit(packet: PacketType): Int =
        when (packet) {
            PacketType.Initial -> I
            PacketType.ZeroRtt -> Z
            PacketType.Handshake -> H
            PacketType.OneRtt -> O
            PacketType.Retry -> 0
        }

    private val sharedView = AckFrameView() // for single-threaded callers (tests); each receiver passes its own view

    /** Decodes every frame in [r]; returns true when the packet is ack-eliciting. [ackView] is reused for ACK frames and must belong to the caller. */
    fun decode(
        r: WireReader,
        packet: PacketType,
        h: FrameHandler,
        ackView: AckFrameView = sharedView,
    ): Boolean {
        if (r.remaining == 0) throw QuicWireException(TransportError.PROTOCOL_VIOLATION, 0, "packet without frames")
        val allowedBit = bit(packet)
        var ackEliciting = false
        var pings = 0
        var others = 0
        var nonProbing = 0
        while (r.remaining > 0) {
            r.frameType = 0
            val type = r.varint()
            r.frameType = type
            when (type) {
                FrameType.PADDING, FrameType.ACK, FrameType.ACK_ECN -> {}

                FrameType.PING -> {
                    pings++
                }

                else -> {
                    others++
                }
            }
            when (type) {
                FrameType.PADDING, FrameType.PATH_CHALLENGE, FrameType.PATH_RESPONSE, FrameType.NEW_CONNECTION_ID -> {}

                else -> {
                    nonProbing++
                }
            }
            val mask = allowedIn(type)
            if (mask == 0) throw QuicWireException(TransportError.FRAME_ENCODING_ERROR, type, "unknown frame type 0x${type.toString(16)}")
            if (mask and allowedBit ==
                0
            ) {
                throw QuicWireException(TransportError.PROTOCOL_VIOLATION, type, "frame 0x${type.toString(16)} not allowed in $packet")
            }
            when (type) {
                FrameType.PADDING -> {
                    var n = 1
                    while (r.remaining > 0 && r.buf[r.pos].toInt() == 0) {
                        r.pos++
                        n++
                    }
                    h.padding(n)
                }

                FrameType.PING -> {
                    ackEliciting = true
                    h.ping()
                }

                FrameType.ACK, FrameType.ACK_ECN -> {
                    val v = ackView
                    v.reset()
                    v.largest = r.varint()
                    v.ackDelay = r.varint()
                    val count = r.varint()
                    val first = r.varint()
                    var smallest = v.largest - first
                    if (first > v.largest) throw QuicWireException(TransportError.FRAME_ENCODING_ERROR, type, "ack range below zero")
                    v.addRange(smallest, v.largest)
                    var i = 0L
                    while (i < count) {
                        val gap = r.varint()
                        val len = r.varint()
                        val largest = smallest - gap - 2
                        if (largest < 0 ||
                            len > largest
                        ) {
                            throw QuicWireException(TransportError.FRAME_ENCODING_ERROR, type, "ack range below zero")
                        }
                        smallest = largest - len
                        v.addRange(smallest, largest)
                        i++
                    }
                    if (type == FrameType.ACK_ECN) v.setEcn(r.varint(), r.varint(), r.varint())
                    h.ack(v)
                }

                FrameType.RESET_STREAM -> {
                    ackEliciting = true
                    h.resetStream(r.varint(), r.varint(), r.varint())
                }

                FrameType.STOP_SENDING -> {
                    ackEliciting = true
                    h.stopSending(r.varint(), r.varint())
                }

                FrameType.CRYPTO -> {
                    ackEliciting = true
                    val off = r.varint()
                    val len = r.length()
                    if (off + len >
                        VarInt.MAX
                    ) {
                        throw QuicWireException(TransportError.FRAME_ENCODING_ERROR, type, "crypto offset overflow")
                    }
                    val p = r.pos
                    r.pos +=
                        len
                    h.crypto(off, r.buf, p, len)
                }

                FrameType.NEW_TOKEN -> {
                    ackEliciting = true
                    val len = r.length()
                    if (len ==
                        0
                    ) {
                        throw QuicWireException(TransportError.FRAME_ENCODING_ERROR, type, "empty token")
                    }
                    val p = r.pos
                    r.pos += len
                    h.newToken(r.buf, p, len)
                }

                in FrameType.STREAM..0x0fL -> {
                    ackEliciting = true
                    val id = r.varint()
                    val off = if (type and 0x04L != 0L) r.varint() else 0L
                    val len = if (type and 0x02L != 0L) r.length() else r.remaining
                    if (off + len > VarInt.MAX) throw QuicWireException(TransportError.FRAME_ENCODING_ERROR, type, "stream offset overflow")
                    val p = r.pos
                    r.pos += len
                    h.stream(id, off, r.buf, p, len, type and 0x01L != 0L)
                }

                FrameType.MAX_DATA -> {
                    ackEliciting = true
                    h.maxData(r.varint())
                }

                FrameType.MAX_STREAM_DATA -> {
                    ackEliciting = true
                    h.maxStreamData(r.varint(), r.varint())
                }

                FrameType.MAX_STREAMS_BIDI, FrameType.MAX_STREAMS_UNI -> {
                    ackEliciting = true
                    val m = r.varint()
                    if (m >
                        FrameType.MAX_STREAMS_LIMIT
                    ) {
                        throw QuicWireException(TransportError.FRAME_ENCODING_ERROR, type, "max streams above 2^60")
                    }
                    h.maxStreams(type == FrameType.MAX_STREAMS_BIDI, m)
                }

                FrameType.DATA_BLOCKED -> {
                    ackEliciting = true
                    h.dataBlocked(r.varint())
                }

                FrameType.STREAM_DATA_BLOCKED -> {
                    ackEliciting = true
                    h.streamDataBlocked(r.varint(), r.varint())
                }

                FrameType.STREAMS_BLOCKED_BIDI, FrameType.STREAMS_BLOCKED_UNI -> {
                    ackEliciting = true
                    val m = r.varint()
                    if (m >
                        FrameType.MAX_STREAMS_LIMIT
                    ) {
                        throw QuicWireException(TransportError.FRAME_ENCODING_ERROR, type, "streams blocked above 2^60")
                    }
                    h.streamsBlocked(type == FrameType.STREAMS_BLOCKED_BIDI, m)
                }

                FrameType.NEW_CONNECTION_ID -> {
                    ackEliciting = true
                    val seq = r.varint()
                    val retire = r.varint()
                    val len = r.u8()
                    if (retire > seq) throw QuicWireException(TransportError.FRAME_ENCODING_ERROR, type, "retire_prior_to above sequence")
                    if (len < 1 || len > 20) throw QuicWireException(TransportError.FRAME_ENCODING_ERROR, type, "connection id length $len")
                    r.require(len + 16)
                    val p = r.pos
                    r.pos += len + 16
                    h.newConnectionId(seq, retire, r.buf, p, len, p + len)
                }

                FrameType.RETIRE_CONNECTION_ID -> {
                    ackEliciting = true
                    h.retireConnectionId(r.varint())
                }

                FrameType.PATH_CHALLENGE -> {
                    ackEliciting = true
                    h.pathChallenge(r.u64())
                }

                FrameType.PATH_RESPONSE -> {
                    ackEliciting = true
                    h.pathResponse(r.u64())
                }

                FrameType.CONNECTION_CLOSE, FrameType.CONNECTION_CLOSE_APP -> {
                    val app = type == FrameType.CONNECTION_CLOSE_APP
                    val code = r.varint()
                    val ft = if (app) 0L else r.varint()
                    val len = r.length()
                    val p = r.pos
                    r.pos += len
                    h.connectionClose(app, code, ft, r.buf, p, len)
                }

                FrameType.HANDSHAKE_DONE -> {
                    ackEliciting = true
                    h.handshakeDone()
                }

                FrameType.DATAGRAM, FrameType.DATAGRAM_LEN -> {
                    ackEliciting = true
                    val len =
                        if (type ==
                            FrameType.DATAGRAM_LEN
                        ) {
                            r.length()
                        } else {
                            r.remaining
                        }
                    ; val p = r.pos
                    r.pos += len
                    h.datagram(r.buf, p, len)
                }
            }
        }
        r.pingOnly = pings > 0 && others == 0
        r.probingOnly = nonProbing == 0
        return ackEliciting
    }
}
