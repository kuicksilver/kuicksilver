// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.qlog

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.wire.AckFrameView
import io.kuicksilver.quic.wire.FrameDecoder
import io.kuicksilver.quic.wire.FrameHandler
import io.kuicksilver.quic.wire.FrameType
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.WireReader

/**
 * The frames of one packet as qlog QuicFrame objects (draft-ietf-quic-qlog-quic-events-04 section 8.11), for the
 * `frames` of `transport:packet_sent` and `packet_received`. Only a traced connection has one ([QlogWriter]).
 *
 * Sent packets: [sent] decodes the plaintext payload the packet builder wrote, before it is sealed, so the trace shows
 * every frame as it went on the wire whatever part of the builder wrote it. Received packets: [receiving] puts this
 * handler in front of the connection's own, recording each frame as the decoder hands it over.
 *
 * What is never written: STREAM, CRYPTO and DATAGRAM payloads (their offsets and lengths are), the stateless reset token
 * of a NEW_CONNECTION_ID (optional in section 8.11.15; whoever holds it can end the connection), and the bytes of a
 * NEW_TOKEN's token (section 8.8 makes them optional; a token lets its holder skip address validation), which is logged
 * by its length. Connection IDs are written: section 8.11.15 requires them, and they travel in clear in packet headers.
 * Everything here appends to one reused builder: a traced connection allocates per packet only the event's string, an
 * untraced one runs none of it.
 */
internal class QlogFrames : FrameHandler {
    val out = StringBuilder(256)
    private var first = true
    private var delegate: FrameHandler? = null
    private var ackDelayExponent = 3
    private val reader = WireReader(NO_BYTES, 0, 0)
    private val ackView = AckFrameView()

    /** Whether [out] holds the frames of the packet being logged (a decode that failed leaves it false). */
    var ready = false
        private set

    private fun begin(exponent: Int) {
        out.setLength(0)
        first = true
        ackDelayExponent = exponent
        ready = false
    }

    /**
     * The frames of a packet we built, from its plaintext payload `[from, to)` in [buf]; [exponent] is our
     * `ack_delay_exponent`. A payload the decoder refuses (none should be) leaves no frames.
     */
    fun sent(
        buf: PacketBuffer,
        from: Int,
        to: Int,
        type: PacketType,
        exponent: Int,
    ) {
        begin(exponent)
        delegate = null
        reader.buf = buf
        reader.pos = from
        reader.limit = to
        try {
            FrameDecoder.decode(reader, type, this, ackView)
            ready = true
        } catch (_: Exception) {
            out.setLength(0)
        }
    }

    /** This handler in front of [h] for one received packet; [exponent] is the peer's `ack_delay_exponent`. */
    fun receiving(
        h: FrameHandler,
        exponent: Int,
    ): FrameHandler {
        begin(exponent)
        delegate = h
        ready = true
        return this
    }

    /** A received packet's decode failed: what was recorded is not logged. */
    fun abandon() {
        ready = false
        out.setLength(0)
    }

    private fun open(type: String): StringBuilder {
        if (!first) out.append(',')
        first = false
        return out.append("{\"frame_type\":\"").append(type).append('"')
    }

    private fun StringBuilder.num(
        key: String,
        v: Long,
    ): StringBuilder = append(",\"").append(key).append("\":").append(v)

    override fun padding(count: Int) {
        // section 8.11.1: one PaddingFrame for the packet's PADDING, its byte count in payload_length
        open("padding").num("payload_length", count.toLong()).append('}')
        delegate?.padding(count)
    }

    override fun ping() {
        open("ping").append('}')
        delegate?.ping()
    }

    override fun ack(ack: AckFrameView) {
        val o = open("ack")
        // ack_delay in ms: the field times 2^ack_delay_exponent microseconds (RFC 9000 section 19.3)
        val micros = if (ack.ackDelay > Long.MAX_VALUE shr 20) Long.MAX_VALUE else ack.ackDelay shl ackDelayExponent
        o
            .append(",\"ack_delay\":")
            .append(micros / 1000)
            .append('.')
            .append((micros % 1000).toString().padStart(3, '0'))
        o.append(",\"acked_ranges\":[")
        for (i in 0 until ack.rangeCount) {
            if (i > 0) o.append(',')
            val lo = ack.smallest(i)
            val hi = ack.largest(i)
            // section 8.11.3: "[120,120] ... implementers SHOULD log [120] instead"
            if (lo == hi) {
                o.append('[').append(lo).append(']')
            } else {
                o
                    .append('[')
                    .append(lo)
                    .append(',')
                    .append(hi)
                    .append(']')
            }
        }
        o.append(']')
        ack.ecn?.let { e -> o.num("ect0", e[0]).num("ect1", e[1]).num("ce", e[2]) }
        o.append('}')
        delegate?.ack(ack)
    }

    override fun resetStream(
        id: Long,
        code: Long,
        finalSize: Long,
    ) {
        val o = open("reset_stream").num("stream_id", id)
        applicationError(o, "error_code", code).num("final_size", finalSize).append('}')
        delegate?.resetStream(id, code, finalSize)
    }

    override fun stopSending(
        id: Long,
        code: Long,
    ) {
        applicationError(open("stop_sending").num("stream_id", id), "error_code", code).append('}')
        delegate?.stopSending(id, code)
    }

    override fun resetStreamAt(
        id: Long,
        code: Long,
        finalSize: Long,
        reliableSize: Long,
    ) {
        // draft-ietf-quic-reliable-stream-reset: a frame type through the $QuicFrame extension point (section 8.11)
        val o = open("reset_stream_at").num("stream_id", id)
        applicationError(o, "error_code", code).num("final_size", finalSize).num("reliable_size", reliableSize).append('}')
        delegate?.resetStreamAt(id, code, finalSize, reliableSize)
    }

    override fun crypto(
        offset: Long,
        data: PacketBuffer,
        off: Int,
        len: Int,
    ) {
        open("crypto").num("offset", offset).num("length", len.toLong()).append('}')
        delegate?.crypto(offset, data, off, len)
    }

    override fun newToken(
        token: PacketBuffer,
        off: Int,
        len: Int,
    ) {
        // section 8.8: the token by its type and length, never its bytes
        open("new_token").append(",\"token\":{\"type\":\"resumption\",\"raw\":{\"length\":").append(len).append("}}}")
        delegate?.newToken(token, off, len)
    }

    override fun stream(
        id: Long,
        offset: Long,
        data: PacketBuffer,
        off: Int,
        len: Int,
        fin: Boolean,
    ) {
        val o = open("stream").num("stream_id", id).num("offset", offset).num("length", len.toLong())
        // section 8.11.8: fin "MUST only be set if the value is true"
        if (fin) o.append(",\"fin\":true")
        o.append('}')
        delegate?.stream(id, offset, data, off, len, fin)
    }

    override fun maxData(max: Long) {
        open("max_data").num("maximum", max).append('}')
        delegate?.maxData(max)
    }

    override fun maxStreamData(
        id: Long,
        max: Long,
    ) {
        open("max_stream_data").num("stream_id", id).num("maximum", max).append('}')
        delegate?.maxStreamData(id, max)
    }

    override fun maxStreams(
        bidi: Boolean,
        max: Long,
    ) {
        open("max_streams")
            .append(",\"stream_type\":\"")
            .append(streamType(bidi))
            .append('"')
            .num("maximum", max)
            .append('}')
        delegate?.maxStreams(bidi, max)
    }

    override fun dataBlocked(limit: Long) {
        open("data_blocked").num("limit", limit).append('}')
        delegate?.dataBlocked(limit)
    }

    override fun streamDataBlocked(
        id: Long,
        limit: Long,
    ) {
        open("stream_data_blocked").num("stream_id", id).num("limit", limit).append('}')
        delegate?.streamDataBlocked(id, limit)
    }

    override fun streamsBlocked(
        bidi: Boolean,
        limit: Long,
    ) {
        open("streams_blocked")
            .append(",\"stream_type\":\"")
            .append(streamType(bidi))
            .append('"')
            .num("limit", limit)
            .append('}')
        delegate?.streamsBlocked(bidi, limit)
    }

    override fun newConnectionId(
        seq: Long,
        retirePriorTo: Long,
        cid: PacketBuffer,
        cidOff: Int,
        cidLen: Int,
        resetTokenOff: Int,
    ) {
        val o = open("new_connection_id").num("sequence_number", seq).num("retire_prior_to", retirePriorTo)
        o.num("connection_id_length", cidLen.toLong()).append(",\"connection_id\":\"")
        hex(cid, cidOff, cidLen)
        o.append("\"}") // no stateless_reset_token: see the class comment
        delegate?.newConnectionId(seq, retirePriorTo, cid, cidOff, cidLen, resetTokenOff)
    }

    override fun retireConnectionId(seq: Long) {
        open("retire_connection_id").num("sequence_number", seq).append('}')
        delegate?.retireConnectionId(seq)
    }

    override fun pathChallenge(data: Long) {
        open("path_challenge").append(",\"data\":\"").append(hex64(data)).append("\"}")
        delegate?.pathChallenge(data)
    }

    override fun pathResponse(data: Long) {
        open("path_response").append(",\"data\":\"").append(hex64(data)).append("\"}")
        delegate?.pathResponse(data)
    }

    override fun connectionClose(
        application: Boolean,
        code: Long,
        frameType: Long,
        reason: PacketBuffer,
        off: Int,
        len: Int,
    ) {
        val o = open("connection_close").append(",\"error_space\":\"").append(if (application) "application" else "transport").append('"')
        if (application) applicationError(o, "error_code", code, optional = true) else transportError(o, code)
        o.num("error_code_value", code)
        o.append(",\"reason\":\"")
        QlogWriter.escapeInto(reason.decodeUtf8(off, len), o)
        o.append('"')
        if (!application) o.append(",\"trigger_frame_type\":").append(frameTypeName(frameType))
        o.append('}')
        delegate?.connectionClose(application, code, frameType, reason, off, len)
    }

    override fun handshakeDone() {
        open("handshake_done").append('}')
        delegate?.handshakeDone()
    }

    override fun datagram(
        data: PacketBuffer,
        off: Int,
        len: Int,
    ) {
        // RFC 9221 DATAGRAM: a frame type through the $QuicFrame extension point, by its length (as the later drafts define it)
        open("datagram").num("length", len.toLong()).append('}')
        delegate?.datagram(data, off, len)
    }

    private fun hex(
        b: PacketBuffer,
        off: Int,
        len: Int,
    ) {
        for (i in off until off + len) {
            val v = b[i].toInt() and 0xff
            out.append(HEX[v ushr 4]).append(HEX[v and 0xf])
        }
    }

    private fun hex64(v: Long): String = v.toULong().toString(16).padStart(16, '0')

    internal companion object {
        private const val HEX = "0123456789abcdef"

        /** quic-events-04 section 8.11.11 StreamType. */
        fun streamType(bidi: Boolean): String = if (bidi) "bidirectional" else "unidirectional"

        /**
         * `$ApplicationError / uint32` (sections 8.11.4, 8.11.5, 8.11.23): the number when it fits 32 bits; a larger one
         * (WebTransport's application error codes, draft-ietf-webtrans-http3 section 4.4) as the string
         * `application_error_0x<hex>`, Kuicksilver's extension of the `$ApplicationError` socket section 8.11.23 provides
         * (the way CryptoError writes its codes, section 8.11.24). [optional]: leave such a code out (a field the type marks
         * optional, with `error_code_value` next to it).
         */
        fun applicationError(
            o: StringBuilder,
            key: String,
            code: Long,
            optional: Boolean = false,
        ): StringBuilder {
            if (code in 0..0xffff_ffffL) {
                return o
                    .append(",\"")
                    .append(key)
                    .append("\":")
                    .append(code)
            }
            if (optional) return o
            return o
                .append(",\"")
                .append(key)
                .append("\":\"application_error_0x")
                .append(code.toString(16))
                .append('"')
        }

        /** TransportError (section 8.11.22), CryptoError (section 8.11.24), or nothing for a code neither names. */
        fun transportError(
            o: StringBuilder,
            code: Long,
        ): StringBuilder {
            val name = transportErrorName(code) ?: return o
            return o.append(",\"error_code\":\"").append(name).append('"')
        }

        fun transportErrorName(code: Long): String? =
            when {
                code in 0L until TRANSPORT_ERRORS.size -> TRANSPORT_ERRORS[code.toInt()]
                code in 0x100L..0x1ffL -> "crypto_error_0x" + code.toString(16)
                else -> null
            }

        // RFC 9000 section 20.1 in code order, as section 8.11.22 names them; 0x10 is RFC 9000's NO_VIABLE_PATH
        private val TRANSPORT_ERRORS =
            arrayOf(
                "no_error",
                "internal_error",
                "connection_refused",
                "flow_control_error",
                "stream_limit_error",
                "stream_state_error",
                "final_size_error",
                "frame_encoding_error",
                "transport_parameter_error",
                "connection_id_limit_error",
                "protocol_violation",
                "invalid_token",
                "application_error",
                "crypto_buffer_exceeded",
                "key_update_error",
                "aead_limit_reached",
                "no_viable_path",
            )

        /** trigger_frame_type (section 8.11.19): a known frame type by its name (a JSON string), another one in hex text. */
        fun frameTypeName(t: Long): String {
            val name =
                when (t) {
                    FrameType.PADDING -> "padding"
                    FrameType.PING -> "ping"
                    FrameType.ACK, FrameType.ACK_ECN -> "ack"
                    FrameType.RESET_STREAM -> "reset_stream"
                    FrameType.STOP_SENDING -> "stop_sending"
                    FrameType.CRYPTO -> "crypto"
                    FrameType.NEW_TOKEN -> "new_token"
                    in FrameType.STREAM..0x0fL -> "stream"
                    FrameType.MAX_DATA -> "max_data"
                    FrameType.MAX_STREAM_DATA -> "max_stream_data"
                    FrameType.MAX_STREAMS_BIDI, FrameType.MAX_STREAMS_UNI -> "max_streams"
                    FrameType.DATA_BLOCKED -> "data_blocked"
                    FrameType.STREAM_DATA_BLOCKED -> "stream_data_blocked"
                    FrameType.STREAMS_BLOCKED_BIDI, FrameType.STREAMS_BLOCKED_UNI -> "streams_blocked"
                    FrameType.NEW_CONNECTION_ID -> "new_connection_id"
                    FrameType.RETIRE_CONNECTION_ID -> "retire_connection_id"
                    FrameType.PATH_CHALLENGE -> "path_challenge"
                    FrameType.PATH_RESPONSE -> "path_response"
                    FrameType.CONNECTION_CLOSE, FrameType.CONNECTION_CLOSE_APP -> "connection_close"
                    FrameType.HANDSHAKE_DONE -> "handshake_done"
                    else -> null
                }
            return if (name != null) "\"$name\"" else "\"0x${t.toString(16)}\""
        }
    }
}

/** The bytes `[off, off + len)` as UTF-8 text (malformed sequences replaced). */
private fun PacketBuffer.decodeUtf8(
    off: Int,
    len: Int,
): String {
    val b = ByteArray(len)
    for (i in 0 until len) b[i] = this[off + i]
    return b.decodeToString()
}

/** The reader's buffer between packets (one for the process, as the packet receiver keeps). */
private val NO_BYTES = PacketBuffer.allocate(1)
