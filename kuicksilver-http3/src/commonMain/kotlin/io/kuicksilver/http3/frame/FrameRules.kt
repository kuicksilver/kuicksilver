// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.frame

import io.kuicksilver.http3.Http3ErrorCode

/** What the reader does with a frame that is allowed where it arrived. */
internal enum class FrameAction { Process, Skip }

/** Which frame may appear on which stream, with the error codes by role (RFC 9114 sections 6.2.1, 7.2, 4.6; RFC 9218 section 7.1). */
internal object FrameRules {
    /** Largest payload of a control-stream frame we read into memory; checked against the header before reading. */
    const val MAX_CONTROL_PAYLOAD: Long = 4096

    private fun unexpected(what: String): Nothing = throw H3ProtocolError(Http3ErrorCode.FRAME_UNEXPECTED, what)

    private fun wtStreamMisplaced(where: String): Nothing =
        throw H3ProtocolError(Http3ErrorCode.FRAME_ERROR, "WebTransport WT_STREAM signal inside $where")

    /**
     * A frame on the peer's control stream; [first] is its first frame; [isServer] is our role; [webTransport] says
     * whether we speak WebTransport, which makes its `WT_STREAM` signal a frame error here.
     */
    fun checkControl(
        type: Long,
        first: Boolean,
        isServer: Boolean,
        webTransport: Boolean = false,
    ): FrameAction {
        // two MUSTs meet for WT_STREAM as the first frame: RFC 9114 section 6.2.1 (any other first frame, H3_MISSING_SETTINGS)
        // and draft-ietf-webtrans-http3-16 section 4.3 (WT_STREAM "in any other circumstances", H3_FRAME_ERROR). The base
        // protocol's rule wins: it applies before the type is interpreted, with or without WebTransport, as a peer without
        // WebTransport would apply it (docs/spec/rfc-compliance.md, the SETTINGS row)
        if (first &&
            type != FrameType.SETTINGS
        ) {
            throw H3ProtocolError(Http3ErrorCode.MISSING_SETTINGS, "control stream must start with SETTINGS")
        }
        if (webTransport && type == FrameType.WT_STREAM) wtStreamMisplaced("the control stream")
        return when (type) {
            FrameType.SETTINGS -> {
                if (first) FrameAction.Process else unexpected("second SETTINGS")
            }

            FrameType.DATA, FrameType.HEADERS, FrameType.PUSH_PROMISE -> {
                unexpected("frame 0x${type.toString(16)} on the control stream")
            }

            FrameType.GOAWAY -> {
                FrameAction.Process
            }

            // no push: nothing was ever promised, so every push ID is unknown (RFC 9114 section 7.2.3)
            FrameType.CANCEL_PUSH -> {
                throw H3ProtocolError(Http3ErrorCode.ID_ERROR, "CANCEL_PUSH without server push")
            }

            // a server reads it even without push: a decreasing or malformed one is a connection error (sections 7.2.7, 7.1)
            FrameType.MAX_PUSH_ID -> {
                if (isServer) FrameAction.Process else unexpected("MAX_PUSH_ID received by a client")
            }

            FrameType.PRIORITY_UPDATE_REQUEST, FrameType.PRIORITY_UPDATE_PUSH -> {
                if (isServer) {
                    FrameAction.Process
                } else {
                    unexpected(
                        "PRIORITY_UPDATE received by a client",
                    )
                }
            }

            in FrameType.H2_ONLY -> {
                unexpected("HTTP/2 frame type 0x${type.toString(16)}")
            }

            else -> {
                FrameAction.Skip
            }
        }
    }

    /**
     * A frame on a request stream; [isServerSide] means we read a request (we are the server). With [webTransport] the
     * `WT_STREAM` signal is only valid as the first bytes of a bidirectional stream, which the caller reads before this;
     * anywhere else it is H3_FRAME_ERROR (draft-ietf-webtrans-http3-16 section 4.3).
     */
    fun checkRequest(
        type: Long,
        isServerSide: Boolean,
        webTransport: Boolean = false,
    ): FrameAction =
        when (type) {
            FrameType.WT_STREAM -> {
                if (webTransport) wtStreamMisplaced("a request stream") else FrameAction.Skip
            }

            FrameType.DATA, FrameType.HEADERS -> {
                FrameAction.Process
            }

            // a client never sent MAX_PUSH_ID, so any promised push ID exceeds it (RFC 9114 section 7.2.5); a server never gets one
            FrameType.PUSH_PROMISE -> {
                if (isServerSide) {
                    unexpected(
                        "PUSH_PROMISE from a client",
                    )
                } else {
                    throw H3ProtocolError(Http3ErrorCode.ID_ERROR, "PUSH_PROMISE without MAX_PUSH_ID")
                }
            }

            FrameType.SETTINGS,
            FrameType.GOAWAY,
            FrameType.MAX_PUSH_ID,
            FrameType.CANCEL_PUSH,
            FrameType.PRIORITY_UPDATE_REQUEST,
            FrameType.PRIORITY_UPDATE_PUSH,
            -> {
                unexpected(
                    "control frame 0x${type.toString(16)} on a request stream",
                )
            }

            in FrameType.H2_ONLY -> {
                unexpected("HTTP/2 frame type 0x${type.toString(16)}")
            }

            else -> {
                FrameAction.Skip
            }
        }

    /** Payload ceiling of the control frames we buffer (SETTINGS, GOAWAY, PRIORITY_UPDATE, ...): checked before any allocation. */
    fun checkControlLength(
        type: Long,
        length: Long,
    ) {
        if (length >
            MAX_CONTROL_PAYLOAD
        ) {
            throw H3ProtocolError(Http3ErrorCode.EXCESSIVE_LOAD, "control frame 0x${type.toString(16)} of $length bytes")
        }
    }
}

/** Payloads of the control frames we send and parse (RFC 9114 sections 7.2.6, 7.2.7; RFC 9218 section 7). */
internal object ControlFrames {
    fun goAwayPayload(id: Long): ByteArray = VarInt.encode(id)

    fun parseGoAway(payload: ByteArray): Long = single(payload, "GOAWAY")

    fun maxPushIdPayload(id: Long): ByteArray = VarInt.encode(id)

    fun parseMaxPushId(payload: ByteArray): Long = single(payload, "MAX_PUSH_ID")

    fun priorityUpdatePayload(
        elementId: Long,
        fieldValue: String,
    ): ByteArray {
        val v = fieldValue.encodeToByteArray()
        val out = ByteArray(VarInt.size(elementId) + v.size)
        val n = VarInt.write(elementId, out, 0)
        v.copyInto(out, n)
        return out
    }

    fun parsePriorityUpdate(payload: ByteArray): Pair<Long, String> {
        val id = VarInt.read(payload, 0, payload.size)
        if (id <
            0
        ) {
            throw H3ProtocolError(Http3ErrorCode.FRAME_ERROR, "truncated PRIORITY_UPDATE")
        }
        val n = VarInt.encodedLength(payload[0])
        return id to payload.decodeToString(n, payload.size)
    }

    private fun single(
        payload: ByteArray,
        what: String,
    ): Long {
        val v = VarInt.read(payload, 0, payload.size)
        if (v < 0 || VarInt.encodedLength(payload[0]) != payload.size) throw H3ProtocolError(Http3ErrorCode.FRAME_ERROR, "malformed $what")
        return v
    }
}
