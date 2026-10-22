// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

/**
 * HTTP/3, QPACK and WebTransport application error codes (RFC 9114 section 8.1, RFC 9204 section 6, RFC 9297 section 5.2,
 * draft-ietf-webtrans-http3-16 section 9.5). They travel in
 * CONNECTION_CLOSE 0x1d, RESET_STREAM and STOP_SENDING; an unknown code means [NO_ERROR] (RFC 9114 section 9).
 */
public object Http3ErrorCode {
    /** H3_NO_ERROR: no error; closes a connection or stream that is no longer needed, and stops an unread request body. */
    public const val NO_ERROR: Long = 0x100

    /** H3_GENERAL_PROTOCOL_ERROR: a protocol violation no more specific code covers. */
    public const val GENERAL_PROTOCOL_ERROR: Long = 0x101

    /** H3_INTERNAL_ERROR: a failure inside this endpoint, such as a response field the validator rejects. */
    public const val INTERNAL_ERROR: Long = 0x102

    /** H3_STREAM_CREATION_ERROR: the peer opened a stream that is not allowed (a second control stream, a server bidi stream). */
    public const val STREAM_CREATION_ERROR: Long = 0x103

    /** H3_CLOSED_CRITICAL_STREAM: the peer closed or reset its control or QPACK stream (RFC 9114 section 6.2.1). */
    public const val CLOSED_CRITICAL_STREAM: Long = 0x104

    /** H3_FRAME_UNEXPECTED: a frame not permitted in the current state or on this stream (RFC 9114 section 7.1). */
    public const val FRAME_UNEXPECTED: Long = 0x105

    /** H3_FRAME_ERROR: a frame whose layout or size is invalid, or that a FIN cut short (RFC 9114 section 7.1). */
    public const val FRAME_ERROR: Long = 0x106

    /** H3_EXCESSIVE_LOAD: the peer generates excessive load (a field section above the limit, too many 1xx, glitch flood). */
    public const val EXCESSIVE_LOAD: Long = 0x107

    /** H3_ID_ERROR: a stream or push id used incorrectly, such as a GOAWAY id that grows (RFC 9114 section 5.2). */
    public const val ID_ERROR: Long = 0x108

    /** H3_SETTINGS_ERROR: invalid SETTINGS content, such as a duplicate or an HTTP/2 setting (RFC 9114 section 7.2.4). */
    public const val SETTINGS_ERROR: Long = 0x109

    /** H3_MISSING_SETTINGS: the control stream did not start with SETTINGS (RFC 9114 section 6.2.1). */
    public const val MISSING_SETTINGS: Long = 0x10a

    /** H3_REQUEST_REJECTED: the server did not process the request; read as [Http3Exception.RequestNotProcessed], safe to retry. */
    public const val REQUEST_REJECTED: Long = 0x10b

    /** H3_REQUEST_CANCELLED: the request or its response is no longer needed; sent when a client call is cancelled. */
    public const val REQUEST_CANCELLED: Long = 0x10c

    /** H3_REQUEST_INCOMPLETE: the request stream ended (FIN) without a complete message (RFC 9114 section 4.1). */
    public const val REQUEST_INCOMPLETE: Long = 0x10d

    /** H3_MESSAGE_ERROR: a malformed message (RFC 9114 section 4.1.2); a stream error, the connection lives on. */
    public const val MESSAGE_ERROR: Long = 0x10e

    /** H3_CONNECT_ERROR: the tunnel of a CONNECT request was reset or closed abnormally (RFC 9114 section 4.4). */
    public const val CONNECT_ERROR: Long = 0x10f

    /** H3_VERSION_FALLBACK: the request should be retried over HTTP/1.1. */
    public const val VERSION_FALLBACK: Long = 0x110

    /** H3_DATAGRAM_ERROR: a malformed HTTP datagram or capsule, such as an unparsable quarter stream ID (RFC 9297 section 5.2). */
    public const val DATAGRAM_ERROR: Long = 0x33

    /**
     * WT_BUFFERED_STREAM_REJECTED: a WebTransport stream whose session is not there, over the buffering limits, or of a
     * closed session (draft-ietf-webtrans-http3-16 section 4.6). Experimental, as WebTransport is.
     */
    public const val WT_BUFFERED_STREAM_REJECTED: Long = 0x3994bd84

    /** WT_SESSION_GONE: resets and stops the streams of a WebTransport session that closed (section 6). */
    public const val WT_SESSION_GONE: Long = 0x170d7b68

    /** WT_FLOW_CONTROL_ERROR: WebTransport flow control was violated (section 5); not sent by this library, which has none. */
    public const val WT_FLOW_CONTROL_ERROR: Long = 0x045d4487

    /** WT_ALPN_ERROR: the server chose a `WT-Protocol` the client did not offer (section 3.3). */
    public const val WT_ALPN_ERROR: Long = 0x0817b3dd

    /** WT_REQUIREMENTS_NOT_MET: the peer does not meet a WebTransport requirement (section 3.1); not sent by this library. */
    public const val WT_REQUIREMENTS_NOT_MET: Long = 0x212c0d48

    /** QPACK_DECOMPRESSION_FAILED: a field section could not be decoded, or too many streams were blocked (RFC 9204 section 6). */
    public const val QPACK_DECOMPRESSION_FAILED: Long = 0x200

    /** QPACK_ENCODER_STREAM_ERROR: an invalid instruction on the peer's encoder stream (RFC 9204 section 6). */
    public const val QPACK_ENCODER_STREAM_ERROR: Long = 0x201

    /** QPACK_DECODER_STREAM_ERROR: an invalid instruction on the peer's decoder stream (RFC 9204 section 6). */
    public const val QPACK_DECODER_STREAM_ERROR: Long = 0x202

    private val names =
        mapOf(
            NO_ERROR to "H3_NO_ERROR",
            GENERAL_PROTOCOL_ERROR to "H3_GENERAL_PROTOCOL_ERROR",
            INTERNAL_ERROR to "H3_INTERNAL_ERROR",
            STREAM_CREATION_ERROR to "H3_STREAM_CREATION_ERROR",
            CLOSED_CRITICAL_STREAM to "H3_CLOSED_CRITICAL_STREAM",
            FRAME_UNEXPECTED to "H3_FRAME_UNEXPECTED",
            FRAME_ERROR to "H3_FRAME_ERROR",
            EXCESSIVE_LOAD to "H3_EXCESSIVE_LOAD",
            ID_ERROR to "H3_ID_ERROR",
            SETTINGS_ERROR to "H3_SETTINGS_ERROR",
            MISSING_SETTINGS to "H3_MISSING_SETTINGS",
            REQUEST_REJECTED to "H3_REQUEST_REJECTED",
            REQUEST_CANCELLED to "H3_REQUEST_CANCELLED",
            REQUEST_INCOMPLETE to "H3_REQUEST_INCOMPLETE",
            MESSAGE_ERROR to "H3_MESSAGE_ERROR",
            CONNECT_ERROR to "H3_CONNECT_ERROR",
            VERSION_FALLBACK to "H3_VERSION_FALLBACK",
            DATAGRAM_ERROR to "H3_DATAGRAM_ERROR",
            WT_BUFFERED_STREAM_REJECTED to "WT_BUFFERED_STREAM_REJECTED",
            WT_SESSION_GONE to "WT_SESSION_GONE",
            WT_FLOW_CONTROL_ERROR to "WT_FLOW_CONTROL_ERROR",
            WT_ALPN_ERROR to "WT_ALPN_ERROR",
            WT_REQUIREMENTS_NOT_MET to "WT_REQUIREMENTS_NOT_MET",
            QPACK_DECOMPRESSION_FAILED to "QPACK_DECOMPRESSION_FAILED",
            QPACK_ENCODER_STREAM_ERROR to "QPACK_ENCODER_STREAM_ERROR",
            QPACK_DECODER_STREAM_ERROR to "QPACK_DECODER_STREAM_ERROR",
        )

    /** True for the codes this library knows; others (including GREASE `0x1f * N + 0x21`) are treated as [NO_ERROR]. */
    public fun isKnown(code: Long): Boolean = code in names

    /** The registry name, or `"0x…"` for an unknown code. */
    public fun name(code: Long): String = names[code] ?: ("0x" + code.toString(16))

    /** [code] when known, else [NO_ERROR] (RFC 9114 section 9: unknown codes are equivalent to H3_NO_ERROR). */
    public fun normalize(code: Long): Long = if (isKnown(code)) code else NO_ERROR
}
